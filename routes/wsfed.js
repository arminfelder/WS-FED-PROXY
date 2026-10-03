/*
Copyright (C) ws-fed proxy  Armin Felder

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

const express = require('express');
const createError = require('http-errors');
const wsfed = require("wsfed");
const fs = require("fs");
const path = require("path");
const profileMapper = require("../util/OWAProfileMapper");
const { isRealmAllowed, isWreplyAllowed } = require("../util/validateRedirect");
const { logError } = require("../util/logError");
const { metadataHandler } = require("../util/metadata");
const router = express.Router();

const certsDir = path.join(__dirname, '../certs');
let _cert, _key, _pkcs7;
function getCerts(app) {
    if (!_cert) {
        _cert  = fs.readFileSync(path.join(certsDir, app.get("WSFED_CERT")));
        _key   = fs.readFileSync(path.join(certsDir, app.get("WSFED_KEY")));
        _pkcs7 = fs.readFileSync(path.join(certsDir, app.get("WSFED_PKCS7")));
    }
    return { cert: _cert, key: _key, pkcs7: _pkcs7 };
}



const WSFED_PARAMS = ['wa', 'wtrealm', 'wreply', 'wctx', 'wfresh'];
// one year, in minutes
const MAX_WFRESH_MINUTES = 525600;

// WS-Federation 1.2 §13.2.2: wfresh is the maximum age of the authentication, in minutes.
// Returns "ok", "reauth" (ask the IdP again, one time) or "stale".
function checkFreshness(req, args) {
    if (args.wfresh === undefined) return "ok";
    const authnInstant = Date.parse(req.user && req.user.authnInstant);
    if (Number.isNaN(authnInstant)) return "stale";
    const notBefore = args.wfresh === "0"
        ? args.authRequestedAt
        : Date.now() - Number(args.wfresh) * 60000;
    if (authnInstant + req.app.get("SAML2_CLOCK_SKEW_MS") >= notBefore) return "ok";
    return args.reauthRequested ? "stale" : "reauth";
}

// Seconds. The token must not outlive wfresh (WS-Federation 1.2 §13.2.2) or the IdP session
// (SessionNotOnOrAfter, SAML 2.0 core §2.7.2). Returns null when less than one second remains:
// the wsfed library turns a lifetime of 0 into 8 hours, so 0 must never reach it.
function tokenLifetime(app, args, user) {
    const limits = [app.get("WSFED_TOKEN_LIFETIME")];
    const minutes = Number(args.wfresh);
    // wfresh=0 asks for a new login, not a 0-second token
    if (args.wfresh !== undefined && minutes > 0) limits.push(minutes * 60);
    if (user && user.sessionNotOnOrAfter !== undefined) {
        const sessionEnd = Date.parse(user.sessionNotOnOrAfter);
        if (Number.isNaN(sessionEnd)) return null;
        limits.push(Math.floor((sessionEnd - Date.now()) / 1000));
    }
    const lifetime = Math.min(...limits);
    return lifetime >= 1 ? lifetime : null;
}

// Express 5 parses a repeated key into an array. The allowlist checks need one string for each parameter.
function readWsfedParams(query) {
    const params = {};
    for (const name of WSFED_PARAMS) {
        const value = query[name];
        if (value === undefined) continue;
        if (typeof value !== 'string') return null;
        params[name] = value;
    }
    return params;
}

// same escaping as the wsfed library uses for Context (wsfed/lib/utils.js)
function escapeAttribute(value) {
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// 1x1 transparent GIF. RPs and browsers load wsignoutcleanup1.0 URLs as images.
const CLEANUP_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

function signOut(req, res) {
    // CSRF guard for /saml2/logout, which refuses to run without this flag
    req.session.logout_pending = true;
    res.redirect(req.app.get("SAML2_ROOT") + "/logout");
}

// WS-Federation 1.2 §13.2.4.2: remove local state only. Do not contact the IdP.
function signOutCleanup(req, res, next, query) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    if (query.wreply !== undefined && !isWreplyAllowed(query.wreply, undefined, allowedOrigins)) {
        return next(createError(403, `wreply origin not allowed: ${query.wreply}`));
    }
    req.session.destroy(function (err) {
        if (err) { logError('session destroy failed', err, { 'http.request.id': req.requestId }); }
        res.clearCookie("connect.sid");
        res.set('Cache-Control', 'no-store');
        if (query.wreply) { return res.redirect(query.wreply); }
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
        res.type('gif').send(CLEANUP_GIF);
    });
}

function signIn(req, res, next, query) {
    if (query.wtrealm === undefined) {
        return next(createError(400, 'wtrealm is required for wsignin1.0'));
    }
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    if (!isRealmAllowed(query.wtrealm, allowedOrigins)) {
        return next(createError(403, `wtrealm not in allowlist: ${query.wtrealm}`));
    }
    if (!isWreplyAllowed(query.wreply, query.wtrealm, allowedOrigins)) {
        return next(createError(403, `wreply origin not allowed: ${query.wreply}`));
    }
    if (query.wfresh !== undefined && (!/^\d+$/.test(query.wfresh) || Number(query.wfresh) > MAX_WFRESH_MINUTES)) {
        return next(createError(400, `wfresh must be a whole number of minutes from 0 to ${MAX_WFRESH_MINUTES}`));
    }
    req.session.wsfed_args = { ...query, authRequestedAt: Date.now() };
    req.session.save();
    res.redirect(req.app.get("SAML2_ROOT") + "/login");
}

// No wa: the return from /saml2/callback, which redirects to the bare WSFED_ROOT.
function continueSignIn(req, res, next) {
    if (req.isAuthenticated() && "wsfed_args" in req.session) {
        // re-validate: the allowlist may have changed since entry, and wreply
        // is what getPostURL() below hands the signed token to
        const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
        const args = req.session.wsfed_args;
        if (!isRealmAllowed(args.wtrealm, allowedOrigins)) {
            return next(createError(403, `wtrealm not in allowlist: ${args.wtrealm}`));
        }
        if (!isWreplyAllowed(args.wreply, args.wtrealm, allowedOrigins)) {
            return next(createError(403, `wreply origin not allowed: ${args.wreply}`));
        }
        const freshness = checkFreshness(req, args);
        if (freshness === "reauth") {
            args.reauthRequested = true;
            args.authRequestedAt = Date.now();
            req.session.save();
            return res.redirect(req.app.get("SAML2_ROOT") + "/login");
        }
        if (freshness === "stale") {
            return next(createError(403, `authentication is older than wfresh=${args.wfresh}`));
        }
        const lifetime = tokenLifetime(req.app, args, req.user);
        if (lifetime === null) {
            return next(createError(403, 'the IdP session has ended or its end time cannot be read'));
        }
        res.locals.tokenLifetime = lifetime;
        res.locals.wsfedArgs = args;
        return next();
    }
    if (req.isAuthenticated()) { // authenticated without pending WS-Fed arguments: the session is not usable
        return signOut(req, res);
    }
    if (req.app.get("INVALID_LOGIN_REDIRECT") !== "") {
        return res.redirect(303, req.app.get("INVALID_LOGIN_REDIRECT"));
    }
    next(createError(400, 'missing or invalid WS-Fed parameters (wa, wtrealm)'));
}

router.get('/',(req,res,next)=>{
    const query = readWsfedParams(req.query);
    if (query === null) {
        return next(createError(400, 'repeated or malformed WS-Fed parameter'));
    }
    switch (query.wa) {
        case "wsignin1.0":         return signIn(req, res, next, query);
        case "wsignout1.0":        return signOut(req, res);
        case "wsignoutcleanup1.0": return signOutCleanup(req, res, next, query);
        case undefined:            return continueSignIn(req, res, next);
        // WS-Federation 1.2 §17: an unsupported action gets a fault, not a sign-in
        default:                   return next(createError(400, `unsupported wa: ${query.wa}`));
    }
},(req,res,next)=>{
    const { cert, key } = getCerts(req.app);
    const args = res.locals.wsfedArgs;
    return wsfed.auth({
    issuer:     req.app.get("WSFED_ISSUER"),
    cert,
    key,
    // explicit — the library defaults to 8 hours
    lifetime:   res.locals.tokenLifetime,
    audience:   args.wtrealm,
    wctx:       args.wctx,
    profileMapper: profileMapper,
    responseHandler: function (res, postUrl, _wctx, wresult) {
        // The library takes Context from `options.wctx || req.query.wctx`, so an empty or absent
        // wctx falls through to the query of this request. Only the stored wctx is the RP value
        // (WS-Federation 1.2 §13.6.2), so Context is written again from it.
        // Context is outside the signed assertion, so the signature stays valid.
        const context = args.wctx === undefined ? '' : `Context="${escapeAttribute(args.wctx)}" `;
        wresult = wresult.replace(/^<t:RequestSecurityTokenResponse Context="[^"]*" /, `<t:RequestSecurityTokenResponse ${context}`);
        res.render('wsfed-form', { callback: postUrl, wresult, wctx: args.wctx });
    },
    getPostURL: function (_wtrealm, _wreply, req, callback) {
        // empty wreply falls back to wtrealm, already checked against the allowlist
        const redirectUrl = args.wreply || args.wtrealm;
        // callback() must fire inside destroy(): wsfed sends the response
        // synchronously from it, so clearCookie afterwards would be too late
        req.session.destroy(function (err){
            if(err){
                logError('session destroy failed', err, { 'http.request.id': req.requestId })
            }
            res.clearCookie("connect.sid")
            return callback(null, redirectUrl)
        });
    }
})(req,res,next)
});

// WS-Federation 1.2 §3.2.2. app.js also mounts this at the server root.
const federationMetadata = metadataHandler((req) => {
    const { cert, key } = getCerts(req.app);
    return {
        issuer:     req.app.get("WSFED_ISSUER"),
        endpoint:   new URL(req.app.get("WSFED_ISSUER")).origin + req.app.get("WSFED_ROOT"),
        cert,
        key,
        claimTypes: profileMapper.prototype.metadata,
    };
});
router.get('/FederationMetadata/2007-06/FederationMetadata.xml', federationMetadata);
router.federationMetadata = federationMetadata;

// The wsfed library builds URLs from the Host and X-Forwarded-* headers.
// This request copy gives it the configured host only.
function configuredHostRequest(req) {
    return {
        query:       req.query,
        originalUrl: req.baseUrl + req.path,
        protocol:    'https',
        headers:     { host: new URL(req.app.get("WSFED_ISSUER")).host },
    };
}

router.get('/adfs/fs/federationserverservice.asmx', (req, res) => {
    return wsfed.federationServerService.wsdl(configuredHostRequest(req), res);
});

router.post('/adfs/fs/federationserverservice.asmx',
    (req,res,next) => {
    const { cert, pkcs7 } = getCerts(req.app);
    return wsfed.federationServerService.thumbprint({ pkcs7, cert })(configuredHostRequest(req), res)
});



module.exports = router;
