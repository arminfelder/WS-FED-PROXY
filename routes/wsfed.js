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
const {isRealmAllowed, isWreplyAllowed, allowedWreplyUrl} = require("../util/validateRedirect");
const {logError} = require("../util/logError");
const {metadataHandler} = require("../util/metadata");
const {startSamlLogin} = require("../util/samlLogin");
const ssoRecord = require("../util/ssoRecord");
const {pendingLogout} = require("../util/pendingLogout");
const {clearSessionCookie, clearSsoCookie, SSO_COOKIE_OPTIONS} = require("../util/cookies");
const {sendCleanupThenContinue, continueCleanup} = require("../util/signoutPage");
const router = express.Router();

const certsDir = path.join(__dirname, '../certs');
let _cert, _key, _pkcs7;

function getCerts(app) {
    if (!_cert) {
        _cert = fs.readFileSync(path.join(certsDir, app.get("WSFED_CERT")));
        _key = fs.readFileSync(path.join(certsDir, app.get("WSFED_KEY")));
        _pkcs7 = fs.readFileSync(path.join(certsDir, app.get("WSFED_PKCS7")));
    }
    return {cert: _cert, key: _key, pkcs7: _pkcs7};
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

// WS-Federation 1.2 §13.1.2: send wsignoutcleanup1.0 to every realm that got a token, then end the IdP session.
// Like AD FS, wsignout1.0 has no confirmation step. Thus any site can end the session of a user with a link (logout CSRF).
// A check of the request origin is not possible: OWA sends no Referer (<meta name="referrer"> in owa/default.aspx).
async function signOut(req, res, next, query) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    let wreply = null;
    if (query.wreply) {
        wreply = allowedWreplyUrl(query.wreply, allowedOrigins);
        if (!wreply) {
            return next(createError(403, `wreply origin not allowed: ${query.wreply}`));
        }
    }
    const record = ssoRecord.open(ssoRecord.readCookie(req, ssoRecord.COOKIE_NAME), req.app.get("SESSION_SECRET"));
    const user = ssoRecord.identity(req.isAuthenticated() ? req.user : null) || ssoRecord.identity(record);
    const toIdp = req.app.get("SAML2_SLO") && user !== null;
    let continueUrl;
    if (toIdp) {
        // The state ID is the CSRF guard: /saml2/logout does not contact the IdP without it.
        continueUrl = req.app.get("SAML2_ROOT") + "/logout?state=" + await pendingLogout.put({
            kind: 'signout',
            user,
            wreply: wreply ? wreply.href : undefined,
        });
    } else {
        // No IdP step, thus no state. A request without a session adds nothing to the store.
        // Without a state, /saml2/logout shows the "signed out" page.
        continueUrl = wreply ? wreply.href : req.app.get("SAML2_ROOT") + "/logout";
    }

    req.session.destroy(function (err) {
        if (err) {
            logError('session destroy failed', err, {'http.request.id': req.requestId});
        }
        clearSessionCookie(res);
        // With an IdP step, the record stays until /saml2/logout uses the state.
        // Then the user can try again after a failed sign-out.
        if (!toIdp) {
            clearSsoCookie(res);
        }
        sendCleanupThenContinue(req, res, record, continueUrl).catch(next);
    });
}

// WS-Federation 1.2 §13.2.4.2: remove local state only. Do not contact the IdP.
function signOutCleanup(req, res, next, query) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    // Check before any side effect, and redirect only to the parsed URL that was checked.
    let target = null;
    if (query.wreply) {
        target = allowedWreplyUrl(query.wreply, allowedOrigins);
        if (!target) {
            return next(createError(403, `wreply origin not allowed: ${query.wreply}`));
        }
    }
    req.session.destroy(function (err) {
        if (err) {
            logError('session destroy failed', err, {'http.request.id': req.requestId});
        }
        clearSessionCookie(res);
        // The sign-out record stays. Any site can request this URL, and without the record
        // a later wsignout1.0 cannot reach the IdP session.
        res.set('Cache-Control', 'no-store');
        if (target) {
            return res.redirect(target.href);
        }
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
    // express-session stores the session before the redirect is sent
    return startSamlLogin(req, res, next);
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
            return startSamlLogin(req, res, next);
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
        return signOut(req, res, next, {});
    }
    if (req.app.get("INVALID_LOGIN_REDIRECT") !== "") {
        return res.redirect(303, req.app.get("INVALID_LOGIN_REDIRECT"));
    }
    next(createError(400, 'missing or invalid WS-Fed parameters (wa, wtrealm)'));
}

router.get('/', (req, res, next) => {
    const query = readWsfedParams(req.query);
    if (query === null) {
        return next(createError(400, 'repeated or malformed WS-Fed parameter'));
    }
    switch (query.wa) {
        case "wsignin1.0":
            return signIn(req, res, next, query);
        case "wsignout1.0":
            return signOut(req, res, next, query);
        case "wsignoutcleanup1.0":
            return signOutCleanup(req, res, next, query);
        case undefined:
            return continueSignIn(req, res, next);
        // WS-Federation 1.2 §17: an unsupported action gets a fault, not a sign-in
        default:
            return next(createError(400, `unsupported wa: ${query.wa}`));
    }
}, (req, res, next) => {
    const {cert, key} = getCerts(req.app);
    const args = res.locals.wsfedArgs;
    return wsfed.auth({
        issuer: req.app.get("WSFED_ISSUER"),
        cert,
        key,
        // explicit — the library defaults to 8 hours
        lifetime: res.locals.tokenLifetime,
        audience: args.wtrealm,
        wctx: args.wctx,
        profileMapper: profileMapper,
        responseHandler: function (res, postUrl, _wctx, wresult) {
            // The library takes Context from `options.wctx || req.query.wctx`, so an empty or absent
            // wctx falls through to the query of this request. Only the stored wctx is the RP value
            // (WS-Federation 1.2 §13.6.2), so Context is written again from it.
            // Context is outside the signed assertion, so the signature stays valid.
            const context = args.wctx === undefined ? '' : `Context="${escapeAttribute(args.wctx)}" `;
            // A function, not a string: a string replacement expands $&, $` and $' in wctx.
            wresult = wresult.replace(/^<t:RequestSecurityTokenResponse Context="[^"]*" /, () => `<t:RequestSecurityTokenResponse ${context}`);
            // The page holds a bearer token. A cached or bfcache copy would re-post it.
            res.set('Cache-Control', 'no-store');
            res.render('wsfed-form', {callback: postUrl, wresult, wctx: args.wctx});
        },
        getPostURL: function (_wtrealm, _wreply, req, callback) {
            // empty wreply falls back to wtrealm, already checked against the allowlist
            const redirectUrl = args.wreply || args.wtrealm;
            const secret = req.app.get("SESSION_SECRET");
            const maxAge = req.app.get("WSFED_SSO_RECORD_MAX_AGE");
            const record = ssoRecord.addRealm(
                ssoRecord.open(ssoRecord.readCookie(req, ssoRecord.COOKIE_NAME), secret), req.user, args.wtrealm, maxAge);
            // callback() must fire inside destroy(): wsfed sends the response
            // synchronously from it, so cookies set afterwards would be too late
            req.session.destroy(function (err) {
                if (err) {
                    logError('session destroy failed', err, {'http.request.id': req.requestId})
                }
                clearSessionCookie(res);
                res.cookie(ssoRecord.COOKIE_NAME, ssoRecord.seal(record, secret), {
                    ...SSO_COOKIE_OPTIONS,
                    maxAge: maxAge * 1000
                });
                return callback(null, redirectUrl)
            });
        }
    })(req, res, next)
});

// WS-Federation 1.2 §3.2.2. app.js also mounts this at the server root.
const federationMetadata = metadataHandler((req) => {
    const {cert, key} = getCerts(req.app);
    return {
        issuer: req.app.get("WSFED_ISSUER"),
        endpoint: new URL(req.app.get("WSFED_ISSUER")).origin + req.app.get("WSFED_ROOT"),
        cert,
        key,
        claimTypes: profileMapper.prototype.metadata,
    };
});
router.get('/FederationMetadata/2007-06/FederationMetadata.xml', federationMetadata);

// The RPs send the browser back here after wsignoutcleanup1.0 (util/signoutPage.js).
router.get('/signout/continue', (req, res, next) => {
    continueCleanup(req, res).catch(next);
});
router.federationMetadata = federationMetadata;

// The wsfed library builds URLs from the Host and X-Forwarded-* headers.
// This request copy gives it the configured host only.
function configuredHostRequest(req) {
    return {
        query: req.query,
        originalUrl: req.baseUrl + req.path,
        protocol: 'https',
        headers: {host: new URL(req.app.get("WSFED_ISSUER")).host},
    };
}

router.get('/adfs/fs/federationserverservice.asmx', (req, res) => {
    return wsfed.federationServerService.wsdl(configuredHostRequest(req), res);
});

router.post('/adfs/fs/federationserverservice.asmx',
    (req, res, next) => {
        const {cert, pkcs7} = getCerts(req.app);
        return wsfed.federationServerService.thumbprint({pkcs7, cert})(configuredHostRequest(req), res)
    });


module.exports = router;
