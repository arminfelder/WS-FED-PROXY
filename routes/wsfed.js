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
const { formatError } = require("@elastic/ecs-helpers");
const router = express.Router();

function logError(msg, err) {
    const rec = { '@timestamp': new Date().toISOString(), 'log.level': 'error', message: msg, 'ecs.version': '1.6.0' };
    formatError(rec, err);
    process.stdout.write(JSON.stringify(rec) + '\n');
}

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



router.get('/',(req,res,next)=>{
    if("wa" in req.query && req.query.wa === "wsignout1.0") { // user requests a logout
        res.redirect(req.app.get("SAML2_ROOT") + "/logout");
    }else if(req.isAuthenticated() && "wsfed_args" in req.session){ // user has been authenticated and his session contains the required arguments for WSFED to proceed
        // Re-validate wtrealm against the whitelist — guards against session tampering
        // and whitelist changes between initial request and callback.
        // wreply was already validated on entry and is not re-checked here to avoid
        // breaking same-origin fallback for deployments without WSFED_ALLOWED_REALMS.
        const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
        const args = req.session.wsfed_args;
        if (!isRealmAllowed(args.wtrealm, allowedOrigins)) {
            return next(createError(403, `wtrealm not in allowlist: ${args.wtrealm}`));
        }
        req.query = args;
        next();
    }else if ( "wa" in req.query && "wtrealm" in req.query ){   // user is not logged in and requests a login
        const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
        if (!isRealmAllowed(req.query.wtrealm, allowedOrigins)) {
            return next(createError(403, `wtrealm not in allowlist: ${req.query.wtrealm}`));
        }
        if (!isWreplyAllowed(req.query.wreply, req.query.wtrealm, allowedOrigins)) {
            return next(createError(403, `wreply origin not allowed: ${req.query.wreply}`));
        }
        const sessData = req.session;
        sessData.wsfed_args = Object.assign({},req.query);
        req.session.save();
        res.redirect(req.app.get("SAML2_ROOT") + "/login");
    }else if(req.isAuthenticated()) { // user is authenticated, but now valid session data is present, destroy the session as it is not valid
        res.redirect(req.app.get("SAML2_ROOT") + "/logout");
    }else { // user is neither authenticated nor does he present valid WSFED arguments
        if (req.app.get("INVALID_LOGIN_REDIRECT") !== ""){
            res.redirect(303, req.app.get("INVALID_LOGIN_REDIRECT"))
        }else{
            next(createError(400, 'missing or invalid WS-Fed parameters (wa, wtrealm)'))
        }
    }
},(req,res,next)=>{
    const { cert, key } = getCerts(req.app);
    return wsfed.auth({
    issuer:     req.app.get("WSFED_ISSUER"),
    cert,
    key,
    profileMapper: profileMapper,
    getPostURL: function (wtrealm, wreply, req, callback) {
        // immediately destroy the session data
        req.session.destroy(function (err){
            if(err){
                logError('session destroy failed', err)
            }
            res.clearCookie("connect.sid")
        });
        let redirectUrl = ""
        if(wreply === undefined) {
            redirectUrl = wtrealm;
        }else{
            redirectUrl = wreply;
        }
        return callback(null, redirectUrl)
    }
})(req,res,next)
});

router.get('/FederationMetadata/2007-06/FederationMetadata.xml', (req,res, next)=> {
    const { cert } = getCerts(req.app);
    return wsfed.metadata({
        issuer: req.app.get("WSFED_ISSUER"),
        cert,
    })(req, res)
});

router.get('/adfs/fs/federationserverservice.asmx',
    wsfed.federationServerService.wsdl);

router.post('/adfs/fs/federationserverservice.asmx',
    (req,res,next) => {
    const { cert, pkcs7 } = getCerts(req.app);
    return wsfed.federationServerService.thumbprint({ pkcs7, cert })(req, res)
});



module.exports = router;
