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
const passport = require("passport");
const { logError } = require("../util/logError");
const router = express.Router();

router.get('/login',function(req, res, next) {
    passport.authenticate("saml",{
        failureRedirect: req.app.get("SAML2_ROOT") + "/failure"
})(req, res, next)});

// Where to land once the local session is gone. WSFED_ROOT is not usable here:
// it has no wa/wtrealm and would answer 400.
function endLogout(req, res) {
    const target = req.app.get("INVALID_LOGIN_REDIRECT");
    req.session.destroy(function (err) {
        if (err) { logError('session destroy failed', err, { 'http.request.id': req.requestId }); }
        res.clearCookie("connect.sid");
        if (target !== "") { return res.redirect(303, target); }
        res.status(200).type('text/plain').send('Signed out');
    });
}

router.get('/logout', function (req, res, next) {
    const initiated = !!req.session && req.session.logout_pending === true;
    if (initiated) { delete req.session.logout_pending; }

    // Not signed in: nothing to sign out of at the IdP, and nothing a
    // cross-origin page could abuse — drop whatever session exists and finish.
    // Guarding this path would 403 ordinary repeat/refresh of the logout URL.
    if (!req.isAuthenticated()) {
        return endLogout(req, res);
    }

    // Signed in: propagating this to the IdP ends the session everywhere, so it
    // must have come from the wsignout1.0 entry point in routes/wsfed.js.
    if (!initiated) {
        return next(createError(403, 'logout must be initiated via the WS-Fed wsignout1.0 endpoint'));
    }

    // req.user must stay intact — node-saml reads NameID/SessionIndex from it
    passport._strategy('saml').logout(req, function (err, requestUrl) {
        if (err) { return next(err); }
        if (!requestUrl) { return next(createError(500, 'IdP logout URL could not be generated')); }
        // LOCAL logout
        req.logout(function (err) {
            if (err) { return next(err); }
            req.session.destroy(function (err) {
                if (err) { logError('session destroy failed', err, { 'http.request.id': req.requestId }); }
                res.clearCookie("connect.sid");
                // redirect to the IdP with the SAML logout request
                res.redirect(requestUrl);
            });
        });
    });
});

router.get('/failure',function(req, res, next) {
    res.status(401).send('Authentication failed');
});


router.post('/callback', function (req, res, next) {
    // custom callback instead of failureRedirect: it also catches the case where
    // the strategy declines without an error, which would otherwise be unlogged
    passport.authenticate("saml", { keepSessionInfo: true }, function (err, user, info) {
        if (err || !user) {
            logError('saml assertion rejected', err || new Error((info && info.message) || 'authentication declined'), {
                'http.request.id': req.requestId,
                'client.ip':       req.ip,
            });
            return res.redirect(req.app.get("SAML2_ROOT") + "/failure");
        }
        // keepSessionInfo: logIn regenerates the session; wsfed_args must survive
        req.logIn(user, { keepSessionInfo: true }, function (err) {
            if (err) {
                logError('saml session establishment failed', err, {
                    'http.request.id': req.requestId,
                    'client.ip':       req.ip,
                });
                return res.redirect(req.app.get("SAML2_ROOT") + "/failure");
            }
            res.redirect(req.app.get("WSFED_ROOT"));
        });
    })(req, res, next);
});



module.exports = router;
