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
const {logError} = require("../util/logError");
const {isWreplyAllowed} = require("../util/validateRedirect");
const {pendingLogout} = require("../util/pendingLogout");
const {clearSessionCookie, clearSsoCookie} = require("../util/cookies");

async function takeRelay(relayState) {
    const entry = await pendingLogout.take(relayState);
    return entry && entry.kind === 'relay' ? entry : undefined;
}

const router = express.Router();

router.get('/login', function (req, res, next) {
    const args = req.session.wsfed_args;
    // ForceAuthn makes the IdP prompt again (WS-Federation 1.2 §13.2.2, wfresh)
    const strategy = args && (args.wfresh === "0" || args.reauthRequested) ? "saml-force" : "saml";
    passport.authenticate(strategy, {
        failureRedirect: req.app.get("SAML2_ROOT") + "/failure"
    })(req, res, next)
});

// Where to land once the local session is gone: the sign-out wreply (WS-Federation 1.2 §13.2.4.1)
// if it is still allowlisted. WSFED_ROOT is not usable here: it has no wa/wtrealm and would answer 400.
function endLogout(req, res, wreply) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    const target = wreply && isWreplyAllowed(wreply, undefined, allowedOrigins) ? wreply : null;
    const fallback = req.app.get("INVALID_LOGIN_REDIRECT");
    req.session.destroy(function (err) {
        if (err) {
            logError('session destroy failed', err, {'http.request.id': req.requestId});
        }
        clearSessionCookie(req, res);
        res.set('Cache-Control', 'no-store');
        if (target) {
            return res.redirect(target);
        }
        if (fallback !== "") {
            return res.redirect(303, fallback);
        }
        res.status(200).type('text/plain').send('Signed out');
    });
}

router.get('/logout', async function (req, res, next) {
    const taken = await pendingLogout.take(req.query.state);
    const entry = taken && taken.kind === 'signout' ? taken : undefined;

    if (!entry && req.query.state !== undefined) {
        // Expired, used, or pushed out of the store: the IdP was not told. Do not report a sign-out.
        res.set('Cache-Control', 'no-store');
        return res.status(400).render('signout-failed');
    }
    if (!entry) {
        // Signed in: propagating this to the IdP ends the session everywhere, so it
        // must have come from the wsignout1.0 entry point in routes/wsfed.js.
        if (req.isAuthenticated()) {
            return next(createError(403, 'logout must be initiated via the WS-Fed wsignout1.0 endpoint'));
        }
        // Not signed in: nothing a cross-origin page could abuse. A repeat or refresh must not fail.
        return endLogout(req, res);
    }
    // the state is used: the sign-out record is no longer needed
    clearSsoCookie(req, res);
    if (!entry.user) {
        return endLogout(req, res, entry.wreply);
    }

    const relayState = await pendingLogout.put({kind: 'relay', wreply: entry.wreply});
    // node-saml reads NameID and SessionIndex from user, and RelayState from query
    passport._strategy('saml').logout({user: entry.user, query: {RelayState: relayState}}, function (err, requestUrl) {
        if (err) {
            return next(err);
        }
        if (!requestUrl) {
            return next(createError(500, 'IdP logout URL could not be generated'));
        }
        req.session.destroy(function (err) {
            if (err) {
                logError('session destroy failed', err, {'http.request.id': req.requestId});
            }
            clearSessionCookie(req, res);
            res.redirect(requestUrl);
        });
    });
});

// A valid LogoutResponse makes the strategy call pass(), which is the third argument here.
// Any other result reaches the callback and is refused.
function handleLogoutResponse(req, res, next) {
    passport.authenticate("saml", {session: false}, function (err, _user, info) {
        logError('saml logout response rejected', err || new Error((info && info.message) || 'not a LogoutResponse'), {
            'http.request.id': req.requestId,
            'client.ip': req.ip,
        });
        next(createError(400, 'invalid SAML logout response'));
    })(req, res, function () {
        const relayState = (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
        takeRelay(relayState)
            .then((entry) => endLogout(req, res, entry && entry.wreply))
            .catch(next);
    });
}

router.get('/logout/callback', function (req, res, next) {
    // node-saml accepts an unsigned redirect-binding message, so require the signature here
    if (typeof req.query.SAMLResponse !== 'string' || typeof req.query.Signature !== 'string') {
        return next(createError(400, 'signed SAML LogoutResponse required'));
    }
    handleLogoutResponse(req, res, next);
});

// node-saml refuses an unsigned POST LogoutResponse
router.post('/logout/callback', function (req, res, next) {
    if (!req.body || typeof req.body.SAMLResponse !== 'string') {
        return next(createError(400, 'SAML LogoutResponse required'));
    }
    handleLogoutResponse(req, res, next);
});

router.get('/failure', function (req, res, next) {
    res.status(401).send('Authentication failed');
});


router.post('/callback', function (req, res, next) {
    // custom callback instead of failureRedirect: it also catches the case where
    // the strategy declines without an error, which would otherwise be unlogged
    passport.authenticate("saml", {keepSessionInfo: true}, function (err, user, info) {
        if (err || !user) {
            logError('saml assertion rejected', err || new Error((info && info.message) || 'authentication declined'), {
                'http.request.id': req.requestId,
                'client.ip': req.ip,
            });
            return res.redirect(req.app.get("SAML2_ROOT") + "/failure");
        }
        // keepSessionInfo: logIn regenerates the session; wsfed_args must survive
        req.logIn(user, {keepSessionInfo: true}, function (err) {
            if (err) {
                logError('saml session establishment failed', err, {
                    'http.request.id': req.requestId,
                    'client.ip': req.ip,
                });
                return res.redirect(req.app.get("SAML2_ROOT") + "/failure");
            }
            res.redirect(req.app.get("WSFED_ROOT"));
        });
    })(req, res, function () {
        // a LogoutResponse posted to the ACS URL, which is the IdP single-logout URL in some setups
        takeRelay(req.body && req.body.RelayState)
            .then((entry) => endLogout(req, res, entry && entry.wreply))
            .catch(next);
    });
});


module.exports = router;
