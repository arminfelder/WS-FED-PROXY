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
const {startSamlLogin, takeSignIn} = require("../util/samlLogin");
const {allowedWreplyUrl} = require("../util/validateRedirect");
const {pendingLogout} = require("../util/pendingLogout");
const {clearSessionCookie, clearSsoCookie} = require("../util/cookies");
const ssoRecord = require("../util/ssoRecord");
const {sendCleanupThenContinue} = require("../util/signoutPage");

async function takeRelay(relayState) {
    const entry = await pendingLogout.take(relayState);
    return entry && entry.kind === 'relay' ? entry : undefined;
}

const router = express.Router();

// wsignin1.0 no longer redirects here. Kept for links and bookmarks.
router.get('/login', startSamlLogin);

// Where to land once the local session is gone: the sign-out wreply (WS-Federation 1.2 §13.2.4.1)
// if it is still allowlisted, otherwise a "signed out" page, as AD FS does.
function endLogout(req, res, wreply) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    const target = allowedWreplyUrl(wreply, allowedOrigins);
    req.session.destroy(function (err) {
        if (err) {
            logError('session destroy failed', err, {'http.request.id': req.requestId});
        }
        clearSessionCookie(res);
        res.set('Cache-Control', 'no-store');
        if (target) {
            return res.redirect(target.href);
        }
        res.status(200).render('signed-out', {pageTitle: 'Sign out'});
    });
}

router.get('/logout', async function (req, res, next) {
    const taken = await pendingLogout.take(req.query.state);
    const entry = taken && taken.kind === 'signout' ? taken : undefined;

    if (!entry && req.query.state !== undefined) {
        // The state is expired or used, thus the IdP did not get the sign-out. Do not report a sign-out.
        res.set('Cache-Control', 'no-store');
        return res.status(400).render('signout-failed', {pageTitle: 'Sign out'});
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
    clearSsoCookie(res);
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
            clearSessionCookie(res);
            res.redirect(requestUrl);
        });
    });
});

// A valid LogoutResponse makes the strategy call pass(), which is the third argument here.
// Any other result reaches the callback and is refused.
function handleLogoutResponse(req, res, next) {
    passport.authenticate("saml-logout", {session: false}, function (err, _user, info) {
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

// Act only on the sign-out of the user this browser holds, as in wsignout1.0: the session first, then the record.
// Without SessionIndex, the LogoutRequest is for all sessions of the user (SAML 2.0 core §3.7.1).
// With SessionIndex, it must agree. Then an old or replayed request does not end a newer session.
function isSameIdpSession(req, record, profile) {
    const local = ssoRecord.identity(req.isAuthenticated() ? req.user : null) || ssoRecord.identity(record);
    if (!local || local.nameID !== profile.nameID) return false;
    if (!profile.sessionIndex || !local.sessionIndex) return true;
    return [].concat(profile.sessionIndex).includes(local.sessionIndex);
}

// Single logout started at the IdP (for example the Keycloak account console). The IdP session has
// already ended. Send wsignoutcleanup1.0 to the RPs in the sign-out record and remove the local state.
// Then send the LogoutResponse to the IdP.
async function handleIdpLogoutRequest(req, res, next) {
    const saml = passport._strategy('saml-logout')._saml;
    let result;
    try {
        result = req.method === 'GET'
            // the redirect binding signs the raw query string, so pass it unparsed
            ? await saml.validateRedirectAsync(req.query, req.originalUrl.split('?')[1] || '')
            : await saml.validatePostRequestAsync(req.body);
    } catch (err) {
        logError('saml logout request rejected', err, {'http.request.id': req.requestId, 'client.ip': req.ip});
        return next(createError(400, 'invalid SAML logout request'));
    }
    if (!result || !result.loggedOut || !result.profile) {
        return next(createError(400, 'invalid SAML logout request'));
    }
    const relayState = (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
    const responseUrl = await saml.getLogoutResponseUrlAsync(result.profile,
        typeof relayState === 'string' ? relayState : undefined, {}, true);
    const record = ssoRecord.open(ssoRecord.readCookie(req, ssoRecord.COOKIE_NAME), req.app.get("SESSION_SECRET"));
    if (!isSameIdpSession(req, record, result.profile)) {
        res.set('Cache-Control', 'no-store');
        return res.redirect(responseUrl);
    }
    req.session.destroy(function (err) {
        if (err) {
            logError('session destroy failed', err, {'http.request.id': req.requestId});
        }
        clearSessionCookie(res);
        clearSsoCookie(res);
        sendCleanupThenContinue(req, res, record, responseUrl);
    });
}

// SAML2_SLO=false: the proxy sends no LogoutRequest, and it does not act on one from the IdP.
router.use('/logout/callback', function (req, res, next) {
    next(req.app.get("SAML2_SLO") ? undefined : createError(404));
});

router.get('/logout/callback', function (req, res, next) {
    // node-saml accepts an unsigned redirect-binding message, so require the signature here
    if (typeof req.query.Signature !== 'string') {
        return next(createError(400, 'signed SAML logout message required'));
    }
    if (typeof req.query.SAMLRequest === 'string') {
        return handleIdpLogoutRequest(req, res, next).catch(next);
    }
    if (typeof req.query.SAMLResponse === 'string') {
        return handleLogoutResponse(req, res, next);
    }
    next(createError(400, 'signed SAML logout message required'));
});

// node-saml refuses an unsigned POST LogoutRequest or LogoutResponse
router.post('/logout/callback', function (req, res, next) {
    if (req.body && typeof req.body.SAMLRequest === 'string') {
        return handleIdpLogoutRequest(req, res, next).catch(next);
    }
    if (req.body && typeof req.body.SAMLResponse === 'string') {
        return handleLogoutResponse(req, res, next);
    }
    next(createError(400, 'SAML logout message required'));
});

router.get('/failure', function (req, res, next) {
    res.status(401).send('Authentication failed');
});


router.post('/callback', function (req, res, next) {
    // Every response must carry the RelayState of a sign-in that this session started.
    // With SESSION_SAMESITE=none, any site can POST to this URL with the session cookie.
    // Without the check, a response for another user could go into this session (login CSRF).
    // An IdP LogoutRequest is a SAMLRequest, so this check does not apply to it.
    if (req.body && req.body.SAMLResponse !== undefined) {
        const taken = takeSignIn(req.session, req.body.RelayState);
        if (!taken.found) {
            return next(createError(403, 'SAML response does not belong to a sign-in of this session'));
        }
        if (taken.args) {
            req.session.wsfed_args = taken.args;
        } else {
            delete req.session.wsfed_args;
        }
    }
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
    })(req, res, next);
});


module.exports = router;
