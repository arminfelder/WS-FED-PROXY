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

const crypto = require('crypto');
const passport = require('passport');

// node-saml's InResponseTo cache is shared by all sessions, so it cannot tell
// whose sign-in a response answers. RelayState is echoed by the IdP and is
// compared with the value this session sent (SAML 2.0 bindings §3.5.3, max 80 bytes).
function newRelayState() {
    return crypto.randomBytes(32).toString('base64url');
}

function relayStateMatches(received, expected) {
    if (typeof received !== 'string' || typeof expected !== 'string') return false;
    const a = Buffer.from(received);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// One entry for each sign-in that waits for the IdP, for example one for each browser tab.
// Each entry keeps its own wsfed_args, so that each tab gets the token for its own realm.
const MAX_PENDING_SIGNINS = 5;

function rememberSignIn(session, relayState) {
    const pending = session.saml_pending && typeof session.saml_pending === 'object' ? session.saml_pending : {};
    // null, not undefined: the session store does not keep undefined values
    pending[relayState] = session.wsfed_args === undefined ? null : session.wsfed_args;
    const keys = Object.keys(pending);
    for (let i = 0; i < keys.length - MAX_PENDING_SIGNINS; i++) {
        delete pending[keys[i]];
    }
    session.saml_pending = pending;
}

/**
 * Removes and returns the pending sign-in that sent this RelayState.
 * @returns {{found: boolean, args?: object|null}}
 */
function takeSignIn(session, relayState) {
    const pending = session && session.saml_pending;
    if (!pending || typeof pending !== 'object') return {found: false};
    const key = Object.keys(pending).find((k) => relayStateMatches(relayState, k));
    if (key === undefined) return {found: false};
    const args = pending[key];
    delete pending[key];
    return {found: true, args};
}

/**
 * Sends the browser to the IdP with an AuthnRequest.
 *
 * Call it in the same response that stores wsfed_args. The sign-in arrives
 * through a redirect from the RP, which is often another site. With
 * SESSION_SAMESITE=strict, browsers then omit the session cookie on every later
 * hop of that navigation, so a second hop on this proxy cannot read the session.
 *
 * The RelayState goes only in the redirect binding: passport-saml does not give
 * options.additionalParams to the HTTP-POST binding (strategy.js getAuthorizeFormAsync).
 */
function startSamlLogin(req, res, next) {
    const args = req.session.wsfed_args;
    // ForceAuthn makes the IdP prompt again (WS-Federation 1.2 §13.2.2, wfresh)
    const strategy = args && (args.wfresh === "0" || args.reauthRequested) ? "saml-force" : "saml";
    const relayState = newRelayState();
    rememberSignIn(req.session, relayState);
    return passport.authenticate(strategy, {
        failureRedirect: req.app.get("SAML2_ROOT") + "/failure",
        additionalParams: { RelayState: relayState },
    })(req, res, next);
}

module.exports = { startSamlLogin, takeSignIn, MAX_PENDING_SIGNINS };
