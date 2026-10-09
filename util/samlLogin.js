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

const passport = require('passport');

/**
 * Sends the browser to the IdP with an AuthnRequest.
 *
 * Call it in the same response that stores wsfed_args. The sign-in arrives
 * through a redirect from the RP, which is often another site. Browsers then
 * treat every later hop of that navigation as cross-site and omit the
 * SameSite=Strict session cookie, so a second hop on this proxy cannot read the
 * session. The IdP's POST to /callback starts a new navigation. That POST
 * carries the cookie only if the IdP is on the same site as this proxy.
 */
function startSamlLogin(req, res, next) {
    const args = req.session.wsfed_args;
    // ForceAuthn makes the IdP prompt again (WS-Federation 1.2 §13.2.2, wfresh)
    const strategy = args && (args.wfresh === "0" || args.reauthRequested) ? "saml-force" : "saml";
    return passport.authenticate(strategy, {
        failureRedirect: req.app.get("SAML2_ROOT") + "/failure",
    })(req, res, next);
}

module.exports = { startSamlLogin };
