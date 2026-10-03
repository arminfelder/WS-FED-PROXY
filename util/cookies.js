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

const {COOKIE_NAME: SSO_COOKIE} = require('./ssoRecord');

// A browser deletes a cookie only when Domain and Path agree with the Set-Cookie that made it.
function domainOption(app) {
    const domain = app.get("COOKIE_DOMAIN");
    return domain ? {domain} : {};
}

function clearSessionCookie(req, res) {
    res.clearCookie("connect.sid", {path: '/', ...domainOption(req.app)});
}

// Lax, not strict: OWA starts wsignout1.0 with a cross-site top-level navigation.
function ssoCookieOptions(app) {
    return {httpOnly: true, secure: true, sameSite: 'lax', path: '/', ...domainOption(app)};
}

function clearSsoCookie(req, res) {
    res.clearCookie(SSO_COOKIE, ssoCookieOptions(req.app));
}

// __Host- prefix: the browser refuses this name from a sibling subdomain (cookie tossing).
const CONFIRM_COOKIE = '__Host-wsfed_signout_confirm';

// Strict and host-only: only a navigation started on the proxy's own page carries it.
function confirmCookieOptions() {
    return {httpOnly: true, secure: true, sameSite: 'strict', path: '/'};
}

module.exports = {clearSessionCookie, ssoCookieOptions, clearSsoCookie, CONFIRM_COOKIE, confirmCookieOptions};
