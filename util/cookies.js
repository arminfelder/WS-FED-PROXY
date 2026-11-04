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
const {SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS} = require('./sessionCookie');

function clearSessionCookie(res) {
    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);
}

// Not strict: OWA starts wsignout1.0 with a cross-site top-level navigation, and Lax is sufficient for that.
// SESSION_SAMESITE=none means that the IdP is on another site. Its LogoutRequest is a cross-site POST,
// and only None sends the record with it.
// Secure, Path=/ and no Domain: the __Host- prefix of the name requires all three.
const SSO_COOKIE_OPTIONS = Object.freeze({
    httpOnly: true, secure: true, path: '/',
    sameSite: SESSION_COOKIE_OPTIONS.sameSite === 'none' ? 'none' : 'lax',
});

function clearSsoCookie(res) {
    res.clearCookie(SSO_COOKIE, SSO_COOKIE_OPTIONS);
}

module.exports = {clearSessionCookie, SSO_COOKIE_OPTIONS, clearSsoCookie};
