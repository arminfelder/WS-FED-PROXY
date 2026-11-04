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

// The __Host- prefix makes the browser refuse the cookie unless it is Secure,
// has Path=/ and no Domain. A sibling subdomain can then not plant a session.
const SESSION_COOKIE_NAME = '__Host-sid';
// Use on every Set-Cookie, the expiry from clearCookie() included.
// Express clearCookie() adds only Path and Expires. Without Secure, the browser
// ignores that expiry cookie and keeps the session cookie.
let sameSite;
try {
    sameSite = parseSameSite(process.env.SESSION_SAMESITE);
} catch (err) {
    // same fail-closed startup as the other settings in app.js
    console.error(`FATAL: ${err.message}`);
    process.exit(1);
}
const SESSION_COOKIE_OPTIONS = Object.freeze({ httpOnly: true, secure: true, sameSite });

/**
 * none: an IdP on another site can POST its response to /saml2/callback with the session cookie.
 * strict and lax: the IdP must be on the same site as this proxy. Lax also blocks a cross-site POST.
 * The RelayState check in routes/saml2.js binds each response to its session, for all three values.
 *
 * @throws {Error} if the value is not "strict", "lax" or "none"
 */
function parseSameSite(raw) {
    const value = (raw === undefined || raw.trim() === '' ? 'none' : raw).trim().toLowerCase();
    if (!['strict', 'lax', 'none'].includes(value)) {
        throw new Error(`SESSION_SAMESITE must be "strict", "lax" or "none", not "${raw}"`);
    }
    return value;
}

module.exports = { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS, parseSameSite };
