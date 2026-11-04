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
const SESSION_COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: 'strict' };

module.exports = { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS };
