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

/**
 * Parses a comma-separated list of allowed realm URLs into an array of origins.
 * Returns an empty array if the input is falsy or empty.
 *
 * Non-http(s) schemes are rejected: their origin serialises to the opaque
 * "null", which would match any other opaque-origin input.
 *
 * @param {string} raw - Comma-separated realm URLs from WSFED_ALLOWED_REALMS
 * @returns {string[]} Array of lowercase origin strings (e.g. ["https://exchange.corp"])
 * @throws {Error} if an entry is not a valid absolute http(s) URL
 */
function parseAllowedRealms(raw) {
    if (!raw || !raw.trim()) return [];
    return raw.split(',')
        .map(r => r.trim())
        .filter(Boolean)
        .map(r => {
            let url;
            try {
                url = new URL(r);
            } catch {
                throw new Error(`WSFED_ALLOWED_REALMS: "${r}" is not a valid absolute URL`);
            }
            if (url.protocol !== 'https:' && url.protocol !== 'http:') {
                throw new Error(`WSFED_ALLOWED_REALMS: "${r}" must use http or https`);
            }
            return url.origin.toLowerCase();
        });
}

/**
 * Checks whether wtrealm is permitted.
 *
 * Fails closed: an empty list matches nothing. The IDP cannot substitute for
 * this check — the audience of the issued token *is* wtrealm, and the IDP
 * never sees it.
 *
 * @param {string} wtrealm
 * @param {string[]} allowedOrigins - from parseAllowedRealms()
 * @returns {boolean}
 */
function isRealmAllowed(wtrealm, allowedOrigins) {
    if (!wtrealm) return false;
    if (!allowedOrigins || allowedOrigins.length === 0) return false;
    try {
        const origin = new URL(wtrealm).origin.toLowerCase();
        return allowedOrigins.includes(origin);
    } catch {
        return false;
    }
}

/**
 * Checks whether wreply is permitted.
 *
 * An absent wreply is valid — the caller falls back to wtrealm, which
 * isRealmAllowed() has already checked. Otherwise wreply's origin must appear
 * in allowedOrigins.
 *
 * No same-origin-to-wtrealm fallback: both arrive in the same request from the
 * same caller, so comparing them to each other constrains nothing.
 *
 * @param {string|undefined} wreply
 * @param {string} wtrealm
 * @param {string[]} allowedOrigins - from parseAllowedRealms()
 * @returns {boolean}
 */
function isWreplyAllowed(wreply, wtrealm, allowedOrigins) {
    if (!wreply) return true;
    if (!allowedOrigins || allowedOrigins.length === 0) return false;
    try {
        const wreplyOrigin = new URL(wreply).origin.toLowerCase();
        return allowedOrigins.includes(wreplyOrigin);
    } catch {
        return false;
    }
}

module.exports = { parseAllowedRealms, isRealmAllowed, isWreplyAllowed };
