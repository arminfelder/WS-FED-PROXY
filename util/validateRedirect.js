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
 * @param {string} raw - Comma-separated realm URLs from WSFED_ALLOWED_REALMS
 * @returns {string[]} Array of lowercase origin strings (e.g. ["https://exchange.corp"])
 */
function parseAllowedRealms(raw) {
    if (!raw || !raw.trim()) return [];
    return raw.split(',')
        .map(r => r.trim())
        .filter(Boolean)
        .map(r => new URL(r).origin.toLowerCase());
}

/**
 * Checks whether wtrealm is permitted.
 *
 * If allowedOrigins is empty the check is skipped (open by default, relying on
 * the IDP to enforce audience restrictions). When allowedOrigins is configured
 * every wtrealm must appear in the list.
 *
 * @param {string} wtrealm
 * @param {string[]} allowedOrigins - from parseAllowedRealms()
 * @returns {boolean}
 */
function isRealmAllowed(wtrealm, allowedOrigins) {
    if (!wtrealm) return false;
    if (allowedOrigins.length === 0) return true;
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
 * Rules (applied in order):
 *  1. If wreply is absent it is always valid (caller will fall back to wtrealm).
 *  2. wreply must be a valid absolute URL.
 *  3. If allowedOrigins is configured, wreply's origin must be in the list.
 *  4. Otherwise wreply's origin must equal wtrealm's origin (same-origin fallback).
 *
 * @param {string|undefined} wreply
 * @param {string} wtrealm
 * @param {string[]} allowedOrigins - from parseAllowedRealms()
 * @returns {boolean}
 */
function isWreplyAllowed(wreply, wtrealm, allowedOrigins) {
    if (!wreply) return true;
    try {
        const wreplyOrigin = new URL(wreply).origin.toLowerCase();
        if (allowedOrigins.length > 0) {
            return allowedOrigins.includes(wreplyOrigin);
        }
        // Fallback: wreply must share the origin of wtrealm
        const wtrealmOrigin = new URL(wtrealm).origin.toLowerCase();
        return wreplyOrigin === wtrealmOrigin;
    } catch {
        return false;
    }
}

module.exports = { parseAllowedRealms, isRealmAllowed, isWreplyAllowed };
