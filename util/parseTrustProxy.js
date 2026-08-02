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
 * Parses TRUST_PROXY into an Express `trust proxy` hop count.
 *
 * Legacy `true`/`false` are accepted and map to 1/0. `true` deliberately does
 * NOT become Express' boolean `true`: that trusts the left-most, client-written
 * end of X-Forwarded-For and lets anyone forge their address.
 *
 * @param {string|undefined} raw - value of the TRUST_PROXY env var
 * @returns {number} non-negative hop count
 * @throws {Error} if the value is neither a legacy boolean nor a whole number
 */
function parseTrustProxy(raw) {
    if (raw === undefined || raw === null || String(raw).trim() === "") return 0;

    const value = String(raw).trim().toLowerCase();
    if (value === "true") return 1;
    if (value === "false") return 0;

    if (!/^\d+$/.test(value)) {
        throw new Error(`TRUST_PROXY must be a non-negative whole number of proxy hops (or the legacy true/false), got "${raw}"`);
    }
    return Number.parseInt(value, 10);
}

module.exports = { parseTrustProxy };
