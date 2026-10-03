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
 * Parses a whole-number env var and fails closed.
 *
 * A raw parseInt gives NaN or 0 for bad input. The consumers then use their own
 * defaults, which are less safe: wsfed issues 8-hour tokens, memorystore has no
 * size limit, and node-saml skips all timestamp checks.
 *
 * @param {string} name - env var name, for the error message
 * @param {string|undefined} raw - env var value
 * @param {{def: number, min: number, max: number}} bounds - default when unset, inclusive range
 * @returns {number}
 * @throws {Error} if the value is not a whole number in [min, max]
 */
function parseIntEnv(name, raw, { def, min, max }) {
    if (raw === undefined || raw === null || String(raw).trim() === "") return def;

    const value = String(raw).trim();
    if (!/^\d+$/.test(value)) {
        throw new Error(`${name} must be a whole number from ${min} to ${max}, got "${raw}"`);
    }
    const parsed = Number.parseInt(value, 10);
    if (parsed < min || parsed > max) {
        throw new Error(`${name} must be a whole number from ${min} to ${max}, got "${raw}"`);
    }
    return parsed;
}

module.exports = { parseIntEnv };
