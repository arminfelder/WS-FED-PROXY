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

// Exact match on the host: "localhost.corp.example" is a normal hostname.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0', '[::]']);

/**
 * Parses a required absolute https URL from an environment variable.
 *
 * @param {string} name - env var name, quoted in the error message
 * @param {string} raw - its value
 * @param {{allowHttp?: boolean}} [options] - allowHttp: accept http as well, for local stacks
 * @returns {URL}
 * @throws {Error} if the value is not an absolute URL with an accepted scheme
 */
function parseHttpsUrl(name, raw, { allowHttp = false } = {}) {
    let url;
    try {
        url = new URL(raw);
    } catch {
        throw new Error(`${name} must be an absolute URL, got "${raw}"`);
    }
    if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
        throw new Error(`${name} must use https, got "${raw}"`);
    }
    return url;
}

/** @param {URL} url */
function isLoopbackHost(url) {
    return LOOPBACK_HOSTS.has(url.hostname);
}

module.exports = { parseHttpsUrl, isLoopbackHost };
