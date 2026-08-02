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

const { formatError } = require("@elastic/ecs-helpers");

/**
 * Writes an ECS-formatted error record to stdout. Server-side only — `err`
 * must never be surfaced to the client.
 *
 * @param {string} msg - short, stable event description
 * @param {Error} err - the error to format (stack included)
 * @param {object} [fields] - extra ECS fields, e.g. { 'http.request.id': req.requestId }
 */
function logError(msg, err, fields = {}) {
    const rec = {
        '@timestamp': new Date().toISOString(),
        'log.level': 'error',
        message: msg,
        'ecs.version': '1.6.0',
        ...fields,
    };
    formatError(rec, err);
    process.stdout.write(JSON.stringify(rec) + '\n');
}

module.exports = { logError };
