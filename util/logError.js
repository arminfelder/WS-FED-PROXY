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

const { formatError } = require('@elastic/ecs-helpers');

function record(level, msg, fields) {
    return {
        '@timestamp': new Date().toISOString(),
        'log.level': level,
        message: msg,
        'ecs.version': '1.6.0',
        ...fields,
    };
}

/**
 * Writes an ECS-formatted error record to stdout. Server-side only — `err`
 * must never be surfaced to the client.
 *
 * @param {string} msg - short, stable event description
 * @param {Error} err - the error to format (stack included)
 * @param {object} [fields] - extra ECS fields, e.g. { 'http.request.id': req.requestId }
 */
function logError(msg, err, fields = {}) {
    const rec = record('error', msg, fields);
    formatError(rec, err);
    process.stdout.write(JSON.stringify(rec) + '\n');
}

/**
 * Writes an ECS-formatted warn record to stdout, for a condition that does not stop the proxy.
 *
 * @param {string} msg - short, stable event description
 * @param {object} [fields] - extra ECS fields
 */
function logWarn(msg, fields = {}) {
    process.stdout.write(JSON.stringify(record('warn', msg, fields)) + '\n');
}

module.exports = { logError, logWarn };
