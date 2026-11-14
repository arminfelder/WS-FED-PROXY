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

const fs = require('fs');
const path = require('path');

/**
 * Reads the WS-Fed signing certificate, private key and PKCS#7 bundle.
 *
 * All three are read before anything is returned, so a failure leaves no
 * partial result. Call it at startup: a missing or unreadable key then stops
 * the process instead of failing the first sign-in.
 *
 * @param {string} certsDir - directory that holds the files
 * @param {{cert: string, key: string, pkcs7: string}} names - file names inside certsDir
 * @returns {{cert: Buffer, key: Buffer, pkcs7: Buffer}}
 * @throws {Error} the fs error, with the file name in the message
 */
function readSigningFiles(certsDir, names) {
    const cert = fs.readFileSync(path.join(certsDir, names.cert));
    const key = fs.readFileSync(path.join(certsDir, names.key));
    const pkcs7 = fs.readFileSync(path.join(certsDir, names.pkcs7));
    return { cert, key, pkcs7 };
}

module.exports = { readSigningFiles };
