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

// MS-DTYP 2.4.2: the only SID revision defined
const SID_REVISION = 1;
// MS-DTYP 2.4.2: SubAuthorityCount is at most 15
const MAX_SUB_AUTHORITIES = 15;
// revision (1) + sub-authority count (1) + identifier authority (6)
const SID_HEADER_BYTES = 8;

/**
 * Converts a binary Windows SID to its S-R-IA-SA-... text form.
 *
 * Layout (MS-DTYP 2.4.2.2): 1 byte revision, 1 byte sub-authority count,
 * 6 bytes big-endian identifier authority, then `count` little-endian uint32.
 * The input is a SAML attribute, so each field is checked before it is read.
 *
 * @param {Buffer} buf
 * @returns {string}
 * @throws {Error} if the buffer is not a well-formed SID
 */
function sidBufferToString(buf) {
    if (buf.length < SID_HEADER_BYTES) {
        throw new Error(`SID is too short: ${buf.length} bytes`);
    }
    const revision = buf.readUInt8(0);
    if (revision !== SID_REVISION) {
        throw new Error(`SID revision must be ${SID_REVISION}, got ${revision}`);
    }
    const subAuthCount = buf.readUInt8(1);
    if (subAuthCount < 1 || subAuthCount > MAX_SUB_AUTHORITIES) {
        throw new Error(`SID must have 1 to ${MAX_SUB_AUTHORITIES} sub-authorities, got ${subAuthCount}`);
    }
    // Exact, not minimum: trailing bytes do not come from a SID encoder.
    const expected = SID_HEADER_BYTES + 4 * subAuthCount;
    if (buf.length !== expected) {
        throw new Error(`SID length must be ${expected} bytes for ${subAuthCount} sub-authorities, got ${buf.length}`);
    }

    const authorityValue = buf.readUIntBE(2, 6);
    // Windows writes an authority that does not fit in 32 bits as hex
    const identifierAuthority = authorityValue < 2 ** 32
        ? authorityValue.toString(10)
        : `0x${buf.toString('hex', 2, 8).toUpperCase()}`;

    const subAuthorities = [];
    for (let i = 0; i < subAuthCount; i++) {
        subAuthorities.push(buf.readUInt32LE(SID_HEADER_BYTES + 4 * i));
    }
    return `S-${revision}-${identifierAuthority}-${subAuthorities.join('-')}`;
}

module.exports = { sidBufferToString };
