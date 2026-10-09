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

const sidConverter = require('security-identifier');

// Text form of a Windows SID (MS-DTYP §2.4.2.1). The identifier authority is
// decimal below 2^32 and 12 hex digits above; 1 to 15 sub-authorities.
const SID_PATTERN = /^S-1-(\d{1,10}|0x[0-9A-Fa-f]{12})((?:-\d{1,10}){1,15})$/;
const UINT32_MAX = 0xFFFFFFFF;

/** A required claim is missing or malformed. The assertion is refused, not the process. */
class ClaimError extends Error {}

function isWellFormedSid(sid) {
    const match = SID_PATTERN.exec(sid);
    if (!match) return false;
    if (!match[1].startsWith('0x') && Number(match[1]) > UINT32_MAX) return false;
    return match[2].slice(1).split('-').every((sub) => Number(sub) <= UINT32_MAX);
}

// node-saml copies only the first attribute with a given Name into the profile.
// Collect the values from the assertion, so that a duplicate attribute is refused.
function attributeValues(assertion, name) {
    const statements = (assertion && assertion.Assertion && assertion.Assertion.AttributeStatement) || [];
    const values = [];
    for (const statement of statements) {
        for (const attribute of statement.Attribute || []) {
            if (!attribute.$ || attribute.$.Name !== name) continue;
            for (const value of attribute.AttributeValue || []) {
                values.push(typeof value === 'string' ? value : value._);
            }
        }
    }
    return values;
}

function requiredAttribute(assertion, name, claim) {
    const values = attributeValues(assertion, name);
    if (values.length === 0) throw new ClaimError(`assertion has no ${claim} (attribute "${name}")`);
    if (values.length > 1) throw new ClaimError(`assertion has more than one ${claim} (attribute "${name}")`);
    if (typeof values[0] !== 'string' || values[0] === '') {
        throw new ClaimError(`assertion has no usable ${claim} (attribute "${name}")`);
    }
    return values[0];
}

/** @throws {ClaimError} */
function parseSid(raw, base64) {
    let sid = raw;
    if (base64) {
        const buf = Buffer.from(raw, 'base64');
        // revision, sub-authority count, 6-byte authority, 4 bytes per sub-authority.
        // security-identifier reads past the end of a shorter buffer.
        if (buf.length < 8 || buf.length !== 8 + 4 * buf[1]) {
            throw new ClaimError('SID attribute is not a binary SID');
        }
        sid = sidConverter.sidBufferToString(buf);
    }
    if (!isWellFormedSid(sid)) {
        throw new ClaimError('SID attribute is not a well-formed SID');
    }
    return sid;
}

/**
 * Builds the session user from a verified SAML profile.
 *
 * NameID, UPN and SID are required. Exchange claims-based authentication
 * needs the UPN and primary SID claims in every token.
 *
 * @param {{upnAttribute: string, sidAttribute: string, sidBase64: boolean}} settings
 * @throws {ClaimError}
 */
function userFromProfile(profile, { upnAttribute, sidAttribute, sidBase64 }) {
    const assertion = typeof profile.getAssertion === 'function' ? profile.getAssertion() : undefined;
    if (!assertion || !assertion.Assertion) throw new ClaimError('profile has no assertion');
    const user = {};
    if (typeof profile.nameID !== 'string' || profile.nameID === '') {
        throw new ClaimError('assertion has no usable NameID');
    }
    user.id = profile.nameID;
    user.nameID = user.id;
    user.nameIDFormat = profile.nameIDFormat;
    // node-saml puts these in the IdP LogoutRequest
    user.nameQualifier = profile.nameQualifier;
    user.spNameQualifier = profile.spNameQualifier;
    user.sessionIndex = profile.sessionIndex;
    user.upn = requiredAttribute(assertion, upnAttribute, 'UPN');
    user.sid = parseSid(requiredAttribute(assertion, sidAttribute, 'SID'), sidBase64);
    const authnStatement = assertion.Assertion.AuthnStatement;
    const authn = authnStatement && authnStatement[0] && authnStatement[0].$;
    // wfresh compares this with the requested maximum age (WS-Federation 1.2 §13.2.2)
    user.authnInstant = authn ? authn.AuthnInstant : undefined;
    // the issued token must not outlive the IdP session (routes/wsfed.js tokenLifetime)
    user.sessionNotOnOrAfter = authn ? authn.SessionNotOnOrAfter : undefined;
    return user;
}

module.exports = { userFromProfile, parseSid, ClaimError, SID_PATTERN };
