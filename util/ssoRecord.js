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
 * The sign-out record: the realms that got a token, and the SAML identity for
 * the IdP LogoutRequest (WS-Federation 1.2 §13.1.2).
 *
 * The session ends when the token is issued, so the record lives in its own
 * encrypted cookie. Only sign-out reads it. It never authorizes a token.
 */

const crypto = require('crypto');

// The __Host- prefix makes the browser refuse this name from a sibling subdomain.
// Without it, a planted record could send the IdP the LogoutRequest of a different user.
const COOKIE_NAME = '__Host-wsfed_sso';
const MAX_REALMS = 20;
// The browser drops a cookie that is larger than 4096 bytes. 20 realms of this length stay below that.
const MAX_REALM_LENGTH = 100;
const IDENTITY_FIELDS = ['nameID', 'nameIDFormat', 'nameQualifier', 'spNameQualifier', 'sessionIndex'];

let cachedKey = {secret: undefined, key: undefined};

function deriveKey(secret) {
    if (cachedKey.secret !== secret) {
        const key = Buffer.from(crypto.hkdfSync('sha256', String(secret), Buffer.alloc(0), 'wsfed-sso-v1', 32));
        cachedKey = {secret, key};
    }
    return cachedKey.key;
}

/**
 * The realm without query and fragment. The allowlist checks only the origin, so the
 * rest of wtrealm comes from the caller. One RP must not fill the list with variants.
 *
 * @returns {string|null} null if wtrealm is not an absolute URL or is too long
 */
function normalizeRealm(wtrealm) {
    let url;
    try {
        url = new URL(wtrealm);
    } catch {
        return null;
    }
    const realm = url.origin + url.pathname;
    return realm.length <= MAX_REALM_LENGTH ? realm : null;
}

function seal(record, secret) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(secret), iv);
    cipher.setAAD(Buffer.from(COOKIE_NAME));
    const body = Buffer.concat([cipher.update(JSON.stringify(record), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

/** @returns {object|null} null if the value is missing, changed, expired or not readable */
function open(token, secret) {
    if (typeof token !== 'string' || token === '') return null;
    try {
        const raw = Buffer.from(token, 'base64url');
        if (raw.length < 29) return null;
        const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(secret), raw.subarray(0, 12));
        decipher.setAAD(Buffer.from(COOKIE_NAME));
        decipher.setAuthTag(raw.subarray(12, 28));
        const record = JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8'));
        if (typeof record.exp !== 'number' || Date.now() >= record.exp) return null;
        return record;
    } catch {
        return null;
    }
}

/** Adds wtrealm to the record and takes the identity from the current login. */
function addRealm(existing, user, wtrealm, maxAgeSeconds) {
    const realm = normalizeRealm(wtrealm);
    const realms = (existing && Array.isArray(existing.realms) ? existing.realms : []).filter((r) => r !== realm);
    if (realm !== null) realms.push(realm);
    const record = {realms: realms.slice(-MAX_REALMS), exp: Date.now() + maxAgeSeconds * 1000};
    for (const f of IDENTITY_FIELDS) {
        if (user && user[f] !== undefined) record[f] = user[f];
    }
    return record;
}

/** The identity part, in the shape node-saml reads for a LogoutRequest. */
function identity(record) {
    if (!record || !record.nameID) return null;
    const user = {};
    for (const f of IDENTITY_FIELDS) {
        if (record[f] !== undefined) user[f] = record[f];
    }
    return user;
}

function readCookie(req, name) {
    const header = req.headers && req.headers.cookie;
    if (!header) return undefined;
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
    }
    return undefined;
}

module.exports = {COOKIE_NAME, MAX_REALM_LENGTH, seal, open, addRealm, identity, readCookie, normalizeRealm};
