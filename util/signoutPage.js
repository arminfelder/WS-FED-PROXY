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

const crypto = require('crypto');
const {isRealmAllowed} = require('./validateRedirect');

function cleanupUrl(realm) {
    const url = new URL(realm);
    url.searchParams.set('wa', 'wsignoutcleanup1.0');
    return url.toString();
}

/**
 * WS-Federation 1.2 §13.1.2: send wsignoutcleanup1.0 to every realm that got a token, then go to
 * continueUrl. The proxy cannot open outbound connections, so the browser loads the cleanup URLs.
 * A realm removed from the allowlist since issuance gets no request.
 */
function sendCleanupThenContinue(req, res, record, continueUrl) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    const realms = record ? record.realms.filter((r) => isRealmAllowed(r, allowedOrigins)) : [];
    res.set('Cache-Control', 'no-store');
    if (realms.length === 0) {
        return res.redirect(continueUrl);
    }
    const cleanupUrls = realms.map(cleanupUrl);
    const imgOrigins = [...new Set(cleanupUrls.map((u) => new URL(u).origin))];
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set('Content-Security-Policy',
        `default-src 'none'; img-src ${imgOrigins.join(' ')}; script-src 'nonce-${nonce}'; ` +
        `form-action 'none'; frame-ancestors 'none'; base-uri 'none'`);
    // the RP cleanup responses carry no CORP header, so require-corp would block them
    res.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
    res.render('signout', {cleanupUrls, continueUrl, nonce});
}

module.exports = {sendCleanupThenContinue};
