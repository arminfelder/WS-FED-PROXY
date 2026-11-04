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
const {pendingLogout} = require('./pendingLogout');

// WS-Federation 1.2 §13.2.4.2: wreply is the URL to go to after the cleanup.
function cleanupUrl(realm, wreply) {
    const url = new URL(realm);
    url.searchParams.set('wa', 'wsignoutcleanup1.0');
    if (wreply) url.searchParams.set('wreply', wreply);
    return url.toString();
}

/**
 * WS-Federation 1.2 §13.1.2: send wsignoutcleanup1.0 to every realm that got a token, then go to
 * continueUrl. The proxy cannot open outbound connections, so the browser goes to the cleanup URLs.
 * A realm removed from the allowlist since issuance gets no request.
 *
 * WSFED_SIGNOUT_CLEANUP=redirect (default): a top-level redirect to each realm, with a wreply back to
 * the proxy. Only a top-level navigation sends the RP cookies when the RP is on another site:
 * OWA sets FedAuth without SameSite, and Chromium omits it on a cross-site image request.
 * WSFED_SIGNOUT_CLEANUP=image: one page loads all cleanup URLs as images. Use it for an RP that
 * does not go back to wreply.
 */
async function sendCleanupThenContinue(req, res, record, continueUrl) {
    const allowedOrigins = req.app.get("WSFED_ALLOWED_REALMS") || [];
    const realms = record ? record.realms.filter((r) => isRealmAllowed(r, allowedOrigins)) : [];
    res.set('Cache-Control', 'no-store');
    if (realms.length === 0) {
        return res.redirect(continueUrl);
    }
    if (req.app.get("WSFED_SIGNOUT_CLEANUP") === 'image') {
        return sendImagePage(res, realms, continueUrl);
    }
    return redirectToNextRealm(req, res, realms, continueUrl);
}

function sendImagePage(res, realms, continueUrl) {
    const cleanupUrls = realms.map((r) => cleanupUrl(r));
    const imgOrigins = [...new Set(cleanupUrls.map((u) => new URL(u).origin))];
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set('Content-Security-Policy',
        `default-src 'none'; img-src ${imgOrigins.join(' ')}; script-src 'nonce-${nonce}'; ` +
        `form-action 'none'; frame-ancestors 'none'; base-uri 'none'`);
    // the RP cleanup responses carry no CORP header, so require-corp would block them
    res.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
    res.render('signout', {cleanupUrls, continueUrl, nonce});
}

// The browser carries only a random one-time ID. The other realms and the next URL stay on the server.
async function redirectToNextRealm(req, res, realms, next) {
    const [realm, ...rest] = realms;
    const id = await pendingLogout.put({kind: 'cleanup', realms: rest, next});
    const back = new URL(req.app.get("WSFED_ROOT") + '/signout/continue', new URL(req.app.get("WSFED_ISSUER")).origin);
    back.searchParams.set('c', id);
    res.set('Cache-Control', 'no-store');
    res.redirect(cleanupUrl(realm, back.href));
}

/** The wreply target of each cleanup: go to the next realm, or to the next sign-out step. */
async function continueCleanup(req, res) {
    const entry = await pendingLogout.take(req.query.c);
    res.set('Cache-Control', 'no-store');
    if (!entry || entry.kind !== 'cleanup') {
        return res.status(400).render('signout-failed', {pageTitle: 'Sign out'});
    }
    if (entry.realms.length === 0) {
        return res.redirect(entry.next);
    }
    return redirectToNextRealm(req, res, entry.realms, entry.next);
}

module.exports = {sendCleanupThenContinue, continueCleanup};
