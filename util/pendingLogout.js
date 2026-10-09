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
// not exported from the package index
const {InMemoryCacheProvider} = require('@node-saml/node-saml/lib/in-memory-cache-provider');

/**
 * Server-side state for one sign-out, kept from wsignout1.0 until the IdP
 * LogoutResponse. The browser carries only the random ID, as `state` and as
 * SAML RelayState. The session cookie cannot carry it: the session is gone
 * by then, and SameSite=strict drops it on the cross-site IdP return.
 *
 * Entries expire after 10 minutes. There is no size limit, so a flood cannot
 * push out other users' entries; growth is bounded by the expiry and the rate limit.
 */
const store = new InMemoryCacheProvider({keyExpirationPeriodMs: 10 * 60 * 1000});

async function put(value) {
    const id = crypto.randomBytes(16).toString('hex');
    await store.saveAsync(id, JSON.stringify(value));
    return id;
}

// Each ID works one time only. removeAsync deletes before it yields and returns null to
// every later caller, so two concurrent requests with the same ID cannot both get the value.
async function take(id) {
    if (typeof id !== 'string') return undefined;
    const stored = await store.getAsync(id);
    if (stored === null) return undefined;
    if (await store.removeAsync(id) === null) return undefined;
    return JSON.parse(stored);
}

const pendingLogout = {put, take};

module.exports = {pendingLogout};
