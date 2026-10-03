const request = require('supertest');

// Mock wsfed and fs so route tests don't need real certs
jest.mock('wsfed', () => {
    const auth = jest.fn((opts) => (req, res, next) => {
        // mirror the real library: resolve via getPostURL, then respond
        // synchronously from that callback
        if (opts && typeof opts.getPostURL === 'function') {
            return opts.getPostURL(req.query.wtrealm, req.query.wreply, req, (err, postUrl) => {
                if (err) { return next(err); }
                res.status(200).send(`<html><body><form action="${postUrl}">token-issued</form></body></html>`);
            });
        }
        res.status(200).send('<html><body>token-issued</body></html>');
    });
    const metadata = jest.fn(() => (req, res) => {
        res.status(200).send('<EntityDescriptor issuer="' + _capturedIssuer + '"/>');
    });
    let _capturedIssuer = '';
    // Wrap metadata to capture issuer argument
    const metadataReal = (opts) => {
        _capturedIssuer = opts.issuer;
        return metadata(opts);
    };
    return {
        auth,
        metadata: (opts) => {
            _capturedIssuer = opts.issuer;
            return (req, res) => res.status(200).send(`<EntityDescriptor issuer="${opts.issuer}"/>`);
        },
        federationServerService: {
            wsdl: (req, res) => res.status(200).send('<wsdl/>'),
            thumbprint: jest.fn(() => (req, res) => res.status(200).send('<thumbprint/>')),
        },
        _getLastAuthCall: () => auth.mock.calls.slice(-1)[0],
    };
});

jest.mock('fs', () => {
    const real = jest.requireActual('fs');
    return {
        ...real,
        readFileSync: (p, opts) => {
            // Return dummy cert content for any path under /certs
            if (p.includes('certs')) return 'FAKE_CERT_CONTENT';
            return real.readFileSync(p, opts);
        },
    };
});

const buildApp = require('./helpers/buildApp');

// Reset module registry between tests so route modules pick up fresh mocks
beforeEach(() => {
    jest.resetModules();
});

describe('GET /wsfed — unauthenticated requests', () => {
    test('returns 400 when no wa/wtrealm params and no redirect configured', async () => {
        const app = buildApp();
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(400);
    });

    test('redirects to INVALID_LOGIN_REDIRECT (303) when configured', async () => {
        const app = buildApp({ INVALID_LOGIN_REDIRECT: 'https://sso.corp/error' });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(303);
        expect(res.headers.location).toBe('https://sso.corp/error');
    });

    test('redirects to SAML2 login when valid wa + wtrealm provided', async () => {
        const app = buildApp();
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });

    test('redirects to SAML2 logout when wa=wsignout1.0', async () => {
        const app = buildApp();
        const res = await request(app)
            .get('/wsfed')
            .set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/logout');
    });
});

describe('GET /wsfed — HTTP Parameter Pollution resistance', () => {
    test('duplicate wa params do not crash the route', async () => {
        const app = buildApp();
        // Supertest encodes this as ?wa=wsignin1.0&wa=wsignout1.0
        const res = await request(app).get('/wsfed?wa=wsignin1.0&wa=wsignout1.0&wtrealm=https://exchange.corp/owa');
        // Should not crash with "hasOwnProperty is not a function" (500)
        expect(res.status).not.toBe(500);
    });

    test('duplicate wtrealm params do not bypass allowlist', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app).get('/wsfed?wa=wsignin1.0&wtrealm=https://exchange.corp/owa&wtrealm=https://attacker.com');
        // Must not redirect to SAML login with an attacker-controlled realm
        expect(res.status).not.toBe(500);
        if (res.status === 302) {
            expect(res.headers.location).toMatch('/saml2/login');
        }
    });

    // An array wtrealm becomes the string "allowed,attacker". The URL origin of that string is the allowed origin.
    test('rejects a repeated wtrealm before the allowlist check', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app).get('/wsfed?wa=wsignin1.0&wtrealm=https://exchange.corp/owa&wtrealm=https://attacker.com');
        expect(res.status).toBe(400);
    });

    test('rejects a repeated wreply before the allowlist check', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app).get('/wsfed?wa=wsignin1.0&wtrealm=https://exchange.corp/owa&wreply=https://exchange.corp/cb&wreply=https://attacker.com');
        expect(res.status).toBe(400);
    });});

describe('GET /wsfed — wtrealm allowlist enforcement', () => {
    test('allows request when wtrealm is in WSFED_ALLOWED_REALMS', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });

    test('blocks request when wtrealm is NOT in WSFED_ALLOWED_REALMS', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://attacker.com/steal' });
        expect(res.status).toBe(403);
    });

    test('blocks every wtrealm when WSFED_ALLOWED_REALMS is empty (fails closed)', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: '' });
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://anything.corp/owa' });
        expect(res.status).toBe(403);
    });
});

describe('GET /wsfed — wreply open-redirect prevention', () => {
    test('blocks wreply pointing to a different origin than wtrealm', async () => {
        const app = buildApp();
        const res = await request(app)
            .get('/wsfed')
            .query({
                wa: 'wsignin1.0',
                wtrealm: 'https://exchange.corp/owa',
                wreply: 'https://attacker.com/steal',
            });
        expect(res.status).toBe(403);
    });

    test('allows wreply sharing the wtrealm origin when both are allowlisted', async () => {
        const app = buildApp();
        const res = await request(app)
            .get('/wsfed')
            .query({
                wa: 'wsignin1.0',
                wtrealm: 'https://exchange.corp/owa',
                wreply: 'https://exchange.corp/auth/callback',
            });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });

    test('an attacker-chosen wtrealm cannot vouch for its own wreply', async () => {
        // the old same-origin fallback accepted this: same origin, but both
        // values come from the attacker
        const app = buildApp({ WSFED_ALLOWED_REALMS: '' });
        const res = await request(app)
            .get('/wsfed')
            .query({
                wa: 'wsignin1.0',
                wtrealm: 'https://attacker.tld',
                wreply: 'https://attacker.tld/collect',
            });
        expect(res.status).toBe(403);
    });

    test('blocks wreply not in allowlist even if wtrealm is allowed', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app)
            .get('/wsfed')
            .query({
                wa: 'wsignin1.0',
                wtrealm: 'https://exchange.corp/owa',
                wreply: 'https://attacker.com/steal',
            });
        expect(res.status).toBe(403);
    });

    test('allows wreply in allowlist', async () => {
        const app = buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp/owa' });
        const res = await request(app)
            .get('/wsfed')
            .query({
                wa: 'wsignin1.0',
                wtrealm: 'https://exchange.corp/owa',
                wreply: 'https://exchange.corp/auth/cb',
            });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });
});

describe('GET /wsfed — token issuance on the authenticated return path', () => {
    const REALMS = 'https://exchange.corp';
    const ARGS = { wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa', wreply: 'https://exchange.corp/auth/cb' };

    test('issues the token and clears the session cookie on the same response', async () => {
        const app = buildApp({ authenticated: true, sessionWsfedArgs: ARGS, WSFED_ALLOWED_REALMS: REALMS });
        const res = await request(app).get('/wsfed');

        expect(res.status).toBe(200);
        expect(res.text).toContain('token-issued');
        // must be cleared on the response carrying the token, not after it is sent
        expect(String(res.headers['set-cookie'])).toMatch(/connect\.sid=;/);
    });

    test('posts the token to wreply', async () => {
        const app = buildApp({ authenticated: true, sessionWsfedArgs: ARGS, WSFED_ALLOWED_REALMS: REALMS });
        const res = await request(app).get('/wsfed');
        expect(res.text).toContain(`action="${ARGS.wreply}"`);
    });

    test('falls back to wtrealm when wreply is an empty string', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { ...ARGS, wreply: '' },
            WSFED_ALLOWED_REALMS: REALMS,
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(200);
        expect(res.text).toContain(`action="${ARGS.wtrealm}"`);
    });

    test('rejects a tampered wreply replayed from the session', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { ...ARGS, wreply: 'https://attacker.tld/collect' },
            WSFED_ALLOWED_REALMS: REALMS,
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(403);
    });

    test('rejects a tampered wtrealm replayed from the session', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: 'https://attacker.tld' },
            WSFED_ALLOWED_REALMS: REALMS,
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(403);
    });
});

describe('GET /wsfed — wa dispatch (WS-Federation 1.2 §13.2.1, §17)', () => {
    const REALM = 'https://exchange.corp/owa';

    test.each(['foo', 'wattr1.0', 'wpseudo1.0', 'WSIGNIN1.0'])('wa=%s with an allowed wtrealm is refused, not treated as sign-in', async (wa) => {
        const app = buildApp();
        const res = await request(app).get('/wsfed').query({ wa, wtrealm: REALM });
        expect(res.status).toBe(400);
    });

    test('wa=wsignin1.0 without wtrealm is refused', async () => {
        const app = buildApp({ INVALID_LOGIN_REDIRECT: 'https://sso.corp/error' });
        const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0' });
        expect(res.status).toBe(400);
    });

    test('an unsupported wa on the authenticated return path issues no token', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM },
        });
        const res = await request(app).get('/wsfed').query({ wa: 'bogus' });
        expect(res.status).toBe(400);
        expect(res.text).not.toContain('token-issued');
    });

    test('a new wsignin1.0 while authenticated starts a new sign-in instead of using the stored arguments', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM },
        });
        const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: REALM });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });
});

describe('GET /wsfed — wfresh (WS-Federation 1.2 §13.2.2)', () => {
    const REALM = 'https://exchange.corp/owa';
    const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();

    test.each(['abc', '-1', '1.5', '525601', ''])('refuses wfresh=%p', async (wfresh) => {
        const app = buildApp();
        const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: REALM, wfresh });
        expect(res.status).toBe(400);
    });

    test('accepts a valid wfresh and starts the sign-in', async () => {
        const app = buildApp();
        const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });

    test('issues the token when the authentication is fresh enough', async () => {
        const app = buildApp({
            authenticated: true,
            user: { id: 'u', upn: 'u@corp', sid: 'S-1-5-21-1', authnInstant: minutesAgo(1) },
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5' },
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(200);
        expect(res.text).toContain('token-issued');
    });

    test('asks the IdP again, one time, when the authentication is too old', async () => {
        const args = { wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5' };
        const app = buildApp({
            authenticated: true,
            user: { id: 'u', upn: 'u@corp', sid: 'S-1-5-21-1', authnInstant: minutesAgo(10) },
            sessionWsfedArgs: args,
        });
        const first = await request(app).get('/wsfed');
        expect(first.status).toBe(302);
        expect(first.headers.location).toMatch('/saml2/login');
        expect(args.reauthRequested).toBe(true);

        const second = await request(app).get('/wsfed');
        expect(second.status).toBe(403);
    });

    test('wfresh=0 refuses an authentication from before the request', async () => {
        const app = buildApp({
            authenticated: true,
            user: { id: 'u', upn: 'u@corp', sid: 'S-1-5-21-1', authnInstant: minutesAgo(1) },
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM, wfresh: '0', authRequestedAt: Date.now(), reauthRequested: true },
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(403);
    });

    test('wfresh=0 accepts an authentication made after the request', async () => {
        const app = buildApp({
            authenticated: true,
            user: { id: 'u', upn: 'u@corp', sid: 'S-1-5-21-1', authnInstant: new Date().toISOString() },
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM, wfresh: '0', authRequestedAt: Date.now() - 1000 },
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(200);
    });

    test('refuses when the assertion has no AuthnInstant', async () => {
        const app = buildApp({
            authenticated: true,
            sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5' },
        });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(403);
    });
});

describe('GET /wsfed — realm tracking and sign-out cleanup (WS-Federation 1.2 §13.1.2)', () => {
    const ssoRecord = require('../../util/ssoRecord');
    const USER = { id: 'u@corp', upn: 'u@corp', sid: 'S-1', nameID: 'u@corp', sessionIndex: 'idx-1' };
    const sealed = (realms) => {
        let r = null;
        for (const realm of realms) r = ssoRecord.addRealm(r, USER, realm, 3600);
        return `wsfed_sso=${ssoRecord.seal(r, 'test-secret')}`;
    };

    test('token issuance records the realm in an encrypted, HttpOnly, Secure, SameSite=Lax cookie', async () => {
        const app = buildApp({ authenticated: true, user: USER, sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa/' } });
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(200);
        const cookie = [].concat(res.headers['set-cookie']).find((c) => c.startsWith('wsfed_sso='));
        expect(cookie).toMatch(/HttpOnly/);
        expect(cookie).toMatch(/Secure/);
        expect(cookie).toMatch(/SameSite=Lax/);
        const record = ssoRecord.open(/^wsfed_sso=([^;]+)/.exec(cookie)[1], 'test-secret');
        expect(record.realms).toEqual(['https://exchange.corp/owa/']);
        expect(record.sessionIndex).toBe('idx-1');
    });

    test('a second issuance adds its realm to the record', async () => {
        const app = buildApp({ authenticated: true, user: USER, sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/ecp/' } });
        const res = await request(app).get('/wsfed').set('Cookie', sealed(['https://exchange.corp/owa/']));
        const cookie = [].concat(res.headers['set-cookie']).find((c) => c.startsWith('wsfed_sso='));
        const record = ssoRecord.open(/^wsfed_sso=([^;]+)/.exec(cookie)[1], 'test-secret');
        expect(record.realms).toEqual(['https://exchange.corp/owa/', 'https://exchange.corp/ecp/']);
    });

    test('wsignout1.0 loads wsignoutcleanup1.0 for each allowlisted realm, then continues to the IdP step', async () => {
        const app = buildApp();
        const res = await request(app).get('/wsfed')
            .set('Cookie', sealed(['https://exchange.corp/owa/', 'https://removed.tld/app']))
            .set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(200);
        expect(res.text).toContain('src="https://exchange.corp/owa/?wa=wsignoutcleanup1.0"');
        expect(res.text).not.toContain('removed.tld');
        expect(res.text).toMatch(/data-next="\/saml2\/logout\?state=[0-9a-f]{32}"/);
        expect(res.headers['content-security-policy']).toMatch(/img-src https:\/\/exchange\.corp;/);
        expect(res.headers['content-security-policy']).toMatch(/script-src 'nonce-[^']+'/);
        expect(res.headers['cross-origin-embedder-policy']).toBe('unsafe-none');
        expect(res.headers['cache-control']).toBe('no-store');
        // kept until /saml2/logout uses the state, so a failed sign-out can be done again
        expect(String(res.headers['set-cookie'])).not.toMatch(/wsfed_sso=;/);
    });

    test('a record that cannot be read is ignored', async () => {
        const res = await request(buildApp()).get('/wsfed').set('Cookie', 'wsfed_sso=garbage').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/logout?state=');
    });

    test('wsignoutcleanup1.0 keeps the record, so a forged cleanup cannot stop a later IdP sign-out', async () => {
        const res = await request(buildApp()).get('/wsfed').set('Cookie', sealed(['https://exchange.corp/owa/'])).query({ wa: 'wsignoutcleanup1.0' });
        expect(String(res.headers['set-cookie'])).not.toMatch(/wsfed_sso=/);
    });
});

describe('GET /wsfed — wsignout1.0 request origin (logout CSRF)', () => {
    test.each([
        ['another site', { Referer: 'https://attacker.tld/page' }],
        ['no Referer or Origin', {}],
        ['a cross-site fetch', { 'Sec-Fetch-Site': 'cross-site' }],
    ])('from %s: shows a confirmation page and changes nothing', async (_name, headers) => {
        const res = await request(buildApp({ authenticated: true })).get('/wsfed').set(headers).query({ wa: 'wsignout1.0', wreply: 'https://exchange.corp/owa/' });
        expect(res.status).toBe(200);
        expect(res.text).toContain('Sign out?');
        expect(res.text).toMatch(/href="\/wsfed\?wa=wsignout1\.0&amp;confirm=[0-9a-f]{32}&amp;wreply=https%3A%2F%2Fexchange\.corp%2Fowa%2F"/);
        expect(res.headers.location).toBeUndefined();
        // only the confirmation binding is set; the session and the sign-out record are untouched
        const cookies = [].concat(res.headers['set-cookie']);
        expect(cookies).toHaveLength(1);
        expect(cookies[0]).toMatch(/^__Host-wsfed_signout_confirm=[0-9a-f]{32};.*HttpOnly.*Secure.*SameSite=Strict/);
        // browsers drop a __Host- cookie that has a Domain or a Path other than /
        expect(cookies[0]).toMatch(/Path=\/;/);
        expect(cookies[0]).not.toMatch(/Domain=/i);
    });

    test.each([
        ['an allowlisted RP (Referer)', { Referer: 'https://exchange.corp/owa/logoff.owa' }],
        ['an allowlisted RP (Origin)', { Origin: 'https://exchange.corp' }],
        ['the proxy itself', { Referer: 'https://proxy.example.com/wsfed?wa=wsignout1.0' }],
        ['a same-origin navigation', { 'Sec-Fetch-Site': 'same-origin' }],
    ])('from %s: signs out', async (_name, headers) => {
        const res = await request(buildApp()).get('/wsfed').set(headers).query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/logout?state=');
    });

    async function confirmPage(app) {
        const page = await request(app).get('/wsfed').query({ wa: 'wsignout1.0' });
        return {
            href: /href="([^"]+)"/.exec(page.text)[1].replace(/&amp;/g, '&'),
            cookie: /^__Host-wsfed_signout_confirm=[^;]+/.exec([].concat(page.headers['set-cookie'])[0])[0],
        };
    }

    test('the confirmation link works one time, in the browser that got the page', async () => {
        const app = buildApp();
        const { href, cookie } = await confirmPage(app);
        const first = await request(app).get(href).set('Cookie', cookie);
        expect(first.status).toBe(302);
        expect(first.headers.location).toMatch('/saml2/logout?state=');
        expect(String(first.headers['set-cookie'])).toMatch(/__Host-wsfed_signout_confirm=;/);
        const again = await request(app).get(href).set('Cookie', cookie);
        expect(again.text).toContain('Sign out?');
    });

    test('a link with a token that another client got does not sign the victim out', async () => {
        // the attacker loads the confirmation page, then sends the link to the victim
        const app = buildApp();
        const attacker = await confirmPage(app);
        const victim = await request(app).get(attacker.href).set('Referer', 'https://attacker.tld/');
        expect(victim.text).toContain('Sign out?');
        expect(victim.headers.location).toBeUndefined();

        const other = await confirmPage(app);
        const wrongBrowser = await request(app).get(attacker.href).set('Cookie', other.cookie);
        expect(wrongBrowser.text).toContain('Sign out?');
    });

    test('a forged confirm value does not count', async () => {
        const res = await request(buildApp()).get('/wsfed').query({ wa: 'wsignout1.0', confirm: 'f'.repeat(32) });
        expect(res.text).toContain('Sign out?');
    });
});

describe('GET /wsfed — wa=wsignoutcleanup1.0 (WS-Federation 1.2 §13.2.4.2)', () => {
    test('clears the session and returns an uncached cross-origin image', async () => {
        const app = buildApp({ authenticated: true, sessionWsfedArgs: { wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa' } });
        const res = await request(app).get('/wsfed').query({ wa: 'wsignoutcleanup1.0' });
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toBe('image/gif');
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.headers['cross-origin-resource-policy']).toBe('cross-origin');
        expect(String(res.headers['set-cookie'])).toMatch(/connect\.sid=;/);
    });

    test('does not contact the IdP', async () => {
        const app = buildApp({ authenticated: true });
        const res = await request(app).get('/wsfed').query({ wa: 'wsignoutcleanup1.0' });
        expect(res.headers.location).toBeUndefined();
    });

    test('redirects to an allowlisted wreply', async () => {
        const app = buildApp();
        const res = await request(app).get('/wsfed').query({ wa: 'wsignoutcleanup1.0', wreply: 'https://exchange.corp/owa/' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://exchange.corp/owa/');
    });

    test('refuses a wreply outside the allowlist', async () => {
        const app = buildApp();
        const res = await request(app).get('/wsfed').query({ wa: 'wsignoutcleanup1.0', wreply: 'https://attacker.tld/' });
        expect(res.status).toBe(403);
    });
});
