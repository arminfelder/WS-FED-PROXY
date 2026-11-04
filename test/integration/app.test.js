const request = require('supertest');

jest.mock('fs', () => {
    const real = jest.requireActual('fs');
    const nodePath = jest.requireActual('path');
    const fixtures = nodePath.join(__dirname, '../fixtures');
    return {
        ...real,
        readFileSync: (p, opts) => {
            const s = String(p);
            if (s.includes(`${nodePath.sep}certs${nodePath.sep}`)) {
                const name = nodePath.basename(s) === 'idp.pem' ? 'test-cert.pem' : nodePath.basename(s);
                return real.readFileSync(nodePath.join(fixtures, name), opts);
            }
            return real.readFileSync(p, opts);
        },
    };
});

let app;
beforeAll(() => {
    process.env.WSFED_ALLOWED_REALMS = 'https://exchange.corp';
    app = require('./helpers/buildFullApp')();
});

describe('error page', () => {
    test('a 400 shows "400 Bad Request", not "Internal Server Error"', async () => {
        const res = await request(app).get('/wsfed');
        expect(res.status).toBe(400);
        expect(res.text).toContain('400 Bad Request');
        expect(res.text).not.toContain('Internal Server Error');
    });

    test('a 403 shows "403 Forbidden"', async () => {
        const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: 'https://attacker.tld' });
        expect(res.status).toBe(403);
        expect(res.text).toContain('403 Forbidden');
    });

    test('a 404 shows "404 Not Found"', async () => {
        const res = await request(app).get('/nope');
        expect(res.status).toBe(404);
        expect(res.text).toContain('404 Not Found');
    });
});

describe('Content-Security-Policy', () => {
    const scriptSrc = (res) => /script-src ([^;]*)/.exec(res.headers['content-security-policy'])[1];

    test('script-src is a per-response nonce, not unsafe-inline', async () => {
        const first = await request(app).get('/nope');
        const second = await request(app).get('/nope');
        expect(scriptSrc(first)).toMatch(/^'nonce-[A-Za-z0-9+/=]{22,}'$/);
        expect(scriptSrc(first)).not.toBe(scriptSrc(second));
        expect(scriptSrc(first)).not.toContain('unsafe-inline');
    });
});

describe('session cookie', () => {
    afterEach(() => {
        delete process.env.TRUST_PROXY;
    });

    test('is __Host- prefixed: Secure, Path=/, no Domain, HttpOnly, SameSite=Strict', async () => {
        // secure cookies are only set on a request Express sees as HTTPS
        process.env.TRUST_PROXY = '1';
        let proxied;
        jest.isolateModules(() => { proxied = require('./helpers/buildFullApp')(); });
        const res = await request(proxied)
            .get('/wsfed')
            .set('X-Forwarded-Proto', 'https')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://exchange.corp' });
        expect(res.status).toBe(302);
        const cookie = String(res.headers['set-cookie']);
        expect(cookie).toMatch(/^__Host-sid=/);
        expect(cookie).toMatch(/; Path=\//);
        expect(cookie).toMatch(/; HttpOnly/);
        expect(cookie).toMatch(/; Secure/);
        expect(cookie).toMatch(/; SameSite=Strict/);
        expect(cookie).not.toMatch(/Domain=/i);
    });

    test('is cleared under the same name when the token is issued or the user signs out', async () => {
        const res = await request(app).get('/wsfed').query({ wa: 'wsignoutcleanup1.0' });
        expect(res.status).toBe(200);
        const cookie = String(res.headers['set-cookie']);
        expect(cookie).toMatch(/^__Host-sid=; Path=\//);
        // without Secure the browser drops a __Host- cookie, the expiry one included
        expect(cookie).toMatch(/; Secure/);
        expect(cookie).toMatch(/; HttpOnly/);
        expect(cookie).toMatch(/; SameSite=Strict/);
    });
});

describe('SAML verify callback', () => {
    const verify = (profile) => new Promise((resolve) => {
        require('passport')._strategy('saml')._signonVerify(profile, (err, user, info) => resolve({ err, user, info }));
    });
    const withAttributes = (attrs) => ({
        nameID: 'alice',
        getAssertion: () => ({ Assertion: { AttributeStatement: [{
            Attribute: Object.entries(attrs).map(([name, v]) => ({ $: { Name: name }, AttributeValue: [{ _: v }] })),
        }] } }),
    });

    test('refuses an assertion without the required claims instead of issuing a token for it', async () => {
        const { err, user, info } = await verify(withAttributes({ upn: 'alice@example.com' }));
        expect(err).toBeNull();
        expect(user).toBe(false);
        expect(info.message).toMatch(/SID/);
    });

    test('accepts a complete assertion', async () => {
        const sid = require('security-identifier').sidStringToBuffer('S-1-5-21-1-2-3-500').toString('base64');
        const { err, user } = await verify(withAttributes({ upn: 'alice@example.com', sid }));
        expect(err).toBeNull();
        expect(user).toMatchObject({ id: 'alice', upn: 'alice@example.com', sid: 'S-1-5-21-1-2-3-500' });
    });
});

describe('access log', () => {
    const capture = () => {
        const lines = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => { lines.push(String(chunk)); return true; });
        return () => lines
            .filter((l) => l.startsWith('{'))
            .map((l) => JSON.parse(l))
            .filter((r) => r.message === 'access_log');
    };

    afterEach(() => {
        jest.restoreAllMocks();
        delete process.env.TRUST_PROXY;
    });

    test('request and response headers are not logged: Cookie and Set-Cookie carry the session ID', async () => {
        // the Secure session cookie is only set on a request Express sees as HTTPS
        process.env.TRUST_PROXY = '1';
        let proxied;
        jest.isolateModules(() => { proxied = require('./helpers/buildFullApp')(); });
        const accessLines = capture();
        const res = await request(proxied)
            .get('/wsfed')
            .set('X-Forwarded-Proto', 'https')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://exchange.corp' })
            .set('Cookie', '__Host-sid=s%3Asecret-session-id');
        const issued = String(res.headers['set-cookie']).split(';')[0].split('=')[1];
        expect(issued).toBeTruthy();
        const access = accessLines();
        expect(access).toHaveLength(1);
        expect(access[0].http.request.headers).toBeUndefined();
        expect(access[0].http.response.headers).toBeUndefined();
        expect(JSON.stringify(access)).not.toContain('secret-session-id');
        expect(JSON.stringify(access)).not.toContain(issued);
        expect(JSON.stringify(access)).not.toMatch(/set-cookie/i);
        // the fields the headers fed stay
        expect(access[0].http.request.method).toBe('GET');
        expect(access[0].http.response.status_code).toBe(302);
    });

    test('http.request.id is the server UUID, not a client X-Request-ID', async () => {
        const accessLines = capture();
        await request(app).get('/nope').set('X-Request-ID', 'forged-id');
        const [rec] = accessLines();
        expect(rec.http.request.id).toBe(rec['http.request.id']);
        expect(JSON.stringify(rec)).not.toContain('forged-id');
    });
});

describe('SAML request-ID cache', () => {
    test("both strategies share one node-saml InMemoryCacheProvider with a short TTL", () => {
        const passport = require('passport');
        const { InMemoryCacheProvider } = require('@node-saml/node-saml/lib/in-memory-cache-provider');
        const cache = passport._strategy('saml')._saml.options.cacheProvider;
        expect(cache).toBeInstanceOf(InMemoryCacheProvider);
        // shared: a response to a saml-force request arrives at the "saml" /callback
        expect(passport._strategy('saml-force')._saml.options.cacheProvider).toBe(cache);
        expect(cache.options.keyExpirationPeriodMs).toBe(15 * 60 * 1000);
        expect(passport._strategy('saml')._saml.options.requestIdExpirationPeriodMs).toBe(15 * 60 * 1000);
    });
});

describe('startup config', () => {
    afterEach(() => {
        delete process.env.WSFED_TOKEN_LIFETIME;
        jest.restoreAllMocks();
    });

    test.each(['0', 'abc', '600abc'])('WSFED_TOKEN_LIFETIME=%s stops startup instead of giving an 8-hour token', (bad) => {
        process.env.WSFED_TOKEN_LIFETIME = bad;
        jest.spyOn(console, 'error').mockImplementation(() => {});
        // a no-op exit would let startup continue past the guard
        jest.spyOn(process, 'exit').mockImplementation((code) => { throw new Error(`exit ${code}`); });
        // jest keeps its own module registry; clearing require.cache does not reload app.js
        expect(() => jest.isolateModules(() => require('./helpers/buildFullApp')())).toThrow('exit 1');
        expect(console.error).toHaveBeenCalledWith(expect.stringContaining('WSFED_TOKEN_LIFETIME'));
    });
});
