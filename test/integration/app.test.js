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
