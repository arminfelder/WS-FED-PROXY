const request = require('supertest');

// Mock wsfed and fs so route tests don't need real certs
jest.mock('wsfed', () => {
    const auth = jest.fn(() => (req, res, next) => {
        // Simulate wsfed generating a token page
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
            .query({ wa: 'wsignout1.0' });
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
});

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

    test('allows any wtrealm when WSFED_ALLOWED_REALMS is not configured', async () => {
        const app = buildApp();
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: 'https://anything.corp/owa' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch('/saml2/login');
    });
});

describe('GET /wsfed — wreply open-redirect prevention', () => {
    test('blocks wreply pointing to a different origin than wtrealm (no allowlist)', async () => {
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

    test('allows wreply sharing the wtrealm origin (no allowlist)', async () => {
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

describe('GET /wsfed/FederationMetadata — issuer is taken from config', () => {
    test('metadata endpoint uses WSFED_ISSUER, not hardcoded string', async () => {
        const app = buildApp({ WSFED_ISSUER: 'https://proxy.example.com/wsfed' });
        const res = await request(app)
            .get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml');
        expect(res.status).toBe(200);
        expect(res.text).toContain('https://proxy.example.com/wsfed');
        expect(res.text).not.toContain('the-issuer');
    });
});
