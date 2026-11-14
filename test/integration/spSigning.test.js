/**
 * SAML2_SP_KEY / SAML2_SP_CERT: the proxy signs its AuthnRequest and logout messages.
 * Real node-saml strategy; certificate reads go to test/fixtures.
 */

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

const SP_ENV = ['SAML2_SP_KEY', 'SAML2_SP_CERT'];

function buildApp(env) {
    for (const name of SP_ENV) delete process.env[name];
    Object.assign(process.env, { WSFED_ALLOWED_REALMS: 'https://exchange.corp' }, env);
    // a fresh module registry for each app: jest ignores require.cache, which buildFullApp clears
    let app;
    jest.isolateModules(() => { app = require('./helpers/buildFullApp')(); });
    return app;
}

async function authnRequestUrl(app) {
    const res = await request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: 'https://exchange.corp/owa/' });
    expect(res.status).toBe(302);
    return new URL(res.headers.location);
}

describe('SP request signing', () => {
    test('without the settings the AuthnRequest is not signed', async () => {
        const url = await authnRequestUrl(buildApp({}));
        expect(url.searchParams.has('SAMLRequest')).toBe(true);
        expect(url.searchParams.has('Signature')).toBe(false);
    });

    test('with both settings the AuthnRequest carries an RSA-SHA256 signature', async () => {
        const url = await authnRequestUrl(buildApp({ SAML2_SP_KEY: 'test-cert.key', SAML2_SP_CERT: 'test-cert.pem' }));
        expect(url.searchParams.get('SigAlg')).toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        expect(url.searchParams.get('Signature')).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    test.each([
        ['SAML2_SP_KEY', 'test-cert.key'],
        ['SAML2_SP_CERT', 'test-cert.pem'],
    ])('exits 1 when only %s is set', (name, value) => {
        const exit = jest.spyOn(process, 'exit').mockImplementation((code) => { throw new Error(`exit ${code}`); });
        const error = jest.spyOn(console, 'error').mockImplementation(() => {});
        try {
            expect(() => buildApp({ [name]: value })).toThrow('exit 1');
            expect(error.mock.calls.flat().join('\n')).toMatch(/FATAL: SAML2_SP_KEY and SAML2_SP_CERT/);
        } finally {
            exit.mockRestore();
            error.mockRestore();
        }
    });
});
