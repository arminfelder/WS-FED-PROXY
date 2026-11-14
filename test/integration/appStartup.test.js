/**
 * Startup checks of app.js: every bad setting must end the process with a FATAL line.
 * process.exit is replaced by a throw, so that nothing runs past the guard.
 */

const path = require('path');

jest.mock('fs', () => {
    const real = jest.requireActual('fs');
    const nodePath = jest.requireActual('path');
    const fixtures = nodePath.join(__dirname, '../fixtures');
    const names = { 'exchange.crt': 'test-cert.pem', 'exchange.key': 'test-cert.key', 'exchange.p7b': 'test-cert.pem', 'idp.pem': 'test-cert.pem' };
    return {
        ...real,
        readFileSync: (p, opts) => {
            const s = String(p);
            if (s.includes(`${nodePath.sep}certs${nodePath.sep}`)) {
                const name = nodePath.basename(s);
                if (global.__unreadableCertFile === name) {
                    const err = new Error(`EACCES: permission denied, open '${s}'`);
                    err.code = 'EACCES';
                    throw err;
                }
                return real.readFileSync(nodePath.join(fixtures, names[name] || name), opts);
            }
            return real.readFileSync(p, opts);
        },
    };
});

const BASE_ENV = {
    WSFED_ISSUER: 'https://proxy.example.com/wsfed',
    SAML2_IDP: 'https://idp.example.com/saml',
    WSFED_ALLOWED_REALMS: 'https://exchange.corp',
};

class ExitError extends Error {}

function startApp(env) {
    const saved = { ...process.env };
    for (const key of Object.keys(process.env)) {
        if (/^(WSFED|SAML2|SESSION|TRUST_PROXY|NODE_ENV)/.test(key)) delete process.env[key];
    }
    Object.assign(process.env, BASE_ENV, env);
    const exit = jest.spyOn(process, 'exit').mockImplementation((code) => { throw new ExitError(String(code)); });
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    let app;
    let thrown;
    let fatal;
    try {
        jest.isolateModules(() => {
            app = require(path.join(__dirname, '../../app'));
        });
    } catch (err) {
        thrown = err;
    } finally {
        fatal = error.mock.calls.map((c) => c.join(' ')).filter((l) => l.startsWith('FATAL:'));
        exit.mockRestore();
        error.mockRestore();
        for (const key of Object.keys(process.env)) delete process.env[key];
        Object.assign(process.env, saved);
    }
    return { app, thrown, fatal };
}

describe('app.js startup', () => {
    afterEach(() => { delete global.__unreadableCertFile; });

    test('starts with a complete configuration', () => {
        const { app, thrown } = startApp({});
        expect(thrown).toBeUndefined();
        expect(app.get('WSFED_SIGNING').key.length).toBeGreaterThan(0);
    });

    test.each(['exchange.crt', 'exchange.key', 'exchange.p7b'])('exits 1 when %s cannot be read', (file) => {
        global.__unreadableCertFile = file;
        const { thrown, fatal } = startApp({});
        expect(thrown).toBeInstanceOf(ExitError);
        expect(thrown.message).toBe('1');
        expect(fatal.join('\n')).toMatch(new RegExp(`FATAL:.*${file.replace('.', '\\.')}`));
    });

    function expectFatal(env, pattern) {
        const { thrown, fatal } = startApp(env);
        expect(thrown).toBeInstanceOf(ExitError);
        expect(thrown.message).toBe('1');
        expect(fatal.join('\n')).toMatch(pattern);
    }

    describe('URL settings', () => {
        test.each([
            ['WSFED_ISSUER', 'proxy.example.com/wsfed'],
            ['WSFED_ISSUER', 'ftp://proxy.example.com/wsfed'],
            ['SAML2_IDP', 'idp.example.com'],
        ])('exits 1 when %s is %p', (name, value) => {
            expectFatal({ [name]: value }, new RegExp(`FATAL: ${name}`));
        });

        test('accepts http URLs outside production', () => {
            const { thrown } = startApp({ WSFED_ISSUER: 'http://proxy.example.com/wsfed', SAML2_IDP: 'http://idp.example.com/saml' });
            expect(thrown).toBeUndefined();
        });

        test.each(['WSFED_ISSUER', 'SAML2_IDP'])('refuses an http %s in production', (name) => {
            expectFatal({ NODE_ENV: 'production', [name]: 'http://host.example.com/x' }, new RegExp(`FATAL: ${name}.*https`));
        });

        test.each([
            ['WSFED_ISSUER', 'https://localhost:3000/wsfed'],
            ['SAML2_IDP', 'https://127.0.0.1:8443/saml'],
        ])('refuses a loopback %s in production', (name, value) => {
            expectFatal({ NODE_ENV: 'production', [name]: value }, new RegExp(`FATAL: ${name}.*loopback`));
        });

        test('a hostname that only starts with "localhost" is not loopback', () => {
            const { thrown } = startApp({ NODE_ENV: 'production', WSFED_ISSUER: 'https://localhost.corp.example/wsfed', SESSION_SECRET: 's', SAML2_IDP_ISSUER: 'i' });
            expect(thrown).toBeUndefined();
        });
    });

    describe('WSFED_ALLOWED_REALMS in production', () => {
        test('refuses an http realm: CSP form-action https: would block the token POST', () => {
            expectFatal({ NODE_ENV: 'production', WSFED_ALLOWED_REALMS: 'https://exchange.corp,http://owa.corp' }, /FATAL: WSFED_ALLOWED_REALMS.*http:\/\/owa\.corp/);
        });

        test('accepts an http realm outside production', () => {
            expect(startApp({ WSFED_ALLOWED_REALMS: 'http://owa.corp' }).thrown).toBeUndefined();
        });
    });

    describe('production warnings', () => {
        function warnings(env) {
            const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
            let lines;
            try {
                const { thrown } = startApp(env);
                expect(thrown).toBeUndefined();
            } finally {
                lines = write.mock.calls.map((c) => String(c[0]));
                write.mockRestore();
            }
            return lines.map((l) => JSON.parse(l)).filter((r) => r['log.level'] === 'warn');
        }

        test('warns when SESSION_SECRET is random: sign-out records do not survive a restart', () => {
            const messages = warnings({ NODE_ENV: 'production', SAML2_IDP_ISSUER: 'i' }).map((r) => r.message);
            expect(messages).toHaveLength(1);
            expect(messages[0]).toMatch(/SESSION_SECRET/);
        });

        test('warns when SAML2_IDP_ISSUER is empty: the issuer is not checked', () => {
            const messages = warnings({ NODE_ENV: 'production', SESSION_SECRET: 's' }).map((r) => r.message);
            expect(messages).toHaveLength(1);
            expect(messages[0]).toMatch(/SAML2_IDP_ISSUER/);
        });

        test('is silent when both are set', () => {
            expect(warnings({ NODE_ENV: 'production', SESSION_SECRET: 's', SAML2_IDP_ISSUER: 'i' })).toHaveLength(0);
        });
    });
});
