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
});
