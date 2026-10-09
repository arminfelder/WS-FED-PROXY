const request = require('supertest');

// passport.authenticate is a heavy dependency; stub it so tests don't need a
// real SAML IDP or certificate files.
jest.mock('passport', () => {
    const original = jest.requireActual('passport');
    const logout = jest.fn((req, cb) => cb(null, 'https://idp.example.com/logout'));
    return {
        ...original,
        authenticate: jest.fn((strategy, opts, callback) => (req, res, next) => {
            // Simulate failure by redirecting to failureRedirect
            if (opts && opts.failureRedirect) {
                return res.redirect(opts.failureRedirect);
            }
            // ?reject=1 simulates a message the strategy refuses
            if (callback && req.query && req.query.reject) {
                return callback(new Error('rejected'));
            }
            // a valid LogoutResponse: the strategy calls pass()
            next();
        }),
        _strategy: jest.fn(() => ({ logout })),
    };
});

const buildApp = require('./helpers/buildApp');
const passport = require('passport');
const ssoRecord = require('../../util/ssoRecord');

const SAML_USER = { id: 'u@corp', upn: 'u@corp', sid: 'S-1-5-21-1', nameID: 'u@corp', nameIDFormat: 'fmt', sessionIndex: 'idx-1' };

beforeEach(() => passport._strategy().logout.mockClear());

describe('GET /saml2/failure', () => {
    test('returns 401 with a plain-text body', async () => {
        const app = buildApp();
        const res = await request(app).get('/saml2/failure');
        expect(res.status).toBe(401);
        expect(res.text).toMatch(/authentication failed/i);
    });
});

describe('GET /saml2/login', () => {
    test('redirects to failureRedirect when authentication fails', async () => {
        const app = buildApp();
        const res = await request(app).get('/saml2/login');
        // With our mock, authenticate() immediately hits failureRedirect
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('/saml2/failure');
    });
});

describe('GET /saml2/login — strategy for wfresh', () => {
    const passport = require('passport');
    const REALM = 'https://exchange.corp/owa';

    test.each([
        [{ wa: 'wsignin1.0', wtrealm: REALM }, 'saml'],
        [{ wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5' }, 'saml'],
        [{ wa: 'wsignin1.0', wtrealm: REALM, wfresh: '0' }, 'saml-force'],
        [{ wa: 'wsignin1.0', wtrealm: REALM, wfresh: '5', reauthRequested: true }, 'saml-force'],
    ])('%o uses %s', async (sessionWsfedArgs, strategy) => {
        passport.authenticate.mockClear();
        await request(buildApp({ sessionWsfedArgs })).get('/saml2/login');
        expect(passport.authenticate.mock.calls[0][0]).toBe(strategy);
    });
});

describe('GET /saml2/logout', () => {
    test('blocks an authenticated single logout not initiated via wsignout1.0', async () => {
        // the <img src="…/saml2/logout"> case — this is the one worth guarding,
        // because it would end the user's session at the IdP
        const app = buildApp({ authenticated: true });
        const res = await request(app).get('/saml2/logout');
        expect(res.status).toBe(403);
    });

    test('propagates to the IdP when reached through the wsignout1.0 entry point', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const agent = request.agent(app);

        const entry = await agent.get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(entry.status).toBe(302);
        expect(entry.headers.location).toMatch(/^\/saml2\/logout\?state=[0-9a-f]{32}$/);

        const res = await agent.get(entry.headers.location);
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://idp.example.com/logout');
        const [logoutReq] = passport._strategy().logout.mock.calls[0];
        expect(logoutReq.user).toEqual({ nameID: 'u@corp', nameIDFormat: 'fmt', sessionIndex: 'idx-1' });
        expect(logoutReq.query.RelayState).toMatch(/^[0-9a-f]{32}$/);
    });

    test('the state works one time only', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const entry = await request(app).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        await request(app).get(entry.headers.location);
        const again = await request(app).get(entry.headers.location);
        expect(again.status).toBe(400);
        expect(passport._strategy().logout).toHaveBeenCalledTimes(1);
    });

    test('an unknown or expired state fails closed instead of reporting a sign-out', async () => {
        const res = await request(buildApp()).get('/saml2/logout').query({ state: 'f'.repeat(32) });
        expect(res.status).toBe(400);
        expect(res.text).toContain('Sign-out not complete');
        expect(res.text).not.toMatch(/Signed out/);
        expect(res.headers['cache-control']).toBe('no-store');
    });

    test('a confirmation token or RelayState is not accepted as state', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const page = await request(app).get('/wsfed').query({ wa: 'wsignout1.0' });
        const confirm = /confirm=([0-9a-f]{32})/.exec(page.text)[1];
        expect((await request(app).get('/saml2/logout').query({ state: confirm })).status).toBe(400);

        const entry = await request(app).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        await request(app).get(entry.headers.location);
        const relayState = passport._strategy().logout.mock.calls[0][0].query.RelayState;
        expect((await request(app).get('/saml2/logout').query({ state: relayState })).status).toBe(400);
    });

    test('the sign-out record is cleared only when the state is used', async () => {
        const record = ssoRecord.addRealm(null, SAML_USER, 'https://elsewhere.tld/', 3600);
        const cookie = `wsfed_sso=${ssoRecord.seal(record, 'test-secret')}`;
        const app = buildApp();
        const entry = await request(app).get('/wsfed').set('Cookie', cookie).set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(String(entry.headers['set-cookie'])).not.toMatch(/wsfed_sso=;/);
        const res = await request(app).get(entry.headers.location).set('Cookie', cookie);
        expect(String(res.headers['set-cookie'])).toMatch(/wsfed_sso=;/);
    });

    test('reaches the IdP from the sign-out record when the session is already gone', async () => {
        // the normal OWA case: the session ended when the token was issued
        const record = ssoRecord.addRealm(null, SAML_USER, 'https://elsewhere.tld/', 3600);
        const cookie = `wsfed_sso=${ssoRecord.seal(record, 'test-secret')}`;
        const app = buildApp();
        const entry = await request(app).get('/wsfed').set('Cookie', cookie).set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        // the only realm is not on the allowlist, so there is no cleanup page
        expect(entry.status).toBe(302);
        const res = await request(app).get(entry.headers.location);
        expect(res.headers.location).toBe('https://idp.example.com/logout');
        expect(passport._strategy().logout.mock.calls[0][0].user.sessionIndex).toBe('idx-1');
    });

    test('does not error when already signed out', async () => {
        // the proxy destroys its session as soon as the token is issued, so the
        // real sign-out arrives unauthenticated; it must not 403 or 400
        const app = buildApp();
        const res = await request(app).get('/saml2/logout');
        expect(res.status).toBe(200);
        expect(res.text).toMatch(/signed out/i);
    });

    test('is repeatable once signed out', async () => {
        const app = buildApp();
        const agent = request.agent(app);
        await agent.get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect((await agent.get('/saml2/logout')).status).toBe(200);
        expect((await agent.get('/saml2/logout')).status).toBe(200);
    });

    test('redirects to INVALID_LOGIN_REDIRECT when configured', async () => {
        const app = buildApp({ INVALID_LOGIN_REDIRECT: 'https://sso.corp/bye' });
        const res = await request(app).get('/saml2/logout');
        expect(res.status).toBe(303);
        expect(res.headers.location).toBe('https://sso.corp/bye');
    });
});

describe('sign-out wreply (WS-Federation 1.2 §13.2.4.1)', () => {
    const WREPLY = 'https://exchange.corp/owa/';

    test('refuses a wreply outside the allowlist at the start', async () => {
        const res = await request(buildApp()).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0', wreply: 'https://attacker.tld/' });
        expect(res.status).toBe(403);
    });

    test('without a SAML identity, goes to wreply after the local sign-out', async () => {
        const app = buildApp();
        const entry = await request(app).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0', wreply: WREPLY });
        const res = await request(app).get(entry.headers.location);
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe(WREPLY);
    });

    test('with a SAML identity, goes to wreply after the IdP LogoutResponse', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const entry = await request(app).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0', wreply: WREPLY });
        await request(app).get(entry.headers.location);
        const relayState = passport._strategy().logout.mock.calls[0][0].query.RelayState;

        const res = await request(app).get('/saml2/logout/callback')
            .query({ SAMLResponse: 'x', Signature: 'y', RelayState: relayState });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe(WREPLY);
    });

    test('an unknown RelayState ends without a redirect to any wreply', async () => {
        const res = await request(buildApp()).get('/saml2/logout/callback')
            .query({ SAMLResponse: 'x', Signature: 'y', RelayState: 'f'.repeat(32) });
        expect(res.status).toBe(200);
        expect(res.text).toMatch(/signed out/i);
    });
});

describe('/saml2/logout/callback', () => {
    test('GET refuses a LogoutResponse without Signature', async () => {
        const res = await request(buildApp()).get('/saml2/logout/callback').query({ SAMLResponse: 'x' });
        expect(res.status).toBe(400);
    });

    test('POST refuses a body without SAMLResponse', async () => {
        const res = await request(buildApp()).post('/saml2/logout/callback').type('form').send({ RelayState: 'x' });
        expect(res.status).toBe(400);
    });

    test('a message the strategy refuses gives 400', async () => {
        const res = await request(buildApp()).get('/saml2/logout/callback')
            .query({ SAMLResponse: 'x', Signature: 'y', reject: '1' });
        expect(res.status).toBe(400);
    });
});

describe('GET /saml2/callback (dead route removed)', () => {
    test('GET /saml2/callback no longer exists (returns 404)', async () => {
        const app = buildApp();
        const res = await request(app).get('/saml2/callback');
        expect(res.status).toBe(404);
    });
});
