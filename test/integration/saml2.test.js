const request = require('supertest');

// passport.authenticate is a heavy dependency; stub it so tests don't need a
// real SAML IDP or certificate files.
jest.mock('passport', () => {
    const original = jest.requireActual('passport');
    return {
        ...original,
        authenticate: jest.fn((strategy, opts) => (req, res, next) => {
            // Simulate failure by redirecting to failureRedirect
            if (opts && opts.failureRedirect) {
                return res.redirect(opts.failureRedirect);
            }
            next();
        }),
        _strategy: jest.fn(() => ({
            logout: (req, cb) => cb(null, 'https://idp.example.com/logout'),
        })),
    };
});

const buildApp = require('./helpers/buildApp');

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
        const app = buildApp({ authenticated: true });
        const agent = request.agent(app);

        const entry = await agent.get('/wsfed').query({ wa: 'wsignout1.0' });
        expect(entry.status).toBe(302);
        expect(entry.headers.location).toMatch('/saml2/logout');

        const res = await agent.get('/saml2/logout');
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://idp.example.com/logout');
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
        await agent.get('/wsfed').query({ wa: 'wsignout1.0' });
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

describe('GET /saml2/callback (dead route removed)', () => {
    test('GET /saml2/callback no longer exists (returns 404)', async () => {
        const app = buildApp();
        const res = await request(app).get('/saml2/callback');
        expect(res.status).toBe(404);
    });
});

describe('RelayState binds the SAML response to the sign-in session', () => {
    const passport = require('passport');
    const REALM = 'https://exchange.corp';

    // mints the session nonce through /login and returns it together with the one sent to the IdP
    async function startSignIn(agent) {
        await agent.get('/wsfed').query({ wa: 'wsignin1.0', wtrealm: REALM });
        passport.authenticate.mockImplementationOnce((strategy, opts) => (req, res) => {
            res.json({ session: req.session.saml_relay, sent: opts.additionalParams.RelayState });
        });
        const res = await agent.get('/saml2/login');
        return res.body;
    }

    beforeEach(() => passport.authenticate.mockClear());

    test('/login stores a fresh nonce in the session and sends the same value as RelayState', async () => {
        const first = await startSignIn(request.agent(buildApp()));
        expect(first.sent).toBe(first.session);
        expect(first.sent).toMatch(/^[A-Za-z0-9_-]{43}$/);
        const second = await startSignIn(request.agent(buildApp()));
        expect(second.sent).not.toBe(first.sent);
    });

    test('a response with the matching RelayState reaches passport', async () => {
        const agent = request.agent(buildApp());
        const { sent } = await startSignIn(agent);
        await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        const callbackCalls = passport.authenticate.mock.calls.filter((c) => c[2] !== undefined);
        expect(callbackCalls).toHaveLength(1);
        expect(callbackCalls[0][0]).toBe('saml');
    });

    test.each([
        ['missing', {}],
        ['wrong', { RelayState: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
        ['repeated', { RelayState: ['x', 'y'] }],
    ])('a response with a %s RelayState is refused while a sign-in is pending', async (_label, fields) => {
        const agent = request.agent(buildApp());
        await startSignIn(agent);
        passport.authenticate.mockClear();
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', ...fields });
        expect(res.status).toBe(403);
        expect(passport.authenticate).not.toHaveBeenCalled();
    });

    test('the nonce is single-use: a refused attempt burns it', async () => {
        const agent = request.agent(buildApp());
        const { sent } = await startSignIn(agent);
        await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: 'wrong' });
        passport.authenticate.mockClear();
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        expect(res.status).toBe(403);
        expect(passport.authenticate).not.toHaveBeenCalled();
    });

    test('without a pending sign-in the response passes through (IdP logout messages, stray responses)', async () => {
        await request(buildApp()).post('/saml2/callback').type('form').send({ SAMLResponse: 'x' });
        expect(passport.authenticate).toHaveBeenCalledTimes(1);
        expect(passport.authenticate.mock.calls[0][0]).toBe('saml');
    });
});
