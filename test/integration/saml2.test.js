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
    const { MAX_PENDING_SIGNINS } = require('../../util/samlLogin');
    const REALM = 'https://exchange.corp';

    // starts a sign-in through wsignin1.0 and returns the RelayState that went to the IdP
    async function startSignIn(agent, wtrealm = REALM) {
        let sent;
        passport.authenticate.mockImplementationOnce((strategy, opts) => (req, res) => {
            sent = opts.additionalParams.RelayState;
            res.redirect('https://idp.example.com/saml');
        });
        await agent.get('/wsfed').query({ wa: 'wsignin1.0', wtrealm });
        return sent;
    }
    // the stubbed strategy accepts the response; report which wsfed_args the session then holds
    function acceptResponse() {
        passport.authenticate.mockImplementationOnce(() => (req, res) => res.json({ args: req.session.wsfed_args || null }));
    }

    beforeEach(() => passport.authenticate.mockClear());

    test('each sign-in sends a fresh 256-bit RelayState', async () => {
        const first = await startSignIn(request.agent(buildApp()));
        const second = await startSignIn(request.agent(buildApp()));
        expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(second).not.toBe(first);
    });

    test('a response with the matching RelayState reaches passport and is not refused', async () => {
        const agent = request.agent(buildApp());
        const sent = await startSignIn(agent);
        acceptResponse();
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        expect(res.status).toBe(200);
        expect(res.body.args.wtrealm).toBe(REALM);
    });

    test.each([
        ['missing', {}],
        ['wrong', { RelayState: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
        ['repeated', { RelayState: ['x', 'y'] }],
    ])('a response with a %s RelayState is refused', async (_label, fields) => {
        const agent = request.agent(buildApp());
        await startSignIn(agent);
        passport.authenticate.mockClear();
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', ...fields });
        expect(res.status).toBe(403);
        expect(passport.authenticate).not.toHaveBeenCalled();
    });

    test('a response without any sign-in of this session is refused (login CSRF)', async () => {
        const res = await request(buildApp()).post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: 'y' });
        expect(res.status).toBe(403);
        expect(passport.authenticate).not.toHaveBeenCalled();
    });

    test('a refused response leaves the pending sign-in usable', async () => {
        const agent = request.agent(buildApp());
        const sent = await startSignIn(agent);
        await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: 'wrong' });
        acceptResponse();
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        expect(res.status).toBe(200);
    });

    test('each RelayState works one time only', async () => {
        const agent = request.agent(buildApp());
        const sent = await startSignIn(agent);
        acceptResponse();
        await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        const res = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent });
        expect(res.status).toBe(403);
    });

    test('two tabs: each response gets the wtrealm of its own sign-in', async () => {
        const agent = request.agent(buildApp({ WSFED_ALLOWED_REALMS: 'https://exchange.corp,https://other.corp' }));
        const tabA = await startSignIn(agent, 'https://exchange.corp/owa/');
        const tabB = await startSignIn(agent, 'https://other.corp/ecp/');
        acceptResponse();
        const resA = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: tabA });
        acceptResponse();
        const resB = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: tabB });
        expect(resA.body.args.wtrealm).toBe('https://exchange.corp/owa/');
        expect(resB.body.args.wtrealm).toBe('https://other.corp/ecp/');
    });

    test(`only the newest ${MAX_PENDING_SIGNINS} pending sign-ins are kept`, async () => {
        const agent = request.agent(buildApp());
        const sent = [];
        for (let i = 0; i <= MAX_PENDING_SIGNINS; i++) sent.push(await startSignIn(agent));
        const oldest = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent[0] });
        expect(oldest.status).toBe(403);
        acceptResponse();
        const newest = await agent.post('/saml2/callback').type('form').send({ SAMLResponse: 'x', RelayState: sent[MAX_PENDING_SIGNINS] });
        expect(newest.status).toBe(200);
    });

    test('an IdP LogoutRequest (SAMLRequest) is not checked against a sign-in', async () => {
        await request(buildApp()).post('/saml2/callback').type('form').send({ SAMLRequest: 'x' });
        expect(passport.authenticate).toHaveBeenCalledTimes(1);
        expect(passport.authenticate.mock.calls[0][0]).toBe('saml');
    });
});

