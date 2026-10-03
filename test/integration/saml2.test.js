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
        _strategy: jest.fn(() => ({ logout, _saml: mockIdpLogout })),
    };
});
// The IdP LogoutRequest that the stubbed 'saml-logout' strategy reports as valid
const mockIdpLogout = {
    profile: { nameID: 'u@corp', sessionIndex: 'idx-1' },
    validatePostRequestAsync: jest.fn(async () => ({ loggedOut: true, profile: mockIdpLogout.profile })),
    getLogoutResponseUrlAsync: jest.fn(async () => 'https://idp.example.com/saml?SAMLResponse=r'),
};

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

    test('a RelayState is not accepted as state', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const entry = await request(app).get('/wsfed').set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        await request(app).get(entry.headers.location);
        const relayState = passport._strategy().logout.mock.calls[0][0].query.RelayState;
        expect((await request(app).get('/saml2/logout').query({ state: relayState })).status).toBe(400);
    });

    test('the sign-out record is cleared only when the state is used', async () => {
        const record = ssoRecord.addRealm(null, SAML_USER, 'https://elsewhere.tld/', 3600);
        const cookie = `__Host-wsfed_sso=${ssoRecord.seal(record, 'test-secret')}`;
        const app = buildApp();
        const entry = await request(app).get('/wsfed').set('Cookie', cookie).set('Referer', 'https://exchange.corp/owa/').query({ wa: 'wsignout1.0' });
        expect(String(entry.headers['set-cookie'])).not.toMatch(/__Host-wsfed_sso=;/);
        const res = await request(app).get(entry.headers.location).set('Cookie', cookie);
        expect(String(res.headers['set-cookie'])).toMatch(/__Host-wsfed_sso=;/);
    });

    test('reaches the IdP from the sign-out record when the session is already gone', async () => {
        // the normal OWA case: the session ended when the token was issued
        const record = ssoRecord.addRealm(null, SAML_USER, 'https://elsewhere.tld/', 3600);
        const cookie = `__Host-wsfed_sso=${ssoRecord.seal(record, 'test-secret')}`;
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

    test('without wreply ends on a "signed out" page like AD FS, even when INVALID_LOGIN_REDIRECT is set', async () => {
        const app = buildApp({ INVALID_LOGIN_REDIRECT: 'https://sso.corp/bye' });
        const res = await request(app).get('/saml2/logout');
        expect(res.status).toBe(200);
        expect(res.headers.location).toBeUndefined();
        expect(res.headers['content-type']).toMatch(/^text\/html/);
        expect(res.text).toContain('<title>Sign out</title>');
        expect(res.text).toContain('You have successfully signed out.');
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
        // no IdP step: straight to the checked wreply
        expect(entry.status).toBe(302);
        expect(entry.headers.location).toBe(WREPLY);
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

describe('POST /saml2/logout/callback — which local session an IdP LogoutRequest ends', () => {
    const record = (user) => `${ssoRecord.COOKIE_NAME}=${ssoRecord.seal(
        ssoRecord.addRealm(null, user, 'https://exchange.corp/owa/', 3600), 'test-secret')}`;
    const send = (app, cookie) => {
        const r = request(app).post('/saml2/logout/callback').type('form');
        return (cookie ? r.set('Cookie', cookie) : r).send({ SAMLRequest: 'x' });
    };
    const clearsRecord = (res) => new RegExp(`${ssoRecord.COOKIE_NAME}=;`).test(String(res.headers['set-cookie']));

    afterEach(() => { mockIdpLogout.profile = { nameID: 'u@corp', sessionIndex: 'idx-1' }; });

    test('the signed-in user wins over an old record of another user', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const res = await send(app, record({ nameID: 'old@corp', sessionIndex: 'idx-9' }));
        expect(res.status).toBe(200);
        expect(res.text).toContain('wsignoutcleanup1.0');
        expect(clearsRecord(res)).toBe(true);
    });

    test('another SessionIndex of the same user changes nothing locally', async () => {
        mockIdpLogout.profile = { nameID: 'u@corp', sessionIndex: 'idx-OLD' };
        const res = await send(buildApp(), record({ nameID: 'u@corp', sessionIndex: 'idx-1' }));
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://idp.example.com/saml?SAMLResponse=r');
        expect(clearsRecord(res)).toBe(false);
    });

    test('a LogoutRequest without SessionIndex ends every session of the user', async () => {
        mockIdpLogout.profile = { nameID: 'u@corp' };
        const res = await send(buildApp(), record({ nameID: 'u@corp', sessionIndex: 'idx-1' }));
        expect(res.status).toBe(200);
        expect(clearsRecord(res)).toBe(true);
    });
});

describe('SAML2_SLO=false', () => {
    const { pendingLogout } = require('../../util/pendingLogout');

    test('wsignout1.0 ends the local and RP sessions, but sends no LogoutRequest', async () => {
        const put = jest.spyOn(pendingLogout, 'put');
        const app = buildApp({ SAML2_SLO: false, authenticated: true, user: SAML_USER });
        const cookie = `${ssoRecord.COOKIE_NAME}=${ssoRecord.seal(
            ssoRecord.addRealm(null, SAML_USER, 'https://exchange.corp/owa/', 3600), 'test-secret')}`;
        const res = await request(app).get('/wsfed').set('Cookie', cookie).query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(200);
        expect(res.text).toContain('src="https://exchange.corp/owa/?wa=wsignoutcleanup1.0"');
        expect(res.text).toContain('data-next="/saml2/logout"');
        expect(String(res.headers['set-cookie'])).toMatch(new RegExp(`${ssoRecord.COOKIE_NAME}=;`));
        expect(put).not.toHaveBeenCalled();
        put.mockRestore();
    });

    test('with wreply, ends at the checked wreply', async () => {
        const app = buildApp({ SAML2_SLO: false, authenticated: true, user: SAML_USER });
        const res = await request(app).get('/wsfed').query({ wa: 'wsignout1.0', wreply: 'HTTPS://EXCHANGE.corp/owa/' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://exchange.corp/owa/');
        expect(passport._strategy().logout).not.toHaveBeenCalled();
    });

    test.each(['get', 'post'])('%s /saml2/logout/callback returns 404', async (method) => {
        mockIdpLogout.validatePostRequestAsync.mockClear();
        const res = await request(buildApp({ SAML2_SLO: false }))[method]('/saml2/logout/callback')
            .query({ SAMLRequest: 'x', Signature: 'y' });
        expect(res.status).toBe(404);
        expect(mockIdpLogout.validatePostRequestAsync).not.toHaveBeenCalled();
    });
});

describe('sign-out without a SAML identity', () => {
    test('adds nothing to the pending-logout store', async () => {
        const { pendingLogout } = require('../../util/pendingLogout');
        const put = jest.spyOn(pendingLogout, 'put');
        const res = await request(buildApp()).get('/wsfed').query({ wa: 'wsignout1.0' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('/saml2/logout');
        expect(put).not.toHaveBeenCalled();
        put.mockRestore();
    });
});

describe('sign-out wreply after the IdP step', () => {
    test('redirects to the parsed URL that was checked, not the raw string', async () => {
        const app = buildApp({ authenticated: true, user: SAML_USER });
        const entry = await request(app).get('/wsfed').query({ wa: 'wsignout1.0', wreply: 'HTTPS://EXCHANGE.corp/owa/' });
        await request(app).get(entry.headers.location);
        const relayState = passport._strategy().logout.mock.calls[0][0].query.RelayState;
        const res = await request(app).get('/saml2/logout/callback')
            .query({ SAMLResponse: 'x', Signature: 'y', RelayState: relayState });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('https://exchange.corp/owa/');
    });
});
