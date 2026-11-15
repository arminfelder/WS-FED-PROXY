/**
 * Browser tests against the lab: a real Exchange 2016 OWA, this proxy behind nginx, and Keycloak.
 * run.sh sets the environment. Each test starts with a new browser context, thus without cookies.
 *
 * Sign-in:   OWA -> proxy /wsfed?wa=wsignin1.0 -> Keycloak -> POST proxy /saml2/callback
 *            -> proxy /wsfed (token page) -> POST OWA
 * Sign-out:  OWA logoff -> proxy /wsfed?wa=wsignout1.0 -> OWA wsignoutcleanup1.0
 *            -> proxy /wsfed/signout/continue -> proxy /saml2/logout -> Keycloak
 *            -> POST proxy /saml2/logout/callback
 */

const { test, expect } = require('@playwright/test');

function env(name) {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is not set; start the tests with e2e/live/run.sh`);
    return value;
}

const OWA = env('E2E_OWA');
const PROXY = env('E2E_PROXY').replace(/\/$/, '');
const KC = env('E2E_KC').replace(/\/$/, '');
// Keycloak 16 (WildFly) has the /auth prefix and the realm master. Keycloak 26 in e2e/kc26 has the realm lab.
const KC_REALM = (process.env.E2E_KC_REALM || `${KC}/auth/realms/master`).replace(/\/$/, '');
// account: the sign-out button of the Keycloak 16 account console. endsession: the OIDC logout page, for Keycloak 26.
const KC_LOGOUT = process.env.E2E_KC_LOGOUT || 'account';
const USER = env('E2E_USER');
const PASSWORD = env('E2E_PW');

const OWA_ORIGIN = new URL(OWA).origin;
const SESSION_COOKIE = '__Host-sid';
const RECORD_COOKIE = '__Host-wsfed_sso';

/** Records each main-frame navigation as "METHOD url", and each answer as {method, url, status}. */
function track(page) {
    const requests = [];
    const responses = [];
    page.on('request', (req) => {
        if (req.isNavigationRequest() && req.frame() === page.mainFrame()) requests.push(`${req.method()} ${req.url()}`);
    });
    page.on('response', (res) => {
        const req = res.request();
        if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
            responses.push({ method: req.method(), url: res.url(), status: res.status() });
        }
    });
    return {
        requests,
        responses,
        chain: () => requests.join('\n'),
        answersOf: (method, urlPart) => responses.filter((r) => r.method === method && r.url.includes(urlPart)),
    };
}

const onKeycloak = (page) => page.url().startsWith(KC);

async function expectKeycloakLogin(page, message) {
    await expect(page, message).toHaveURL((url) => url.toString().startsWith(KC), { timeout: 90_000 });
    await expect(page.locator('#password'), message).toBeVisible();
}

async function logInAtKeycloak(page) {
    await expectKeycloakLogin(page, 'expected the Keycloak login page');
    // For a new authentication of a known user, Keycloak 26 shows only the password field.
    const username = page.locator('#username');
    if (await username.isVisible()) await username.fill(USER);
    await page.locator('#password').fill(PASSWORD);
    await Promise.all([
        // "commit", not "load": the token page posts itself to OWA at once, and its load event never fires.
        page.waitForURL((url) => !url.toString().startsWith(KC), { timeout: 120_000, waitUntil: 'commit' }),
        page.locator('#kc-login').click(),
    ]);
}

/**
 * OWA 2016 gives a loaded mailbox the title "<Folder> - Outlook". The error page and the
 * language page have the title "Outlook" only. OWA loads slowly, so poll.
 */
async function mailboxIsOpen(page, timeoutMs = 120_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (page.url().startsWith(OWA_ORIGIN)) {
            const title = await page.title().catch(() => '');
            if (/\S\s*-\s*Outlook\s*$/.test(title)) return true;
        }
        await page.waitForTimeout(2000);
    }
    return false;
}

async function signInToOwa(page) {
    await page.goto(OWA, { waitUntil: 'domcontentloaded' });
    await logInAtKeycloak(page);
    expect(await mailboxIsOpen(page), `expected a mailbox, the browser is on ${page.url()} ("${await page.title()}")`).toBe(true);
}

async function proxyCookies(context) {
    const cookies = await context.cookies(PROXY);
    return Object.fromEntries(cookies.map((c) => [c.name, c]));
}

// Exchange permits a limited number of open sessions for one mailbox (about 32). Each sign-in opens one,
// and OWA keeps it for minutes. Without this, a few runs end in "too many active sessions".
// The redirect to the proxy is not followed: only the OWA session must end here.
async function endOwaSession(context) {
    const cookies = await context.cookies(OWA);
    if (!cookies.some((cookie) => cookie.name.startsWith('FedAuth'))) return;
    await context.request.get(`${OWA.replace(/\/$/, '')}/logoff.owa`, { maxRedirects: 0 }).catch(() => {});
}

test.afterEach(async ({ context }) => {
    await endOwaSession(context);
});

test.describe('proxy endpoints', () => {
    test('metadata, error pages and the realm allowlist answer as configured', async ({ request }) => {
        const metadata = await request.get(`${PROXY}/FederationMetadata/2007-06/FederationMetadata.xml`);
        expect(metadata.status()).toBe(200);
        expect(await metadata.text()).toContain('EntityDescriptor');

        const notFound = await request.get(`${PROXY}/nope`);
        expect(notFound.status()).toBe(404);
        expect(await notFound.text(), 'the styled error page, not the Express default').toContain('font-family');

        const foreignRealm = await request.get(`${PROXY}/wsfed?wa=wsignin1.0&wtrealm=${encodeURIComponent('https://attacker.example/owa/')}`, { maxRedirects: 0 });
        expect(foreignRealm.status()).toBe(403);
    });

    test('a logout query that can be read in two ways is refused', async ({ request }) => {
        const res = await request.get(`${PROXY}/saml2/logout/callback?SAMLReques%74=x&SAMLResponse=y&SigAlg=z&Signature=s`, { maxRedirects: 0 });
        expect(res.status()).toBe(400);
    });
});

test.describe('sign-in', () => {
    test('a visit to OWA without a session ends in the mailbox', async ({ page, context }) => {
        const nav = track(page);
        await signInToOwa(page);

        expect(nav.chain(), 'OWA must start the sign-in at the proxy').toContain(`GET ${PROXY}/wsfed?wa=wsignin1.0`);
        expect(nav.chain(), 'the proxy must send the AuthnRequest to Keycloak').toMatch(new RegExp(`GET ${KC.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^\\n]*SAMLRequest=`));
        const callback = nav.answersOf('POST', `${PROXY}/saml2/callback`);
        expect(callback.map((r) => r.status), 'Keycloak posts the response; the proxy accepts it').toEqual([302]);
        const token = nav.answersOf('GET', `${PROXY}/wsfed`).filter((r) => !r.url.includes('wa='));
        expect(token.map((r) => r.status), 'the token page').toEqual([200]);

        const cookies = await proxyCookies(context);
        expect(cookies[SESSION_COOKIE], 'the proxy session ends when the token is issued').toBeUndefined();
        expect(cookies[RECORD_COOKIE], 'the sign-out record stays for a later sign-out').toBeDefined();
        expect(cookies[RECORD_COOKIE].httpOnly).toBe(true);
        expect(cookies[RECORD_COOKIE].secure).toBe(true);
    });

    test('after the token, the proxy gives no second token', async ({ page }) => {
        await signInToOwa(page);
        const res = await page.request.get(`${PROXY}/wsfed`, { maxRedirects: 0 });
        // 400, or 303 when INVALID_LOGIN_REDIRECT is set (docker-compose.yaml sets it)
        expect([400, 303]).toContain(res.status());
        expect(await res.text(), 'no token in the answer').not.toContain('wresult');
    });

    test('two tabs: the second sign-in completes after the first got its token', async ({ context }) => {
        const first = await context.newPage();
        const second = await context.newPage();
        const secondNav = track(second);

        await first.goto(OWA, { waitUntil: 'domcontentloaded' });
        await expectKeycloakLogin(first, 'tab 1 waits at Keycloak');
        await second.goto(OWA, { waitUntil: 'domcontentloaded' });
        await expectKeycloakLogin(second, 'tab 2 waits at Keycloak');
        const secondAuthnRequest = secondNav.requests.map((r) => r.slice(4)).find((url) => url.startsWith(KC) && url.includes('SAMLRequest='));
        expect(secondAuthnRequest, 'the AuthnRequest URL of tab 2').toBeDefined();

        await logInAtKeycloak(first);
        expect(await mailboxIsOpen(first), 'tab 1 must reach the mailbox').toBe(true);

        // Keycloak now has a session, so it answers the AuthnRequest of tab 2 without a prompt.
        // The login page of Keycloak 26 sees the login of the other tab and continues by itself.
        // Keycloak 16 does not, so there the test sends the AuthnRequest of tab 2 again.
        // Not both: a second answer has a RelayState that was used, and the proxy refuses it.
        const callback = () => secondNav.answersOf('POST', `${PROXY}/saml2/callback`).map((r) => r.status);
        const leftLoginPage = await second.waitForURL((url) => !url.toString().startsWith(KC), { timeout: 10_000, waitUntil: 'commit' })
            .then(() => true, () => false);
        if (!leftLoginPage) await second.goto(secondAuthnRequest, { waitUntil: 'commit' });
        await expect.poll(callback, { timeout: 60_000, message: `Keycloak must post the response of tab 2; chain:\n${secondNav.chain()}` }).not.toEqual([]);
        expect(callback(), 'the callback of tab 2 must not be refused').toEqual([302]);
        expect(await mailboxIsOpen(second), `tab 2 must reach the mailbox, it is on ${second.url()}`).toBe(true);
    });
});

test.describe('sign-out', () => {
    test('sign-out in OWA ends the OWA session and the Keycloak session', async ({ page }) => {
        await signInToOwa(page);

        const nav = track(page);
        await page.goto(`${OWA.replace(/\/$/, '')}/logoff.owa`, { waitUntil: 'domcontentloaded' });
        await expect.poll(() => nav.answersOf('POST', `${PROXY}/saml2/logout/callback`).length + nav.answersOf('GET', `${PROXY}/saml2/logout/callback`).length,
            { timeout: 90_000, message: `Keycloak must answer the LogoutRequest at the proxy; chain:\n${nav.chain()}` }).toBeGreaterThan(0);

        const chain = nav.chain();
        expect(chain, 'OWA starts at wsignout1.0').toContain(`GET ${PROXY}/wsfed?wa=wsignout1.0`);
        expect(chain, 'the proxy sends the browser to the OWA cleanup').toMatch(new RegExp(`GET ${OWA_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^\\n]*wa=wsignoutcleanup1\\.0`));
        expect(chain, 'OWA sends the browser back to the proxy').toContain(`GET ${PROXY}/wsfed/signout/continue?c=`);
        expect(chain, 'the proxy uses the one-time state').toContain(`GET ${PROXY}/saml2/logout?state=`);
        expect(chain, 'the LogoutRequest goes to Keycloak').toMatch(/SAMLRequest=/);

        const answers = [...nav.answersOf('POST', `${PROXY}/saml2/logout/callback`), ...nav.answersOf('GET', `${PROXY}/saml2/logout/callback`)];
        expect(answers.map((r) => r.status).every((status) => status === 200 || status === 302),
            `the proxy must accept the LogoutResponse of Keycloak, got ${JSON.stringify(answers)}`).toBe(true);

        // Both sessions are gone: OWA sends the browser to the proxy, and Keycloak asks for the password.
        await page.goto(OWA, { waitUntil: 'domcontentloaded' });
        await expectKeycloakLogin(page, 'after the sign-out, OWA must need a new login at Keycloak');
    });

    test('sign-in works again after a sign-out', async ({ page }) => {
        await signInToOwa(page);
        const nav = track(page);
        await page.goto(`${OWA.replace(/\/$/, '')}/logoff.owa`, { waitUntil: 'domcontentloaded' });
        await expect.poll(() => nav.responses.filter((r) => r.url.includes(`${PROXY}/saml2/logout/callback`)).length, { timeout: 90_000 }).toBeGreaterThan(0);
        await signInToOwa(page);
    });

    test('sign-out at Keycloak ends the OWA session', async ({ page }) => {
        await signInToOwa(page);

        const nav = track(page);
        let signOut;
        if (KC_LOGOUT === 'endsession') {
            await page.goto(`${KC_REALM}/protocol/openid-connect/logout`, { waitUntil: 'domcontentloaded' });
            signOut = page.locator('#kc-logout');
        } else {
            await page.goto(`${KC_REALM}/account/`, { waitUntil: 'domcontentloaded' });
            // Keycloak 16 has two sign-out buttons in the page. Only one of them is visible for a given width.
            signOut = page.locator('#landingSignOutButton:visible, #signOutButton:visible').first();
        }
        await expect(signOut, 'the sign-out control of Keycloak').toBeVisible({ timeout: 60_000 });
        await signOut.click();

        await expect.poll(() => nav.answersOf('POST', `${PROXY}/saml2/logout/callback`).length + nav.answersOf('GET', `${PROXY}/saml2/logout/callback`).length,
            { timeout: 90_000, message: `Keycloak must send its LogoutRequest to the proxy; chain:\n${nav.chain()}` }).toBeGreaterThan(0);
        await expect.poll(() => nav.chain(), { timeout: 90_000, message: 'the proxy must send the browser to the OWA cleanup' })
            .toContain('wa=wsignoutcleanup1.0');
        await expect.poll(() => nav.chain(), { timeout: 90_000, message: 'the proxy must answer Keycloak with a LogoutResponse' })
            .toMatch(/SAMLResponse=/);

        await page.goto(OWA, { waitUntil: 'domcontentloaded' });
        await expectKeycloakLogin(page, 'after the sign-out at Keycloak, OWA must need a new login');
        expect(onKeycloak(page)).toBe(true);
    });
});

// wfresh (WS-Federation 1.2 §13.2.2): the maximum age of the authentication, in minutes. OWA does not
// send it, so these tests start the sign-in at the proxy, with the wtrealm and the wctx that OWA sends.
test.describe('wfresh', () => {
    const zlib = require('zlib');
    const signInUrl = (extra = '') => `${PROXY}/wsfed?wa=wsignin1.0&wtrealm=${encodeURIComponent(OWA)}` +
        `&wctx=${encodeURIComponent('rm=0&id=passive&ru=%2fowa%2f')}${extra}`;

    /** The AuthnRequests that the browser took to Keycloak, as XML. */
    function authnRequests(nav) {
        return nav.requests
            .map((entry) => entry.slice(entry.indexOf(' ') + 1))
            .filter((url) => url.startsWith(KC) && url.includes('SAMLRequest='))
            .map((url) => zlib.inflateRawSync(Buffer.from(new URL(url).searchParams.get('SAMLRequest'), 'base64')).toString());
    }

    /** The tokens (wresult) that the browser posts to OWA. */
    function trackTokens(page) {
        const tokens = [];
        page.on('request', (req) => {
            if (req.method() !== 'POST' || !req.url().startsWith(OWA_ORIGIN)) return;
            const wresult = new URLSearchParams(req.postData() || '').get('wresult');
            if (wresult) tokens.push(wresult);
        });
        return tokens;
    }

    function lifetimeSeconds(wresult) {
        const notBefore = /NotBefore="([^"]+)"/.exec(wresult)[1];
        const notOnOrAfter = /NotOnOrAfter="([^"]+)"/.exec(wresult)[1];
        return (Date.parse(notOnOrAfter) - Date.parse(notBefore)) / 1000;
    }

    // First in this group: its wait also keeps the run below the request limit of the proxy.
    test('wfresh=1 with a login that is older than one minute: one new prompt, then the token', async ({ page }) => {
        // Keycloak 16.1.0 and 26.6.4 write the time of the assertion into AuthnInstant, not the time of the
        // login (seen 2026-11-15: the same SessionIndex, an AuthnInstant 71 s later). The proxy then cannot
        // see that the login is old. If this test passes, the IdP reports the login time, and this line can go.
        test.fail(true, 'Keycloak 16.1.0 and 26.6.4: AuthnInstant is the time of the assertion, so a wfresh above 0 has no effect');

        await signInToOwa(page);
        await page.waitForTimeout(70_000);

        const nav = track(page);
        await endOwaSession(page.context());
        await page.goto(signInUrl('&wfresh=1'), { waitUntil: 'commit' });
        await expect(page.locator('#password'), 'the login is too old for wfresh=1, so Keycloak must ask again').toBeVisible({ timeout: 20_000 });
        const requests = authnRequests(nav);
        expect(requests.length, 'a normal AuthnRequest, then one with ForceAuthn').toBe(2);
        expect(requests[0]).not.toContain('ForceAuthn="true"');
        expect(requests[1]).toContain('ForceAuthn="true"');

        await logInAtKeycloak(page);
        expect(await mailboxIsOpen(page), `expected a mailbox, the browser is on ${page.url()}`).toBe(true);
    });

    test('wfresh=0 asks for the password again, although Keycloak has a session', async ({ page }) => {
        await signInToOwa(page);

        const nav = track(page);
        await endOwaSession(page.context());
        await page.goto(signInUrl('&wfresh=0'), { waitUntil: 'commit' });
        await expectKeycloakLogin(page, 'wfresh=0 must give a login prompt');
        const requests = authnRequests(nav);
        expect(requests.length).toBe(1);
        expect(requests[0]).toContain('ForceAuthn="true"');

        await logInAtKeycloak(page);
        expect(await mailboxIsOpen(page), `expected a mailbox, the browser is on ${page.url()}`).toBe(true);
    });

    test('a wfresh that the login satisfies gives no prompt, and limits the token lifetime', async ({ page }) => {
        const tokens = trackTokens(page);
        await signInToOwa(page);
        expect(tokens.length).toBe(1);
        const normal = lifetimeSeconds(tokens[0]);
        expect(normal, 'without wfresh: WSFED_TOKEN_LIFETIME, 600 s by default').toBeGreaterThan(120);
        expect(normal).toBeLessThanOrEqual(3600);

        const nav = track(page);
        await endOwaSession(page.context());
        await page.goto(signInUrl('&wfresh=2'), { waitUntil: 'commit' });
        await expect.poll(() => tokens.length, { timeout: 60_000, message: `a second token must go to OWA; chain:\n${nav.chain()}` }).toBe(2);
        expect(nav.chain(), 'no login form: the session is fresh').not.toContain('login-actions/authenticate');
        const limited = lifetimeSeconds(tokens[1]);
        expect(limited, 'the token must not live longer than wfresh=2 minutes').toBeLessThanOrEqual(120);
        expect(limited).toBeGreaterThan(0);
        expect(await mailboxIsOpen(page), `expected a mailbox, the browser is on ${page.url()}`).toBe(true);
    });

    test('a wfresh that is not a number of minutes is refused', async ({ request }) => {
        for (const value of ['abc', '-1', '1.5', '525601']) {
            const res = await request.get(signInUrl(`&wfresh=${value}`), { maxRedirects: 0 });
            expect(res.status(), `wfresh=${value}`).toBe(400);
        }
    });
});
