/**
 * The complete sign-in against the real app.js and the real node-saml strategy:
 * wsignin1.0, an IdP response signed with the fixture key, then the WS-Fed token page.
 */

const request = require('supertest');
const zlib = require('zlib');
const crypto = require('crypto');

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

const { SignedXml } = require('xml-crypto');
const KEY = jest.requireActual('fs').readFileSync(require('path').join(__dirname, '../fixtures/test-cert.key'));
const IDP = 'https://idp.example.com/saml';
const ACS = 'https://proxy.example.com/saml2/callback';
// S-1-5-21-1-2-3-500 in the MS-DTYP 2.4.2.2 binary form
const SID = Buffer.from([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 244, 1, 0, 0]).toString('base64');

let app;
let stdout;
beforeAll(() => {
    process.env.WSFED_ALLOWED_REALMS = 'https://exchange.corp,https://other.corp';
    process.env.SESSION_SECRET = 'test-secret';
    // the session cookie is Secure: Express must see the request as https
    process.env.TRUST_PROXY = '1';
    jest.isolateModules(() => { app = require('./helpers/buildFullApp')(); });
    stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
});
afterAll(() => {
    stdout.mockRestore();
    delete process.env.TRUST_PROXY;
});

function sign(xml, rootXpath, issuerXpath) {
    const sig = new SignedXml({
        privateKey: KEY,
        signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
        xpath: rootXpath,
        transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(xml, { location: { reference: issuerXpath, action: 'after' } });
    return sig.getSignedXml();
}

// A sign-in response as the IdP posts it: the assertion and the response are both signed.
function idpResponse(requestId, { signed = true } = {}) {
    const now = Date.now();
    const at = (offsetMs) => new Date(now + offsetMs).toISOString();
    const id = () => '_' + crypto.randomBytes(8).toString('hex');
    const xml =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        `ID="${id()}" Version="2.0" IssueInstant="${at(0)}" InResponseTo="${requestId}" Destination="${ACS}">` +
        `<saml:Issuer>${IDP}</saml:Issuer>` +
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        `<saml:Assertion ID="${id()}" Version="2.0" IssueInstant="${at(0)}">` +
        `<saml:Issuer>${IDP}</saml:Issuer>` +
        '<saml:Subject><saml:NameID>alice</saml:NameID>' +
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
        `<saml:SubjectConfirmationData InResponseTo="${requestId}" NotOnOrAfter="${at(60000)}" Recipient="${ACS}"/>` +
        '</saml:SubjectConfirmation></saml:Subject>' +
        `<saml:Conditions NotBefore="${at(-1000)}" NotOnOrAfter="${at(60000)}">` +
        '<saml:AudienceRestriction><saml:Audience>passport-js</saml:Audience></saml:AudienceRestriction></saml:Conditions>' +
        `<saml:AuthnStatement AuthnInstant="${at(0)}" SessionIndex="idx-1"><saml:AuthnContext>` +
        '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>' +
        '</saml:AuthnContext></saml:AuthnStatement>' +
        '<saml:AttributeStatement>' +
        '<saml:Attribute Name="upn"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>' +
        `<saml:Attribute Name="sid"><saml:AttributeValue>${SID}</saml:AttributeValue></saml:Attribute>` +
        '</saml:AttributeStatement></saml:Assertion></samlp:Response>';
    if (!signed) return Buffer.from(xml).toString('base64');
    const withAssertion = sign(xml, "//*[local-name()='Assertion']", "//*[local-name()='Assertion']/*[local-name()='Issuer']");
    return Buffer.from(sign(withAssertion, "/*[local-name()='Response']", "/*/*[local-name()='Issuer']")).toString('base64');
}

// One browser: it keeps the cookies of the proxy between the requests.
function browser() {
    const jar = new Map();
    const send = async (req) => {
        const res = await req
            .set('X-Forwarded-Proto', 'https')
            .set('Cookie', [...jar].map(([name, value]) => `${name}=${value}`).join('; '));
        for (const line of res.headers['set-cookie'] || []) {
            const pair = line.split(';')[0];
            const name = pair.slice(0, pair.indexOf('='));
            const value = pair.slice(pair.indexOf('=') + 1);
            if (value === '') jar.delete(name); else jar.set(name, value);
        }
        return res;
    };
    return {
        jar,
        // wsignin1.0: returns the AuthnRequest ID and the RelayState that go to the IdP
        async startSignIn(wtrealm) {
            const res = await send(request(app).get('/wsfed').query({ wa: 'wsignin1.0', wtrealm }));
            expect(res.status).toBe(302);
            const toIdp = new URL(res.headers.location);
            const authnRequest = zlib.inflateRawSync(Buffer.from(toIdp.searchParams.get('SAMLRequest'), 'base64')).toString();
            return { requestId: /ID="([^"]+)"/.exec(authnRequest)[1], relayState: toIdp.searchParams.get('RelayState') };
        },
        postResponse(signIn, options) {
            return send(request(app).post('/saml2/callback').type('form')
                .send({ SAMLResponse: idpResponse(signIn.requestId, options), RelayState: signIn.relayState }));
        },
        get(path) {
            return send(request(app).get(path));
        },
    };
}

const formAction = (html) => /<form[^>]* action="([^"]+)"/.exec(html)[1];

describe('sign-in with a real IdP response', () => {
    test('a signed response ends at the token page for the realm of the sign-in', async () => {
        const tab = browser();
        const signIn = await tab.startSignIn('https://exchange.corp/owa/');
        const callback = await tab.postResponse(signIn);
        expect(callback.status).toBe(302);
        expect(callback.headers.location).toBe('/wsfed');
        const token = await tab.get('/wsfed');
        expect(token.status).toBe(200);
        expect(formAction(token.text)).toBe('https://exchange.corp/owa/');
        expect(token.text).toContain('alice@example.com');
        expect(token.text).toContain('S-1-5-21-1-2-3-500');
    });

    test('an unsigned response goes to the failure page and gets no token', async () => {
        const tab = browser();
        const signIn = await tab.startSignIn('https://exchange.corp/owa/');
        const callback = await tab.postResponse(signIn, { signed: false });
        expect(callback.status).toBe(302);
        expect(callback.headers.location).toBe('/saml2/failure');
        expect((await tab.get('/wsfed')).status).toBe(400);
    });

    test('the session of a completed sign-in cannot get a second token', async () => {
        const tab = browser();
        await tab.postResponse(await tab.startSignIn('https://exchange.corp/owa/'));
        expect((await tab.get('/wsfed')).status).toBe(200);
        expect((await tab.get('/wsfed')).status).toBe(400);
    });

    test('two tabs: the second sign-in still completes after the first got its token', async () => {
        const tabs = browser();
        const first = await tabs.startSignIn('https://exchange.corp/owa/');
        const second = await tabs.startSignIn('https://other.corp/ecp/');

        await tabs.postResponse(first);
        expect(formAction((await tabs.get('/wsfed')).text)).toBe('https://exchange.corp/owa/');

        const callback = await tabs.postResponse(second);
        expect(callback.status).toBe(302);
        expect(callback.headers.location).toBe('/wsfed');
        const token = await tabs.get('/wsfed');
        expect(token.status).toBe(200);
        expect(formAction(token.text)).toBe('https://other.corp/ecp/');
    });

    test('after the token, the kept session holds no login', async () => {
        const tabs = browser();
        const first = await tabs.startSignIn('https://exchange.corp/owa/');
        await tabs.startSignIn('https://other.corp/ecp/');
        await tabs.postResponse(first);
        expect((await tabs.get('/wsfed')).status).toBe(200);
        // a request without wa gets a token only for a logged-in session
        expect((await tabs.get('/wsfed')).status).toBe(400);
    });
});
