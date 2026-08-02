/**
 * End-to-end WS-Fed token tests.
 *
 * Uses real wsfed.auth() with actual test certificates so the signed SAML 1.1
 * assertion is fully validated — signature, issuer, audience, and every claim
 * OWA requires.  No OWA instance is needed.
 */

const request = require('supertest');
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const wsfed = require('wsfed');
const helmet = require('helmet');
const profileMapper = require('../../util/OWAProfileMapper');

const CERT_PATH = path.join(__dirname, '../fixtures/test-cert.pem');
const KEY_PATH  = path.join(__dirname, '../fixtures/test-cert.key');
const CERT = fs.readFileSync(CERT_PATH);
const KEY  = fs.readFileSync(KEY_PATH);

const ISSUER   = 'https://proxy.example.com/wsfed';
const WTREALM  = 'https://exchange.corp/owa/';
const WREPLY   = 'https://exchange.corp/owa/auth/wsfed';
const WCTX     = 'rm=0&id=passive&ru=%2fowa%2f';
// Mirrors the WSFED_TOKEN_LIFETIME default in app.js.
const TOKEN_LIFETIME = 600;
const TEST_USER = {
    id:  'jdoe@corp.example',
    upn: 'jdoe@corp.example',
    sid: 'S-1-5-21-3623811015-3361044348-30300820-1013',
};

function buildTokenApp(opts = {}) {
    const app = express();
    app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'none'"], scriptSrc: ["'unsafe-inline'", "'unsafe-eval'"], formAction: ["https:"] } }));
    app.use(helmet.referrerPolicy({ policy: 'origin-when-cross-origin' }));
    app.use(express.urlencoded({ extended: false }));
    app.use(session({ secret: 'test', resave: false, saveUninitialized: false, cookie: { secure: false } }));

    app.get('/wsfed', (req, res, next) => {
        req.user = opts.user || TEST_USER;
        return wsfed.auth({
            issuer:        opts.issuer || ISSUER,
            cert:          opts.cert   || CERT,
            key:           opts.key    || KEY,
            lifetime:      opts.lifetime || TOKEN_LIFETIME,
            profileMapper: profileMapper,
            getPostURL: (_wtrealm, wreply, _req, cb) => {
                cb(null, wreply || _wtrealm);
            },
        })(req, res, next);
    });

    return app;
}

// ── helpers ──────────────────────────────────────────────────────────────────

function decodeHtmlEntities(str) {
    return str
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#34;/g, '"');
}

function extractWresult(html) {
    const match = /name="wresult"\s+value="([\s\S]*?)"(?:\s*\/>|\s*>)/.exec(html)
               || /name="wresult" value="([^"]+)"/.exec(html);
    if (!match) throw new Error('wresult not found in HTML');
    // The value itself is HTML-entity encoded once
    return decodeHtmlEntities(match[1]);
}

function extractAssertion(wresult) {
    // wresult may still have a second layer of entity encoding for the XML content
    const decoded = decodeHtmlEntities(wresult);
    const m = /<t:RequestedSecurityToken>([\s\S]*?)<\/t:RequestedSecurityToken>/.exec(decoded);
    if (!m) throw new Error('RequestedSecurityToken not found in: ' + decoded.substring(0, 200));
    return m[1];
}

function verifySignature(assertionXml) {
    const doc = new DOMParser().parseFromString(assertionXml);
    const signatureNode = doc.documentElement.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#', 'Signature'
    )[0];
    if (!signatureNode) throw new Error('No Signature element found in assertion');

    const sig = new SignedXml({ idAttribute: 'AssertionID', publicCert: CERT });
    sig.loadSignature(signatureNode.toString());
    return sig.checkSignature(assertionXml);
}

function getAttributes(doc) {
    const nodes = doc.documentElement.getElementsByTagName('saml:Attribute');
    const map = {};
    for (let i = 0; i < nodes.length; i++) {
        const name = nodes[i].getAttribute('AttributeName');
        const val  = nodes[i].getElementsByTagName('saml:AttributeValue')[0].textContent;
        map[name] = val;
    }
    return map;
}

function extractHiddenInput(html, name) {
    const re = new RegExp(`name="${name}"\\s+value="([^"]*)"`, 'i');
    const m = re.exec(html) || new RegExp(`name="${name}" value="([^"]*)"`, 'i').exec(html);
    return m ? m[1] : null;
}

// ── tests ────────────────────────────────────────────────────────────────────

describe('WS-Fed token — full round-trip (no OWA needed)', () => {
    let html, assertionXml, assertionDoc;

    beforeAll(async () => {
        const app = buildTokenApp();
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: WTREALM, wreply: WREPLY, wctx: WCTX });
        expect(res.status).toBe(200);
        html = res.text;
        const wresult = extractWresult(html);
        assertionXml = extractAssertion(wresult);
        assertionDoc = new DOMParser().parseFromString(assertionXml);
    });

    test('response is an auto-submit HTML form', () => {
        expect(html).toMatch(/<form\b/i);
        expect(html).toMatch(/window\.setTimeout/);
    });

    test('form action is the wreply URL', () => {
        expect(html).toContain(`action="${WREPLY}"`);
    });

    test('form action falls back to wtrealm when wreply is absent', async () => {
        const app = buildTokenApp();
        const res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: WTREALM });
        expect(res.status).toBe(200);
        expect(res.text).toContain(`action="${WTREALM}"`);
    });

    test('wa=wsignin1.0 is present in the form', () => {
        expect(html).toContain('name="wa"');
        expect(html).toContain('value="wsignin1.0"');
    });

    test('wctx is echoed verbatim (after HTML-entity decode)', () => {
        const rawWctx = extractHiddenInput(html, 'wctx');
        expect(rawWctx).not.toBeNull();
        // The wctx value in the HTML is entity-encoded; decode to compare
        expect(decodeHtmlEntities(rawWctx)).toBe(WCTX);
    });

    test('XML signature is cryptographically valid', () => {
        expect(verifySignature(assertionXml)).toBe(true);
    });

    test('issuer matches WSFED_ISSUER config', () => {
        const issuer = assertionDoc.documentElement.getAttribute('Issuer');
        // wsfed.auth() passes the issuer through asResource(), which does NOT
        // add urn: prefix to https:// URIs — it is stored verbatim
        expect(issuer).toBe(ISSUER);
    });

    test('audience matches wtrealm', () => {
        const audiences = assertionDoc.documentElement
            .getElementsByTagName('saml:Conditions')[0]
            .getElementsByTagName('saml:AudienceRestrictionCondition')[0]
            .getElementsByTagName('saml:Audience');
        const texts = Array.from({ length: audiences.length }, (_, i) => audiences[i].textContent);
        expect(texts).toContain(WTREALM);
    });

    test('nameIdentifier matches user.id', () => {
        const ni = assertionDoc.documentElement.getElementsByTagName('saml:NameIdentifier')[0];
        expect(ni.textContent).toBe(TEST_USER.id);
    });

    test('UPN claim is present and correct', () => {
        const attrs = getAttributes(assertionDoc);
        expect(attrs['upn']).toBe(TEST_USER.upn);
    });

    test('primarysid claim is present and correct', () => {
        const attrs = getAttributes(assertionDoc);
        expect(attrs['primarysid']).toBe(TEST_USER.sid);
    });

    test('token lifetime is set (NotBefore / NotOnOrAfter present)', () => {
        const conditions = assertionDoc.documentElement.getElementsByTagName('saml:Conditions')[0];
        expect(conditions.getAttribute('NotBefore')).toBeTruthy();
        expect(conditions.getAttribute('NotOnOrAfter')).toBeTruthy();
    });

    test('token lifetime is capped at WSFED_TOKEN_LIFETIME, not the 8h library default', () => {
        const conditions = assertionDoc.documentElement.getElementsByTagName('saml:Conditions')[0];
        const notBefore   = Date.parse(conditions.getAttribute('NotBefore'));
        const notOnOrAfter = Date.parse(conditions.getAttribute('NotOnOrAfter'));
        expect(Math.round((notOnOrAfter - notBefore) / 1000)).toBe(TOKEN_LIFETIME);
    });
});

describe('WS-Fed token response — security headers', () => {
    let res;

    beforeAll(async () => {
        const app = buildTokenApp();
        res = await request(app)
            .get('/wsfed')
            .query({ wa: 'wsignin1.0', wtrealm: WTREALM, wreply: WREPLY, wctx: WCTX });
    });

    test('Referrer-Policy is origin-when-cross-origin so Exchange receives the Origin on the form POST', () => {
        // no-referrer breaks Exchange 440: it strips the Referer header from the
        // cross-origin form POST, which Exchange uses to correlate its WS-Fed session.
        expect(res.headers['referrer-policy']).toBe('origin-when-cross-origin');
    });

    test('Content-Security-Policy allows unsafe-eval for the auto-submit form script', () => {
        // window.setTimeout(string) is treated as eval() by browsers and requires unsafe-eval.
        const csp = res.headers['content-security-policy'];
        expect(csp).toContain("'unsafe-eval'");
    });

    test('Content-Security-Policy form-action allows HTTPS targets', () => {
        const csp = res.headers['content-security-policy'];
        expect(csp).toContain('form-action https:');
    });
});
