/**
 * Token response from the real /wsfed route with the real wsfed library.
 * Only certificate reads are redirected to test/fixtures.
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');

jest.mock('fs', () => {
    const real = jest.requireActual('fs');
    const nodePath = jest.requireActual('path');
    const fixtures = nodePath.join(__dirname, '../fixtures');
    const names = { 'exchange.crt': 'test-cert.pem', 'exchange.key': 'test-cert.key', 'exchange.p7b': 'test-cert.pem' };
    return {
        ...real,
        readFileSync: (p, opts) => {
            const s = String(p);
            if (s.includes(`${nodePath.sep}certs${nodePath.sep}`)) {
                return real.readFileSync(nodePath.join(fixtures, names[nodePath.basename(s)] || nodePath.basename(s)), opts);
            }
            return real.readFileSync(p, opts);
        },
    };
});

const CERT = fs.readFileSync(path.join(__dirname, '../fixtures/test-cert.pem'));
const REALM = 'https://exchange.corp/owa/';

function decode(str) {
    return str.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function hiddenInput(html, name) {
    const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
    return m ? decode(m[1]) : null;
}

function verifySignature(wresult) {
    const assertion = /<t:RequestedSecurityToken>([\s\S]*?)<\/t:RequestedSecurityToken>/.exec(wresult)[1];
    const doc = new DOMParser().parseFromString(assertion);
    const sigNode = doc.documentElement.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
    const sig = new SignedXml({ idAttribute: 'AssertionID', publicCert: CERT });
    sig.loadSignature(sigNode.toString());
    return sig.checkSignature(assertion);
}

async function issue(sessionWsfedArgs, query = {}) {
    let res;
    jest.isolateModules(() => {
        const buildApp = require('./helpers/buildApp');
        res = request(buildApp({ authenticated: true, sessionWsfedArgs })).get('/wsfed').query(query);
    });
    return res;
}

describe('token response form (WS-Federation 1.2 §13.6.2)', () => {
    test('without wctx: no wctx field and no Context="undefined" on the RSTR', async () => {
        const res = await issue({ wa: 'wsignin1.0', wtrealm: REALM });
        expect(res.status).toBe(200);
        expect(res.text).not.toContain('name="wctx"');
        const wresult = hiddenInput(res.text, 'wresult');
        expect(wresult).toMatch(/^<t:RequestSecurityTokenResponse xmlns:t=/);
        expect(wresult).not.toContain('Context=');
        expect(verifySignature(wresult)).toBe(true);
    });

    test('with wctx: the value is returned unchanged in the form and in Context', async () => {
        const wctx = 'rm=0&id=passive&ru=%2fowa%2f"<x>';
        const res = await issue({ wa: 'wsignin1.0', wtrealm: REALM, wctx });
        expect(hiddenInput(res.text, 'wctx')).toBe(wctx);
        const wresult = hiddenInput(res.text, 'wresult');
        expect(wresult).toContain('Context="rm=0&amp;id=passive&amp;ru=%2fowa%2f&quot;&lt;x&gt;"');
        expect(verifySignature(wresult)).toBe(true);
    });

    test('a wctx in the query of the return request does not reach the response', async () => {
        const res = await issue({ wa: 'wsignin1.0', wtrealm: REALM }, { wctx: 'injected' });
        // ?wctx= alone has no wa, so it is the return path
        expect(res.status).toBe(200);
        expect(res.text).not.toContain('injected');
    });

    test('an empty stored wctx stays empty: a wctx in the return query does not reach Context', async () => {
        // the library uses `options.wctx || req.query.wctx`, so "" falls through to the query
        const res = await issue({ wa: 'wsignin1.0', wtrealm: REALM, wctx: '' }, { wctx: 'injected' });
        expect(res.status).toBe(200);
        expect(res.text).not.toContain('injected');
        expect(hiddenInput(res.text, 'wctx')).toBe('');
        const wresult = hiddenInput(res.text, 'wresult');
        expect(wresult).toMatch(/^<t:RequestSecurityTokenResponse Context="" xmlns:t=/);
        expect(verifySignature(wresult)).toBe(true);
    });

    test('the form submits without eval', async () => {
        const res = await issue({ wa: 'wsignin1.0', wtrealm: REALM });
        expect(res.text).toContain('document.forms[0].submit();');
        expect(res.text).not.toContain('setTimeout');
    });
});
