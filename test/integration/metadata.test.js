/**
 * Federation metadata (WS-Federation 1.2 §3) from the real route, signed with the fixture key.
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');
const express = require('express');
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
const ISSUER = 'https://proxy.example.com/wsfed';
const PATH = '/wsfed/FederationMetadata/2007-06/FederationMetadata.xml';
const NS_FED = 'http://docs.oasis-open.org/wsfed/federation/200706';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

function freshApp() {
    let app;
    jest.isolateModules(() => {
        app = require('./helpers/buildApp')({ WSFED_ISSUER: ISSUER });
        // same mount as app.js
        const wsfedRouter = require('../../routes/wsfed');
        app.get('/FederationMetadata/2007-06/FederationMetadata.xml', wsfedRouter.federationMetadata);
    });
    return app;
}

function elementChildren(node) {
    return Array.from(node.childNodes).filter((n) => n.nodeType === 1);
}

describe('federation metadata', () => {
    let res, doc;
    beforeAll(async () => {
        res = await request(freshApp()).get(PATH).set('X-Forwarded-Host', 'evil.tld').set('Host', 'evil2.tld');
        doc = new DOMParser().parseFromString(res.text, 'text/xml');
    });

    test('is served as XML with the configured entityID', () => {
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toMatch(/^application\/xml/);
        expect(doc.documentElement.localName).toBe('EntityDescriptor');
        expect(doc.documentElement.getAttribute('entityID')).toBe(ISSUER);
    });

    test('takes no host from the request headers', () => {
        expect(res.text).not.toContain('evil.tld');
        expect(res.text).not.toContain('evil2.tld');
    });

    test('names the configured passive endpoint, and the required STS endpoint', () => {
        for (const name of ['PassiveRequestorEndpoint', 'SecurityTokenServiceEndpoint']) {
            const el = doc.getElementsByTagNameNS(NS_FED, name)[0];
            expect(el).toBeDefined();
            expect(el.getElementsByTagNameNS('http://www.w3.org/2005/08/addressing', 'Address')[0].textContent)
                .toBe('https://proxy.example.com/wsfed');
        }
    });

    test('offers only the SAML 1.1 token type that is issued', () => {
        const uris = Array.from(doc.getElementsByTagNameNS(NS_FED, 'TokenType')).map((t) => t.getAttribute('Uri'));
        expect(uris).toEqual(['urn:oasis:names:tc:SAML:1.0:assertion']);
    });

    test('offers the claims that OWAProfileMapper issues', () => {
        const uris = Array.from(doc.getElementsByTagNameNS('http://docs.oasis-open.org/wsfed/authorization/200706', 'ClaimType'))
            .map((c) => c.getAttribute('Uri')).sort();
        expect(uris).toEqual([
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
        ]);
    });

    test('RoleDescriptor children follow the SecurityTokenServiceType sequence', () => {
        const role = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'RoleDescriptor')[0];
        expect(elementChildren(role).map((n) => n.localName)).toEqual([
            'KeyDescriptor', 'TokenTypesOffered', 'ClaimTypesOffered', 'SecurityTokenServiceEndpoint', 'PassiveRequestorEndpoint',
        ]);
    });

    test('is signed: enveloped, exclusive c14n, ds:Signature first, valid with the token signing cert', () => {
        const first = elementChildren(doc.documentElement)[0];
        expect(first.namespaceURI).toBe(NS_DS);
        expect(first.localName).toBe('Signature');
        expect(res.text).toContain('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        expect(res.text).toContain('http://www.w3.org/2001/10/xml-exc-c14n#');

        const sig = new SignedXml({ publicCert: CERT });
        sig.loadSignature(first);
        expect(sig.checkSignature(res.text)).toBe(true);
    });

    test('a changed document fails signature verification', () => {
        const tampered = res.text.replace('https://proxy.example.com/wsfed</Address>', 'https://evil.tld/wsfed</Address>');
        const tdoc = new DOMParser().parseFromString(tampered, 'text/xml');
        const sig = new SignedXml({ publicCert: CERT });
        sig.loadSignature(elementChildren(tdoc.documentElement)[0]);
        expect(sig.checkSignature(tampered)).toBe(false);
    });

    test('is also served at the server root (§3.2.2)', async () => {
        const root = await request(freshApp()).get('/FederationMetadata/2007-06/FederationMetadata.xml');
        expect(root.status).toBe(200);
        expect(root.text).toContain(`entityID="${ISSUER}"`);
    });
});

describe('buildMetadataXml escaping', () => {
    const { buildMetadataXml } = require('../../util/metadata');

    test('values with XML special characters round-trip exactly', () => {
        const issuer = `https://p.example/wsfed?a=1&b="2"&c=<3>&d='4'`;
        const xml = buildMetadataXml({
            issuer,
            endpoint: issuer,
            cert: CERT,
            claimTypes: [{ id: 'urn:x&y', optional: true, displayName: '<b>Name</b>', description: `a & b "c"` }],
        });
        const doc = new DOMParser().parseFromString(xml, 'text/xml');
        expect(doc.documentElement.getAttribute('entityID')).toBe(issuer);
        expect(doc.getElementsByTagNameNS('http://www.w3.org/2005/08/addressing', 'Address')[0].textContent).toBe(issuer);
        const claim = doc.getElementsByTagNameNS('http://docs.oasis-open.org/wsfed/authorization/200706', 'ClaimType')[0];
        expect(claim.getAttribute('Uri')).toBe('urn:x&y');
        expect(claim.getElementsByTagNameNS('http://docs.oasis-open.org/wsfed/authorization/200706', 'DisplayName')[0].textContent).toBe('<b>Name</b>');
        expect(claim.getElementsByTagNameNS('http://docs.oasis-open.org/wsfed/authorization/200706', 'Description')[0].textContent).toBe(`a & b "c"`);
    });

    test('xsi:type resolves: the fed prefix is declared on RoleDescriptor', () => {
        const xml = buildMetadataXml({ issuer: 'https://p/wsfed', endpoint: 'https://p/wsfed', cert: CERT, claimTypes: [] });
        const role = new DOMParser().parseFromString(xml, 'text/xml')
            .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'RoleDescriptor')[0];
        expect(role.getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'type')).toBe('fed:SecurityTokenServiceType');
        expect(role.lookupNamespaceURI('fed')).toBe('http://docs.oasis-open.org/wsfed/federation/200706');
    });
});

describe('ADFS federationserverservice.asmx', () => {
    test.each(['get', 'post'])('%s takes no host from the request headers', async (method) => {
        const res = await request(freshApp())[method]('/wsfed/adfs/fs/federationserverservice.asmx')
            .set('X-Forwarded-Host', 'evil.tld').set('X-Forwarded-Proto', 'http');
        expect(res.status).toBe(200);
        expect(res.text).not.toContain('evil.tld');
        expect(res.text).not.toContain('http://proxy');
        expect(res.text).toContain('https://proxy.example.com');
    });
});
