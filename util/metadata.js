/*
Copyright (C) ws-fed proxy  Armin Felder

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

const crypto = require('crypto');
const { SignedXml } = require('xml-crypto');
const { DOMImplementation, XMLSerializer } = require('@xmldom/xmldom');

const XMLNS = 'http://www.w3.org/2000/xmlns/';

const NS = {
    md:   'urn:oasis:names:tc:SAML:2.0:metadata',
    fed:  'http://docs.oasis-open.org/wsfed/federation/200706',
    auth: 'http://docs.oasis-open.org/wsfed/authorization/200706',
    wsa:  'http://www.w3.org/2005/08/addressing',
    xsi:  'http://www.w3.org/2001/XMLSchema-instance',
    ds:   'http://www.w3.org/2000/09/xmldsig#',
};
// wsfed issues SAML 1.1 assertions only. ADFS advertises them with this URI.
const SAML11_TOKEN_TYPE = 'urn:oasis:names:tc:SAML:1.0:assertion';
const ENTITY_XPATH = "/*[local-name()='EntityDescriptor']";

function pemBody(pem) {
    const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(String(pem));
    if (!m) throw new Error('certificate is not PEM');
    return m[1].replace(/\s+/g, '');
}

function element(doc, ns, name, attributes = {}, children = []) {
    const el = doc.createElementNS(ns, name);
    for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, String(value));
    for (const child of children) el.appendChild(typeof child === 'string' ? doc.createTextNode(child) : child);
    return el;
}

/**
 * Builds the WS-Federation 1.2 §3.1 metadata document for this STS.
 * Every value comes from configuration, never from the request.
 * The serializer escapes all values and writes the namespace declarations.
 *
 * @param {{issuer: string, endpoint: string, cert: (string|Buffer), claimTypes: Array<{id: string, optional?: boolean, displayName?: string, description?: string}>}} opts
 * @returns {string} unsigned XML
 */
function buildMetadataXml({ issuer, endpoint, cert, claimTypes }) {
    const doc = new DOMImplementation().createDocument(NS.md, 'EntityDescriptor', null);
    const el = (ns, name, attributes, children) => element(doc, ns, name, attributes, children);
    const endpointReference = () => el(NS.wsa, 'EndpointReference', {}, [el(NS.wsa, 'Address', {}, [endpoint])]);

    const root = doc.documentElement;
    root.setAttribute('ID', `_${crypto.randomUUID()}`);
    root.setAttribute('entityID', issuer);

    const role = el(NS.md, 'RoleDescriptor', { protocolSupportEnumeration: NS.fed, ServiceDisplayName: issuer });
    // xsi:type holds a QName: its prefix must be declared on this element, not only on the fed:* children
    role.setAttributeNS(XMLNS, 'xmlns:fed', NS.fed);
    role.setAttributeNS(NS.xsi, 'xsi:type', 'fed:SecurityTokenServiceType');

    // child order follows SecurityTokenServiceType, WS-Federation 1.2 §3.1.2 p37-39
    role.appendChild(el(NS.md, 'KeyDescriptor', { use: 'signing' }, [
        el(NS.ds, 'KeyInfo', {}, [el(NS.ds, 'X509Data', {}, [el(NS.ds, 'X509Certificate', {}, [pemBody(cert)])])]),
    ]));
    role.appendChild(el(NS.fed, 'fed:TokenTypesOffered', {}, [el(NS.fed, 'fed:TokenType', { Uri: SAML11_TOKEN_TYPE })]));
    role.appendChild(el(NS.fed, 'fed:ClaimTypesOffered', {}, claimTypes.map((ct) =>
        el(NS.auth, 'auth:ClaimType', { Uri: ct.id, Optional: !!ct.optional }, [
            ...(ct.displayName ? [el(NS.auth, 'auth:DisplayName', {}, [ct.displayName])] : []),
            ...(ct.description ? [el(NS.auth, 'auth:Description', {}, [ct.description])] : []),
        ]))));
    // required by the schema (minOccurs=1). There is no active WS-Trust endpoint, so it names the passive endpoint.
    role.appendChild(el(NS.fed, 'fed:SecurityTokenServiceEndpoint', {}, [endpointReference()]));
    role.appendChild(el(NS.fed, 'fed:PassiveRequestorEndpoint', {}, [endpointReference()]));
    root.appendChild(role);

    return new XMLSerializer().serializeToString(doc);
}

/**
 * Signs the document as WS-Federation 1.2 §3.1.15 requires: enveloped signature,
 * exclusive canonicalization, with the token signing key. ds:Signature is the first child.
 */
function signMetadataXml(xml, { key, cert }) {
    const sig = new SignedXml({
        privateKey: key,
        publicCert: cert,
        idAttribute: 'ID',
        signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
        xpath: ENTITY_XPATH,
        transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(xml, { prefix: 'ds', location: { reference: ENTITY_XPATH, action: 'prepend' } });
    return sig.getSignedXml();
}

/**
 * Express handler. The document is built and signed once, at the first request.
 *
 * @param {() => {issuer: string, endpoint: string, cert: (string|Buffer), key: (string|Buffer), claimTypes: Array}} getOptions
 */
function metadataHandler(getOptions) {
    let doc;
    return function (req, res) {
        if (!doc) {
            const opts = getOptions(req);
            doc = '<?xml version="1.0" encoding="utf-8"?>' + signMetadataXml(buildMetadataXml(opts), opts);
        }
        res.type('application/xml').send(doc);
    };
}

module.exports = { buildMetadataXml, signMetadataXml, metadataHandler };
