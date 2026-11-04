const { userFromProfile, parseSid, ClaimError } = require('../../util/samlProfile');

// MS-DTYP 2.4.2.2 encoder, for the fixtures only
function sidStringToBuffer(sid) {
    const [, , authority, ...subs] = sid.split('-');
    const buf = Buffer.alloc(8 + 4 * subs.length);
    buf[0] = 1;
    buf[1] = subs.length;
    buf.writeUIntBE(Number(authority), 2, 6);
    subs.forEach((s, i) => buf.writeUInt32LE(Number(s), 8 + 4 * i));
    return buf;
}

const SID = 'S-1-5-21-1004336348-1177238915-682003330-512';
const SID_B64 = sidStringToBuffer(SID).toString('base64');
const settings = { upnAttribute: 'upn', sidAttribute: 'sid', sidBase64: true };

const AUTHN = [{ $: { AuthnInstant: '2026-10-09T10:00:00Z', SessionNotOnOrAfter: '2026-10-09T18:00:00Z' } }];

// xml2js shape that node-saml produces (explicitCharkey: true)
function attribute(name, ...values) {
    return { $: { Name: name }, AttributeValue: values.map((v) => ({ _: v })) };
}

function profile({ attributes = [attribute('upn', 'alice@example.com'), attribute('sid', SID_B64)], authn = AUTHN, ...overrides } = {}) {
    return {
        nameID: 'alice',
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        sessionIndex: 'idx-1',
        getAssertion: () => ({ Assertion: { AuthnStatement: authn, AttributeStatement: [{ Attribute: attributes }] } }),
        ...overrides,
    };
}

describe('userFromProfile', () => {
    test('maps a complete profile', () => {
        const user = userFromProfile(profile(), settings);
        expect(user).toMatchObject({
            id: 'alice', nameID: 'alice', upn: 'alice@example.com', sid: SID, sessionIndex: 'idx-1',
            authnInstant: '2026-10-09T10:00:00Z', sessionNotOnOrAfter: '2026-10-09T18:00:00Z',
        });
    });

    test('accepts a textual SID when SAML2_CLAIMS_SID_BASE64 is false', () => {
        const p = profile({ attributes: [attribute('upn', 'alice@example.com'), attribute('sid', SID)] });
        expect(userFromProfile(p, { ...settings, sidBase64: false }).sid).toBe(SID);
    });

    test.each([
        ['without an AuthnStatement', null],
        ['with an empty AuthnStatement', []],
        ['with an AuthnStatement without attributes', [{}]],
    ])('leaves authnInstant and sessionNotOnOrAfter undefined %s', (_label, authn) => {
        const user = userFromProfile(profile({ authn }), settings);
        expect(user.authnInstant).toBeUndefined();
        expect(user.sessionNotOnOrAfter).toBeUndefined();
    });

    // Exchange claims-based authentication needs the UPN and primary SID claims
    test.each([
        ['nameID missing', { nameID: undefined }, /NameID/],
        ['nameID empty', { nameID: '' }, /NameID/],
        ['upn missing', { attributes: [attribute('sid', SID_B64)] }, /UPN/],
        ['upn empty', { attributes: [attribute('upn', ''), attribute('sid', SID_B64)] }, /UPN/],
        ['upn has no text', { attributes: [{ $: { Name: 'upn' }, AttributeValue: [{}] }, attribute('sid', SID_B64)] }, /UPN/],
        ['upn multi-valued', { attributes: [attribute('upn', 'a@example.com', 'b@example.com'), attribute('sid', SID_B64)] }, /more than one UPN/],
        ['upn sent twice', { attributes: [attribute('upn', 'a@example.com'), attribute('upn', 'b@example.com'), attribute('sid', SID_B64)] }, /more than one UPN/],
        ['sid missing', { attributes: [attribute('upn', 'alice@example.com')] }, /SID/],
        ['sid multi-valued', { attributes: [attribute('upn', 'alice@example.com'), attribute('sid', SID_B64, SID_B64)] }, /more than one SID/],
        ['sid sent twice', { attributes: [attribute('upn', 'alice@example.com'), attribute('sid', SID_B64), attribute('sid', SID_B64)] }, /more than one SID/],
        ['the profile has no assertion', { getAssertion: undefined }, /no assertion/],
    ])('refuses the assertion when %s', (_label, overrides, message) => {
        expect(() => userFromProfile(profile(overrides), settings)).toThrow(ClaimError);
        expect(() => userFromProfile(profile(overrides), settings)).toThrow(message);
    });

    // node-saml checks idpIssuer on logout messages only, never on the sign-in assertion
    describe('SAML2_IDP_ISSUER', () => {
        const IDP = 'https://idp.example.com/realms/corp';

        test('accepts the assertion when the issuer matches', () => {
            expect(userFromProfile(profile({ issuer: IDP }), { ...settings, idpIssuer: IDP }).upn).toBe('alice@example.com');
        });

        test.each([
            ['another issuer', { issuer: 'https://idp.example.com/realms/other' }],
            ['no issuer', {}],
        ])('refuses the assertion with %s', (_label, overrides) => {
            expect(() => userFromProfile(profile(overrides), { ...settings, idpIssuer: IDP })).toThrow(ClaimError);
            expect(() => userFromProfile(profile(overrides), { ...settings, idpIssuer: IDP })).toThrow(/issuer/);
        });

        test('does not check the issuer when the setting is not set', () => {
            expect(userFromProfile(profile({ issuer: 'https://idp.example.com/realms/other' }), settings).upn).toBe('alice@example.com');
        });
    });

    test('reads the attribute names from the settings', () => {
        const p = profile({ attributes: [attribute('userPrincipalName', 'bob@example.com'), attribute('objectSid', SID_B64)] });
        const user = userFromProfile(p, { upnAttribute: 'userPrincipalName', sidAttribute: 'objectSid', sidBase64: true });
        expect(user.upn).toBe('bob@example.com');
        expect(user.sid).toBe(SID);
    });

    test('does not take a claim from a built-in profile field of the same name', () => {
        expect(() => userFromProfile(profile(), { ...settings, upnAttribute: 'nameID' })).toThrow(/UPN/);
    });
});

describe('parseSid', () => {
    test('decodes a binary SID', () => {
        expect(parseSid(SID_B64, true)).toBe(SID);
    });

    test('renders an identifier authority of 2^32 or more in hex', () => {
        const buf = Buffer.alloc(12);
        buf[0] = 1; buf[1] = 1;
        buf.writeUIntBE(0x010000000001, 2, 6);
        buf.writeUInt32LE(7, 8);
        expect(parseSid(buf.toString('base64'), true)).toBe('S-1-0x010000000001-7');
    });

    test.each([
        ['too short for a header', Buffer.from([1, 1, 0]).toString('base64')],
        ['a sub-authority count beyond the buffer', Buffer.from([1, 5, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]).toString('base64')],
        ['no sub-authority', Buffer.from([1, 0, 0, 0, 0, 0, 0, 5]).toString('base64')],
        ['revision 2', Buffer.from([2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).toString('base64')],
        ['trailing bytes', Buffer.concat([sidStringToBuffer(SID), Buffer.from([0])]).toString('base64')],
        ['not base64 at all', '!!!'],
        ['an empty value', ''],
    ])('refuses a binary SID that is %s', (_label, value) => {
        expect(() => parseSid(value, true)).toThrow(ClaimError);
    });

    test.each([
        'admin',
        'S-1-5',
        'S-2-5-21-1',
        'S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16',
        'S-1-5-21-1 ',
        'S-1-5-21-0x1',
        'S-1-4294967296-1',
        'S-1-5-21-4294967296',
        '',
    ])('refuses the textual SID %p', (value) => {
        expect(() => parseSid(value, false)).toThrow(ClaimError);
    });

    test.each([
        'S-1-5-18',
        'S-1-5-21-4294967295',
        'S-1-0x010000000001-7',
        'S-1-0x01000000000a-7',
    ])('accepts the textual SID %p', (value) => {
        expect(parseSid(value, false)).toBe(value);
    });
});
