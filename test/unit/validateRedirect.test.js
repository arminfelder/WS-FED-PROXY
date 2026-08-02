const { parseAllowedRealms, isRealmAllowed, isWreplyAllowed } = require('../../util/validateRedirect');

describe('parseAllowedRealms', () => {
    test('returns empty array for empty string', () => {
        expect(parseAllowedRealms('')).toEqual([]);
    });

    test('returns empty array for undefined/null', () => {
        expect(parseAllowedRealms(undefined)).toEqual([]);
        expect(parseAllowedRealms(null)).toEqual([]);
    });

    test('parses a single URL into its origin', () => {
        expect(parseAllowedRealms('https://exchange.corp/owa')).toEqual(['https://exchange.corp']);
    });

    test('parses multiple comma-separated URLs', () => {
        const result = parseAllowedRealms('https://exchange.corp/owa, https://mail.example.com/owa');
        expect(result).toEqual(['https://exchange.corp', 'https://mail.example.com']);
    });

    test('normalises origins to lowercase', () => {
        expect(parseAllowedRealms('https://Exchange.CORP/owa')).toEqual(['https://exchange.corp']);
    });

    test('ignores blank entries', () => {
        expect(parseAllowedRealms('https://a.com,,https://b.com')).toEqual(['https://a.com', 'https://b.com']);
    });

    test('throws a descriptive error on a malformed entry', () => {
        expect(() => parseAllowedRealms('https://a.com,not-a-url'))
            .toThrow(/not a valid absolute URL/);
    });

    test('rejects non-http(s) schemes', () => {
        expect(() => parseAllowedRealms('foo://bar')).toThrow(/must use http or https/);
    });
});

describe('isRealmAllowed', () => {
    const allowedOrigins = ['https://exchange.corp', 'https://mail.example.com'];

    test('blocks every realm when allowedOrigins is empty (fails closed)', () => {
        expect(isRealmAllowed('https://anything.com', [])).toBe(false);
        expect(isRealmAllowed('https://exchange.corp/owa', [])).toBe(false);
        expect(isRealmAllowed('https://anything.com', undefined)).toBe(false);
    });

    test('allows a realm whose origin is in the list', () => {
        expect(isRealmAllowed('https://exchange.corp/owa', allowedOrigins)).toBe(true);
    });

    test('allows a realm matching a second entry', () => {
        expect(isRealmAllowed('https://mail.example.com/owa', allowedOrigins)).toBe(true);
    });

    test('blocks a realm not in the list', () => {
        expect(isRealmAllowed('https://attacker.com', allowedOrigins)).toBe(false);
    });

    test('returns false for missing wtrealm', () => {
        expect(isRealmAllowed(undefined, allowedOrigins)).toBe(false);
        expect(isRealmAllowed('', allowedOrigins)).toBe(false);
    });

    test('returns false for invalid URL', () => {
        expect(isRealmAllowed('not-a-url', allowedOrigins)).toBe(false);
    });
});

describe('isWreplyAllowed', () => {
    const allowedOrigins = ['https://exchange.corp', 'https://mail.example.com'];

    test('always allows absent wreply', () => {
        expect(isWreplyAllowed(undefined, 'https://exchange.corp', allowedOrigins)).toBe(true);
        expect(isWreplyAllowed('', 'https://exchange.corp', allowedOrigins)).toBe(true);
    });

    test('allows wreply on the same origin as an allowed realm', () => {
        expect(isWreplyAllowed('https://exchange.corp/auth/callback', 'https://exchange.corp/owa', allowedOrigins)).toBe(true);
    });

    test('blocks wreply whose origin is not in allowedOrigins list', () => {
        expect(isWreplyAllowed('https://attacker.com/steal', 'https://exchange.corp/owa', allowedOrigins)).toBe(false);
    });

    test('blocks wreply even if wtrealm is allowed but wreply differs', () => {
        expect(isWreplyAllowed('https://evil.corp/steal', 'https://exchange.corp/owa', allowedOrigins)).toBe(false);
    });

    describe('no same-origin fallback (empty allowedOrigins fails closed)', () => {
        test('blocks wreply sharing the wtrealm origin when nothing is allowlisted', () => {
            // both values come from the same caller, so matching them against
            // each other constrains nothing
            expect(isWreplyAllowed('https://attacker.tld/steal', 'https://attacker.tld', [])).toBe(false);
            expect(isWreplyAllowed('https://exchange.corp/reply', 'https://exchange.corp/owa', [])).toBe(false);
        });

        test('blocks wreply with a different origin than wtrealm', () => {
            expect(isWreplyAllowed('https://attacker.com/steal', 'https://exchange.corp/owa', [])).toBe(false);
        });

        test('still allows an absent wreply (caller falls back to the checked wtrealm)', () => {
            expect(isWreplyAllowed(undefined, 'https://exchange.corp', [])).toBe(true);
        });
    });

    test('returns false for an invalid wreply URL', () => {
        expect(isWreplyAllowed('not-a-url', 'https://exchange.corp', allowedOrigins)).toBe(false);
    });
});
