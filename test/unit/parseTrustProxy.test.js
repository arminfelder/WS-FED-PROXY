const { parseTrustProxy } = require('../../util/parseTrustProxy');

describe('parseTrustProxy', () => {
    test('defaults to 0 when unset or blank', () => {
        expect(parseTrustProxy(undefined)).toBe(0);
        expect(parseTrustProxy('')).toBe(0);
        expect(parseTrustProxy('   ')).toBe(0);
    });

    test('accepts a hop count', () => {
        expect(parseTrustProxy('0')).toBe(0);
        expect(parseTrustProxy('1')).toBe(1);
        expect(parseTrustProxy('3')).toBe(3);
        expect(parseTrustProxy(' 2 ')).toBe(2);
    });

    test('maps the legacy booleans to hop counts', () => {
        expect(parseTrustProxy('true')).toBe(1);
        expect(parseTrustProxy('false')).toBe(0);
        expect(parseTrustProxy('TRUE')).toBe(1);
        expect(parseTrustProxy('False')).toBe(0);
    });

    test('never yields a boolean — Express would then trust the client-written end of X-Forwarded-For', () => {
        expect(parseTrustProxy('true')).not.toBe(true);
        expect(typeof parseTrustProxy('true')).toBe('number');
    });

    test('rejects values that are neither a hop count nor a legacy boolean', () => {
        for (const bad of ['yes', 'on', '-1', '1.5', 'nginx', '1,2']) {
            expect(() => parseTrustProxy(bad)).toThrow(/non-negative whole number/);
        }
    });
});
