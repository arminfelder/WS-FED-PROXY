const { parseIntEnv } = require('../../util/parseIntEnv');

const BOUNDS = { def: 600, min: 60, max: 3600 };

describe('parseIntEnv', () => {
    test('returns the default when unset or blank', () => {
        expect(parseIntEnv('X', undefined, BOUNDS)).toBe(600);
        expect(parseIntEnv('X', '', BOUNDS)).toBe(600);
        expect(parseIntEnv('X', '  ', BOUNDS)).toBe(600);
    });

    test('accepts whole numbers inside the range, bounds included', () => {
        expect(parseIntEnv('X', '60', BOUNDS)).toBe(60);
        expect(parseIntEnv('X', ' 900 ', BOUNDS)).toBe(900);
        expect(parseIntEnv('X', '3600', BOUNDS)).toBe(3600);
    });

    test('rejects values a raw parseInt would turn into NaN, 0 or a truncated number', () => {
        for (const bad of ['abc', '0', '-1', '1.5', '600abc', '0x10', '1e3']) {
            expect(() => parseIntEnv('WSFED_TOKEN_LIFETIME', bad, BOUNDS)).toThrow(/WSFED_TOKEN_LIFETIME must be a whole number from 60 to 3600/);
        }
    });

    test('rejects values outside the range', () => {
        expect(() => parseIntEnv('X', '59', BOUNDS)).toThrow();
        expect(() => parseIntEnv('X', '3601', BOUNDS)).toThrow();
    });

    test('accepts 0 when the range allows it', () => {
        expect(parseIntEnv('X', '0', { def: 3000, min: 0, max: 300000 })).toBe(0);
    });
});
