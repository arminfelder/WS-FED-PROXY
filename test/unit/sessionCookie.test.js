const { parseSameSite } = require('../../util/sessionCookie');

describe('parseSameSite (SESSION_SAMESITE)', () => {
    test.each([
        [undefined, 'none'],
        ['', 'none'],
        ['none', 'none'],
        [' Strict ', 'strict'],
        ['LAX', 'lax'],
    ])('%p gives %p', (raw, expected) => {
        expect(parseSameSite(raw)).toBe(expected);
    });

    test.each(['true', 'no', 'strict;'])('%p stops the startup', (raw) => {
        expect(() => parseSameSite(raw)).toThrow(/SESSION_SAMESITE must be/);
    });
});
