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

describe('SameSite of the sign-out record cookie', () => {
    const load = (value) => {
        let options;
        const saved = process.env.SESSION_SAMESITE;
        process.env.SESSION_SAMESITE = value;
        jest.isolateModules(() => { options = require('../../util/cookies').SSO_COOKIE_OPTIONS; });
        if (saved === undefined) delete process.env.SESSION_SAMESITE; else process.env.SESSION_SAMESITE = saved;
        return options;
    };

    test('none when the session cookie is none: a cross-site IdP LogoutRequest must carry it', () => {
        expect(load('none').sameSite).toBe('none');
    });

    test.each(['strict', 'lax'])('lax when the session cookie is %s: wsignout1.0 from OWA is cross-site', (value) => {
        expect(load(value).sameSite).toBe('lax');
    });
});
