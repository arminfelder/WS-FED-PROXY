const { parseHttpsUrl, isLoopbackHost } = require('../../util/validateConfig');

describe('parseHttpsUrl', () => {
    test('returns the parsed https URL', () => {
        expect(parseHttpsUrl('X', 'https://proxy.example.com/wsfed').host).toBe('proxy.example.com');
    });

    test.each(['', 'proxy.example.com/wsfed', 'not a url'])('refuses %p with the variable name', (raw) => {
        expect(() => parseHttpsUrl('WSFED_ISSUER', raw)).toThrow(/WSFED_ISSUER/);
    });

    test('refuses http by default', () => {
        expect(() => parseHttpsUrl('X', 'http://proxy.example.com/')).toThrow(/https/);
    });

    test('accepts http when allowHttp is set', () => {
        expect(parseHttpsUrl('X', 'http://proxy.example.com/', { allowHttp: true }).protocol).toBe('http:');
    });

    test('refuses other schemes even with allowHttp', () => {
        expect(() => parseHttpsUrl('X', 'ftp://proxy.example.com/', { allowHttp: true })).toThrow(/https/);
    });
});

describe('isLoopbackHost', () => {
    test.each(['https://localhost:8443/x', 'https://127.0.0.1/', 'https://[::1]:3000/', 'https://0.0.0.0/'])('%s is loopback', (raw) => {
        expect(isLoopbackHost(new URL(raw))).toBe(true);
    });

    test.each(['https://localhost.corp.example/', 'https://proxy.example.com/'])('%s is not loopback', (raw) => {
        expect(isLoopbackHost(new URL(raw))).toBe(false);
    });
});
