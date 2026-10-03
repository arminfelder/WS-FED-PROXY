const ssoRecord = require('../../util/ssoRecord');
const { pendingLogout } = require('../../util/pendingLogout');

const SECRET = 'test-secret';
const USER = { id: 'u', upn: 'u@corp', sid: 'S-1', nameID: 'u@corp', nameIDFormat: 'fmt', sessionIndex: 'idx-1' };

describe('ssoRecord', () => {
    afterEach(() => jest.useRealTimers());

    test('seal and open give back the record', () => {
        const record = ssoRecord.addRealm(null, USER, 'https://exchange.corp/owa/', 3600);
        const opened = ssoRecord.open(ssoRecord.seal(record, SECRET), SECRET);
        expect(opened.realms).toEqual(['https://exchange.corp/owa/']);
        expect(opened.sessionIndex).toBe('idx-1');
    });

    test('keeps only the SAML identity, not other user fields', () => {
        const record = ssoRecord.addRealm(null, USER, 'https://a/', 3600);
        expect(record).not.toHaveProperty('upn');
        expect(record).not.toHaveProperty('sid');
        expect(ssoRecord.identity(record)).toEqual({ nameID: 'u@corp', nameIDFormat: 'fmt', sessionIndex: 'idx-1' });
    });

    test('a changed value, another secret or garbage gives null', () => {
        const token = ssoRecord.seal(ssoRecord.addRealm(null, USER, 'https://a/', 3600), SECRET);
        const flipped = token.slice(0, -2) + (token.slice(-2) === 'AA' ? 'AB' : 'AA');
        expect(ssoRecord.open(flipped, SECRET)).toBeNull();
        expect(ssoRecord.open(token, 'other-secret')).toBeNull();
        expect(ssoRecord.open('x', SECRET)).toBeNull();
        expect(ssoRecord.open(undefined, SECRET)).toBeNull();
    });

    test('an expired record gives null', () => {
        jest.useFakeTimers({ now: 0 });
        const token = ssoRecord.seal(ssoRecord.addRealm(null, USER, 'https://a/', 60), SECRET);
        jest.setSystemTime(59999);
        expect(ssoRecord.open(token, SECRET)).not.toBeNull();
        jest.setSystemTime(60000);
        expect(ssoRecord.open(token, SECRET)).toBeNull();
    });

    test('adds each realm one time and keeps the last 20', () => {
        let record = null;
        for (let i = 0; i < 25; i++) record = ssoRecord.addRealm(record, USER, `https://r${i}/`, 3600);
        record = ssoRecord.addRealm(record, USER, 'https://r10/', 3600);
        expect(record.realms).toHaveLength(20);
        expect(record.realms[19]).toBe('https://r10/');
        expect(record.realms.filter((r) => r === 'https://r10/')).toHaveLength(1);
    });

    test('no nameID gives no identity', () => {
        expect(ssoRecord.identity({ realms: [] })).toBeNull();
        expect(ssoRecord.identity(null)).toBeNull();
    });

    test('readCookie finds one cookie in the header', () => {
        expect(ssoRecord.readCookie({ headers: { cookie: 'a=1; wsfed_sso=abc; b=2' } }, 'wsfed_sso')).toBe('abc');
        expect(ssoRecord.readCookie({ headers: {} }, 'wsfed_sso')).toBeUndefined();
    });
});

describe('pendingLogout (node-saml InMemoryCacheProvider)', () => {
    afterEach(() => jest.useRealTimers());

    test('each ID works one time', async () => {
        const id = await pendingLogout.put({ a: 1 });
        expect(id).toMatch(/^[0-9a-f]{32}$/);
        expect(await pendingLogout.take(id)).toEqual({ a: 1 });
        expect(await pendingLogout.take(id)).toBeUndefined();
    });

    test('unknown or non-string IDs give nothing', async () => {
        expect(await pendingLogout.take('f'.repeat(32))).toBeUndefined();
        expect(await pendingLogout.take(['x'])).toBeUndefined();
        expect(await pendingLogout.take(undefined)).toBeUndefined();
    });

    test('two concurrent takes of the same ID: only one gets the value', async () => {
        const id = await pendingLogout.put({ wreply: 'https://exchange.corp/' });
        const results = await Promise.all([pendingLogout.take(id), pendingLogout.take(id)]);
        expect(results.filter((r) => r !== undefined)).toEqual([{ wreply: 'https://exchange.corp/' }]);
    });

    test('an ID expires after 10 minutes', async () => {
        jest.useFakeTimers({ now: Date.now() });
        const id = await pendingLogout.put('v');
        jest.setSystemTime(Date.now() + 10 * 60 * 1000);
        expect(await pendingLogout.take(id)).toBeUndefined();
    });
});
