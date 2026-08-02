const OWAProfileMapper = require('../../util/OWAProfileMapper');

const CLAIM_UPN = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn';
const CLAIM_SID = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid';
const CLAIM_NAME_ID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

describe('OWAProfileMapper', () => {
    const user = { id: 'user@corp.example', upn: 'user@corp.example', sid: 'S-1-5-21-1234' };

    test('getClaims maps nameIdentifier', () => {
        const mapper = new OWAProfileMapper(user);
        expect(mapper.getClaims()[CLAIM_NAME_ID]).toBe(user.id);
    });

    test('getClaims maps UPN to the correct WS-Fed claim URI', () => {
        const mapper = new OWAProfileMapper(user);
        expect(mapper.getClaims()[CLAIM_UPN]).toBe(user.upn);
    });

    test('getClaims maps SID to the correct WS-Fed claim URI', () => {
        const mapper = new OWAProfileMapper(user);
        expect(mapper.getClaims()[CLAIM_SID]).toBe(user.sid);
    });

    test('getNameIdentifier returns nameIdentifier matching user id', () => {
        const mapper = new OWAProfileMapper(user);
        expect(mapper.getNameIdentifier().nameIdentifier).toBe(user.id);
    });

    test('metadata declares required UPN and SID claim types', () => {
        const ids = OWAProfileMapper.prototype.metadata.map(m => m.id);
        expect(ids).toContain(CLAIM_UPN);
        expect(ids).toContain(CLAIM_SID);
    });

    test('can be called without new', () => {
        const mapper = OWAProfileMapper(user);
        expect(mapper.getClaims()[CLAIM_UPN]).toBe(user.upn);
    });
});
