const fs = require('fs');
const path = require('path');
const { readSigningFiles } = require('../../util/signingFiles');

const FIXTURES = path.join(__dirname, '../fixtures');
const NAMES = { cert: 'test-cert.pem', key: 'test-cert.key', pkcs7: 'test-cert.pem' };

describe('readSigningFiles', () => {
    test('returns the three files as buffers', () => {
        const files = readSigningFiles(FIXTURES, NAMES);
        expect(files.cert.equals(fs.readFileSync(path.join(FIXTURES, 'test-cert.pem')))).toBe(true);
        expect(files.key.equals(fs.readFileSync(path.join(FIXTURES, 'test-cert.key')))).toBe(true);
        expect(files.pkcs7.equals(files.cert)).toBe(true);
    });

    test.each(['cert', 'key', 'pkcs7'])('throws with the file name when the %s file is missing', (which) => {
        const names = { ...NAMES, [which]: 'missing.pem' };
        expect(() => readSigningFiles(FIXTURES, names)).toThrow(/missing\.pem/);
    });
});
