const { sidBufferToString } = require('../../util/sid');

// MS-DTYP 2.4.2.2 encoder, for the test fixtures only
function encode(revision, authority, subAuthorities) {
    const buf = Buffer.alloc(8 + 4 * subAuthorities.length);
    buf[0] = revision;
    buf[1] = subAuthorities.length;
    buf.writeUIntBE(authority, 2, 6);
    subAuthorities.forEach((s, i) => buf.writeUInt32LE(s, 8 + 4 * i));
    return buf;
}

describe('sidBufferToString', () => {
    test('decodes a domain SID', () => {
        expect(sidBufferToString(encode(1, 5, [21, 1004336348, 1177238915, 682003330, 512])))
            .toBe('S-1-5-21-1004336348-1177238915-682003330-512');
    });

    test('decodes the well-known Local System SID', () => {
        expect(sidBufferToString(encode(1, 5, [18]))).toBe('S-1-5-18');
    });

    test('renders an identifier authority of 2^32 or more in hex', () => {
        expect(sidBufferToString(encode(1, 0x010000000001, [7]))).toBe('S-1-0x010000000001-7');
    });

    test('accepts 15 sub-authorities', () => {
        const subs = Array.from({ length: 15 }, (_v, i) => i + 1);
        expect(sidBufferToString(encode(1, 5, subs))).toBe('S-1-5-' + subs.join('-'));
    });

    test.each([
        ['shorter than the header', Buffer.from([1, 1, 0]), /too short/],
        ['revision 2', encode(2, 5, [18]), /revision/],
        ['16 sub-authorities', encode(1, 5, Array(16).fill(1)), /1 to 15 sub-authorities/],
        ['a count beyond the buffer', Buffer.from([1, 5, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]), /length/],
        ['no sub-authority', Buffer.from([1, 0, 0, 0, 0, 0, 0, 5]), /sub-authorit/],
        ['trailing bytes', Buffer.concat([encode(1, 5, [18]), Buffer.from([0])]), /length/],
    ])('refuses a buffer that is %s', (_label, buf, message) => {
        expect(() => sidBufferToString(buf)).toThrow(message);
    });
});
