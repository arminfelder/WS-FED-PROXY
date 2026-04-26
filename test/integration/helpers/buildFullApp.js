/**
 * Sets env vars and clears the module cache so app.js can be required fresh.
 * The caller is responsible for mocking fs to redirect cert reads to fixtures.
 */
function buildFullApp() {
    Object.keys(require.cache).forEach(k => {
        if (k.includes('ws-fed-proxy') && !k.includes('node_modules') && !k.includes('test')) {
            delete require.cache[k];
        }
    });

    process.env.WSFED_ISSUER      = 'https://proxy.example.com/wsfed';
    process.env.WSFED_CERT        = 'test-cert.pem';
    process.env.WSFED_KEY         = 'test-cert.key';
    process.env.WSFED_PKCS7       = 'test-cert.pem';
    process.env.SAML2_IDP_PUB_KEY = 'idp.pem';
    process.env.SAML2_IDP         = 'https://idp.example.com/saml';
    process.env.SAML2_ROOT        = '/saml2';
    process.env.WSFED_ROOT        = '/wsfed';

    return require('../../../app');
}

module.exports = buildFullApp;
