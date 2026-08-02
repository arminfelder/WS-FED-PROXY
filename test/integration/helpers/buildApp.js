/**
 * Builds a minimal Express app suitable for route integration tests.
 *
 * Avoids loading app.js directly because that reads certificate files from
 * disk at require-time (passport-saml strategy). Instead we mount the real
 * route modules on a fresh Express instance with controllable settings.
 */

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { hppPrevent } = require('hpp-prevent');
const { parseAllowedRealms } = require('../../../util/validateRedirect');

/**
 * @param {object} opts
 * @param {string}   [opts.SAML2_ROOT='/saml2']
 * @param {string}   [opts.WSFED_ROOT='/wsfed']
 * @param {string}   [opts.WSFED_ISSUER='https://proxy.example.com/wsfed']
 * @param {string}   [opts.WSFED_CERT='exchange.crt']
 * @param {string}   [opts.WSFED_KEY='exchange.key']
 * @param {string}   [opts.WSFED_PKCS7='exchange.p7b']
 * @param {string}   [opts.INVALID_LOGIN_REDIRECT='']
 * @param {string}   [opts.WSFED_ALLOWED_REALMS='']  comma-separated
 * @param {boolean}  [opts.authenticated=false]  pre-populate session with a user
 * @param {object}   [opts.sessionWsfedArgs]  pre-populate wsfed_args in session
 */
function buildApp(opts = {}) {
    const app = express();

    app.set('SAML2_ROOT', opts.SAML2_ROOT || '/saml2');
    app.set('WSFED_ROOT', opts.WSFED_ROOT || '/wsfed');
    app.set('WSFED_ISSUER', opts.WSFED_ISSUER || 'https://proxy.example.com/wsfed');
    app.set('WSFED_CERT', opts.WSFED_CERT || 'exchange.crt');
    app.set('WSFED_KEY', opts.WSFED_KEY || 'exchange.key');
    app.set('WSFED_PKCS7', opts.WSFED_PKCS7 || 'exchange.p7b');
    app.set('INVALID_LOGIN_REDIRECT', opts.INVALID_LOGIN_REDIRECT || '');
    app.set('WSFED_ALLOWED_REALMS', parseAllowedRealms(opts.WSFED_ALLOWED_REALMS || ''));

    // same order as app.js: hppPrevent must run after the body parsers
    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());
    app.use(hppPrevent());

    app.use(session({
        secret: 'test-secret',
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false },
    }));

    // Stub passport so we can control isAuthenticated() without a real SAML strategy.
    // isAuthenticated/logout mirror what passport.initialize() provides in app.js.
    let authenticated = !!opts.authenticated;
    app.use((req, res, next) => {
        req.isAuthenticated = () => authenticated;
        req.logout = (cb) => { authenticated = false; delete req.user; cb(); };
        if (authenticated) {
            req.user = { id: 'testuser', upn: 'testuser@example.com', sid: 'S-1-5-21-1' };
        }
        if (opts.sessionWsfedArgs) {
            req.session.wsfed_args = opts.sessionWsfedArgs;
        }
        next();
    });

    const wsfedRouter = require('../../../routes/wsfed');
    const saml2Router = require('../../../routes/saml2');

    app.use(app.get('SAML2_ROOT'), saml2Router);
    app.use(app.get('WSFED_ROOT'), wsfedRouter);

    return app;
}

module.exports = buildApp;
