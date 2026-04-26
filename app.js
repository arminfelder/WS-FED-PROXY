/*
Copyright (C) ws-fed proxy  Armin Felder

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

const createError = require('http-errors');
const express = require('express');
const path = require('path');
const { formatHttpRequest, formatHttpResponse, formatError } = require('@elastic/ecs-helpers');
const crypto_internal = require('crypto');
const sidConverter = require('security-identifier');
const session = require('express-session');
const MemoryStore = require('memorystore')(session)
const wsfed = require("wsfed");
const fs = require("fs");
const crypto = require('crypto');
const passport = require('passport');
const SamlStrategy = require('@node-saml/passport-saml').Strategy;
const { ValidateInResponseTo } = require('@node-saml/passport-saml');
const helmet = require('helmet');
const { hppPrevent } = require('hpp-prevent');
const rateLimit = require('express-rate-limit');
const { parseAllowedRealms } = require('./util/validateRedirect');

const app = express();

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'none'"],
        scriptSrc:  ["'unsafe-inline'", "'unsafe-eval'"],
        // Allow the form POST to any HTTPS target — the allowlist in validateRedirect.js
        // enforces the actual destination; CSP here just blocks non-HTTPS targets.
        formAction: ["https:"],
    },
}));
app.use(helmet.crossOriginEmbedderPolicy());
app.use(helmet.crossOriginOpenerPolicy());
app.use(helmet.crossOriginResourcePolicy());
app.use(helmet.dnsPrefetchControl());
app.use(helmet.frameguard());
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts());
app.use(helmet.ieNoOpen());
app.use(helmet.noSniff());
app.use(helmet.originAgentCluster());
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.referrerPolicy({ policy: 'origin-when-cross-origin' }));
app.use(helmet.xssFilter());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

const saml2Router = require('./routes/saml2');
const wsfedRouter = require('./routes/wsfed');

(function () {
    app.set("SESSION_SECRET",process.env.SESSION_SECRET || crypto.randomBytes(120).toString('hex'));
    app.set("SAML2_ISSUER",process.env.SAML2_ISSUER || 'passport-js');
    app.set("SAML2_IDENTIFIER_FORMAT",process.env.SAML2_IDENTIFIER_FORMAT || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    app.set("SAML2_IDP",process.env.SAML2_IDP || 'https://localhost:8443/auth/realms/master/protocol/saml');
    app.set("SAML2_CLAIMS_UPN",process.env.SAML2_CLAIMS_UPN || "upn");
    app.set("SAML2_CLAIMS_SID", process.env.SAML2_CLAIMS_SID || "sid");
    app.set("SAML2_CLAIMS_SID_BASE64", process.env.SAML2_CLAIMS_SID_BASE64 || "true" )
    app.set("SAML2_IDP_PUB_KEY", process.env.SAML2_IDP_PUB_KEY || "idp.pem");
    app.set("SAML2_ROOT", process.env.SAML2_ROOT || "/saml2");
    app.set("WSFED_ISSUER", process.env.WSFED_ISSUER || "https://localhost:3000/wsfed");
    app.set("WSFED_CERT", process.env.WSFED_CERT || "exchange.crt");
    app.set("WSFED_KEY", process.env.WSFED_KEY || "exchange.key");
    app.set("WSFED_PKCS7", process.env.WSFED_PKCS7 || "exchange.p7b");
    app.set("WSFED_ROOT", process.env.WSFED_ROOT || "/wsfed");
    app.set("INVALID_LOGIN_REDIRECT", process.env.INVALID_LOGIN_REDIRECT || "");
    app.set("TRUST_PROXY", (process.env.TRUST_PROXY || "false").toLowerCase() === "true" );
    app.set("WSFED_ALLOWED_REALMS", parseAllowedRealms(process.env.WSFED_ALLOWED_REALMS || ""));
    app.set("SESSION_MAX_STORE", parseInt(process.env.SESSION_MAX_STORE || "500", 10));
    app.set("SAML2_WANT_ASSERTIONS_SIGNED", (process.env.SAML2_WANT_ASSERTIONS_SIGNED || "true").toLowerCase() !== "false");

    if (process.env.NODE_ENV === 'production') {
        const issuer = app.get("WSFED_ISSUER");
        if (issuer.includes('localhost')) {
            console.error('FATAL: WSFED_ISSUER contains "localhost" in a production environment. Set WSFED_ISSUER to the public proxy URL.');
            process.exit(1);
        }
    }
})();

// Assign a unique request ID used in both the access log and error/warn log
app.use(function assignRequestId(req, _res, next) {
  req.requestId = crypto_internal.randomUUID();
  next();
});

app.use(function ecsAccessLog(req, res, next) {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const rec = {
      '@timestamp':        new Date().toISOString(),
      'log.level':         'info',
      message:             'access_log',
      'http.request.id':   req.requestId,
      'event.duration':    Number(process.hrtime.bigint() - start), // nanoseconds (ECS)
      'ecs.version':       '1.6.0',
    };
    formatHttpRequest(rec, req);
    formatHttpResponse(rec, res);
    process.stdout.write(JSON.stringify(rec) + '\n');
  });
  next();
});

// HTTP Parameter Pollution prevention — must come before body/query parsing is used by routes
app.use(hppPrevent());

// Rate limiting — tight on the SAML callback (CPU-intensive XML verify), broad elsewhere
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
});
const callbackLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);
app.use(app.get("SAML2_ROOT") + '/callback', callbackLimiter);

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

app.use(session({
    proxy: app.get("TRUST_PROXY"),
    cookie: {
        maxAge: 600000,
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        domain: new URL(app.get("WSFED_ISSUER")).hostname
    },
    saveUninitialized: false,
    store: new MemoryStore({
        checkPeriod: 60000,
        max: app.get("SESSION_MAX_STORE"),
    }),
    resave: false,
    secret: app.get("SESSION_SECRET")
}));

app.use(passport.initialize());
app.use(passport.session({
    keepSessionInfo: false
}));
app.use(express.static(path.join(__dirname, 'public')));

app.use(app.get("SAML2_ROOT"), saml2Router);
app.use(app.get("WSFED_ROOT"), wsfedRouter);



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler — log full details server-side, never expose them to the client
app.use(function(err, req, res, next) {
  const status = err.status || 500;
  const rec = {
    '@timestamp': new Date().toISOString(),
    'log.level':  status >= 500 ? 'error' : 'warn',
    message:      err.message,
    'http.request.id':           req.requestId,
    'http.request.method':       req.method,
    'url.path':                  req.url,
    'http.response.status_code': status,
    'client.ip':                 req.ip,
    'user_agent.original':       req.get('user-agent'),
    'http.version':              req.httpVersion,
    'ecs.version': '1.6.0',
  };
  if (status >= 500) formatError(rec, err);
  process.stdout.write(JSON.stringify(rec) + '\n');
  res.status(status);
  res.locals.statusCode = status;
  res.locals.statusMessage = status === 404 ? 'Not Found' : 'Internal Server Error';
  res.render('error');
});



passport.use(new SamlStrategy(
    {
      callbackUrl:  "https://" + new URL(app.get("WSFED_ISSUER")).host + app.get("SAML2_ROOT") + "/callback",
      path: app.get("SAML2_ROOT") + '/callback',
      protocol: "https",
      entryPoint: app.get("SAML2_IDP"),
      issuer: app.get("SAML2_ISSUER"),
      wantAssertionsSigned: app.get("SAML2_WANT_ASSERTIONS_SIGNED"),
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: 3600000,
      identifierFormat: app.get("SAML2_IDENTIFIER_FORMAT"),
      idpCert: fs.readFileSync(path.join(__dirname, "./certs" ,app.get("SAML2_IDP_PUB_KEY")), { encoding: 'utf8' }), // cert must be provided
    },
    function(profile, done) {
        const user = {};
        user.id = profile["nameID"];
        user.upn = profile[app.get("SAML2_CLAIMS_UPN")];
        user.nameID = profile["nameID"];
        user.nameIDFormat = profile["nameIDFormat"];
        if(profile.hasOwnProperty(app.get("SAML2_CLAIMS_SID"))){
            let sid = "";
            if(app.get("SAML2_CLAIMS_SID_BASE64").toLowerCase() === "true"){
                const sid_binary = Buffer.from(profile[app.get("SAML2_CLAIMS_SID")], 'base64');
                sid = sidConverter.sidBufferToString(sid_binary)
            }else {
                sid = profile[app.get("SAML2_CLAIMS_SID")]
            }
            user.sid =  sid;
        }


        return done(null, user);
    },function (profile, done) {
        // for logout
        const user = {};
        user.id = profile["nameID"];
        user.nameID = profile["nameID"];
        user.nameIDFormat = profile["nameIDFormat"];
        return done(null, user);
    })
);

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});




module.exports = app;
