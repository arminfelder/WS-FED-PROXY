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
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const ecsFormat = require('@elastic/ecs-morgan-format')
const sidConverter = require('security-identifier');
const session = require('express-session');
const MemoryStore = require('memorystore')(session)
const wsfed = require("wsfed");
const fs = require("fs");
const crypto = require('crypto');
const passport = require('passport');
const SamlStrategy = require('@node-saml/passport-saml').Strategy;

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

const saml2Router = require('./routes/saml2');
const wsfedRouter = require('./routes/wsfed');
const bodyParser = require("express");

(function () {
    app.set("SESSION_SECRET",process.env.SESSION_SECRET || crypto.randomBytes(120).toString('hex'));
    app.set("SAML2_ISSUER",process.env.SAML2_ISSUER || 'passport-js');
    app.set("SAML2_IDENTIFIER_FORMAT",process.env.SAML2_IDENTIFIER_FORMAT || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    app.set("SAML2_IDP",process.env.SAML2_IDP || 'https://localhost:8443/auht/realms/master/protocol/saml');
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
})();

app.use(logger(ecsFormat()));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }))

app.use(session({
    cookie: {
        maxAge: 600000
    },
    saveUninitialized: false,
    store: new MemoryStore({
        checkPeriod: 60000 // prune expired entries every 1m
    }),
    resave: false,
    secret: app.get("SESSION_SECRET")
}));

app.use(passport.initialize());
app.use(passport.session({
    keepSessionInfo: true
}));
app.use(express.static(path.join(__dirname, 'public')));

app.use(app.get("SAML2_ROOT"), saml2Router);
app.use(app.get("WSFED_ROOT"), wsfedRouter);



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});



passport.use(new SamlStrategy(
    {
      path: app.get("SAML2_ROOT") + '/callback',
      protocol: "https",
      entryPoint: app.get("SAML2_IDP"),
      issuer: app.get("SAML2_ISSUER"),
      wantAssertionsSigned: false,
      identifierFormat: app.get("SAML2_IDENTIFIER_FORMAT"),
      cert: fs.readFileSync(path.join(__dirname, "./certs" ,app.get("SAML2_IDP_PUB_KEY")), { encoding: 'utf8' }), // cert must be provided
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
                const sid_binary = Buffer.from(new Buffer(profile[app.get("SAML2_CLAIMS_SID")], 'base64'), 'hex');
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
