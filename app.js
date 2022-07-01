const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

const session = require('express-session');
const MemoryStore = require('memorystore')(session)
const wsfed = require("wsfed");
const fs = require("fs");
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

const saml2Router = require('./routes/saml2');
const wsfedRouter = require('./routes/wsfed');
const bodyParser = require("express");

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }))

app.use(session({
    saveUninitialized: true,
    store: new MemoryStore({
        checkPeriod: 86400000 // prune expired entries every 24h
    }),
    resave: false,
    secret: 'bla bla bla'
}));

app.use(passport.initialize());
app.use(passport.session({
    keepSessionInfo: true
}));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/saml2', saml2Router);
app.use('/wsfed', wsfedRouter);



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

(function () {
    app.set("SAML2_ISSUER",process.env.SAML2_ISSUER || 'passport-js');
    app.set("SAML2_IDENTIFIER_FORMAT",process.env.SAML2_IDENTIFIER_FORMAT || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    app.set("SAML2_IDP",process.env.SAML2_IDP || 'https://localhost:8443/auht/realms/master/protocol/saml');
    app.set("SAML2_CLAIMS_UPN",process.env.SAML2_CLAIMS_UPN || "urn:oid:1.2.840.113549.1.9.1");
    app.set("SAML2_CLAIMS_SID", process.env.SAML2_CLAIMS_SID || "sid");
    app.set("SAML2_CLAIMS_SID_BASE64", process.env.SAML2_CLAIMS_SID_BASE64 || "true" )
    app.set("SAML2_IDP_PUB_KEY", process.env.SAML2_IDP_PUB_KEY || "idp.pem");
    app.set("WSFED_ISSUER", process.env.WSFED_ISSUER || "https://localhost:3000/wsfed");
    app.set("WSFED_CERT", process.env.WSFED_CERT || "exchange.crt");
    app.set("WSFED_KEY", process.env.WSFED_KEY || "exchange.key");
    app.set("WSFED_PKCS7", process.env.WSFED_PKCS7 || "exchange.p7b");
})();

passport.use(new SamlStrategy(
    {
      path: '/saml2/callback',
      protocol: "https",
      entryPoint: app.get("SAML2_IDP"),
      issuer: app.get("SAML2_ISSUER"),
      identifierFormat: app.get("SAML2_IDENTIFIER_FORMAT"),
      cert: fs.readFileSync(path.join(__dirname, "./certs" ,app.get("SAML2_IDP_PUB_KEY")), { encoding: 'utf8' }), // cert must be provided
    },
    function(profile, done) {
        const user = {};
        user.id = profile["nameID"];
        user.upn = profile[app.get("SAML2_CLAIMS_UPN")];

        if(profile.hasOwnProperty(app.get("SAML2_CLAIMS_SID"))){
            let sid = "";
            if(app.get("SAML2_CLAIMS_SID_BASE64").toLowerCase() === "true"){
                sid = new Buffer(profile[app.get("SAML2_CLAIMS_SID")], 'base64')
            }else {
                sid = profile[app.get("SAML2_CLAIMS_SID")]
            }
            user.sid =  sid;
        }


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
