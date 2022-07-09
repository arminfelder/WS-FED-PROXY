const express = require('express');
const passport = require("passport");
const bodyParser = require("express");
const samlStrategy = require('passport-saml').Strategy;
const router = express.Router();

router.get('/login',passport.authenticate("saml",{
    failureRedirect: "/saml2/failure"
}));

router.get('/logout',function (req, res, next){
    req.user = {};
    next();
},function(req,res){
    passport._strategy('saml').logout(req, function(err, requestUrl) {
        // LOCAL logout
        req.logout(function(err) {
            if (err) { return next(err); }
            res.redirect(requestUrl);
        });
        // redirect to the IdP with the encrypted SAML logout request

    });
   // res.send("logout");
});

router.get('/failure',function(req, res, next) {
    res.code()
});


router.get('/callback',function(req, res, next) {
    const xmlResponse = req.body.SAMLResponse;
    const parser = new Saml2js(xmlResponse);
    req.samlUserObject = parser.toObject();
    next();
    res.redirect("/wsfed");
});

router.post('/callback',
        passport.authenticate("saml", { failureRedirect: "/", failureFlash: true, keepSessionInfo: true
}),
        function (req, res) {
            res.redirect("/wsfed");
        }
);



module.exports = router;
