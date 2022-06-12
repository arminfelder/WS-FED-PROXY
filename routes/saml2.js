var express = require('express');
const passport = require("passport");
const bodyParser = require("express");
var router = express.Router();

router.get('/login',passport.authenticate("saml",{
    failureRedirect: "/saml2/failure"
}));

router.get('/logout',function(req,res){
    res.send("logout");
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
