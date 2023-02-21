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

const express = require('express');
const passport = require("passport");
const bodyParser = require("express");
const samlStrategy = require('@node-saml/passport-saml').Strategy;
const router = express.Router();

router.get('/login',function(req, res, next) {
    passport.authenticate("saml",{
        failureRedirect: req.app.get("SAML2_ROOT") + "/failure"
})(req, res, next)});

router.get('/logout',function (req, res, next){
    // we need an user object for passport-saml, to create the LogoutRequest
    req.user = {};
    next();
},function(req,res){
    passport._strategy('saml').logout(req, function(err, requestUrl) {
        // LOCAL logout
        req.logout(function(err) {
            if (err) { return next(err); }
            req.session.destroy(function (err){
                if(err){
                    console.log(err)
                }
            });
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
    res.redirect(req.app.get("WSFED_ROOT"));
});

router.post('/callback', function (req, res, next) {
        passport.authenticate("saml", { failureRedirect: req.app.get("SAML2_ROOT") + "/", failureFlash: true, keepSessionInfo: true
})(req, res, next)},
        function (req, res) {
            res.redirect(req.app.get("WSFED_ROOT"));
        }
);



module.exports = router;
