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
