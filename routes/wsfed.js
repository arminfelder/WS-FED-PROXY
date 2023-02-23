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
const wsfed = require("wsfed");
const fs = require("fs");
const path = require("path");
const profileMapper = require("../util/OWAProfileMapper");
const router = express.Router();



router.get('/',(req,res,next)=>{
    if(req.query.hasOwnProperty("wa")&& req.query.wa === "wsignout1.0") { // user requests a logout
        res.redirect(req.app.get("SAML2_ROOT") + "/logout");
    }else if(req.isAuthenticated() && req.session.hasOwnProperty("wsfed_args")){ // user has been authenticated and his session contains the required arguments for WSFED to proceed
        const sessData = req.session;
        req.query = sessData.wsfed_args
        next();
    }else if ( req.query.hasOwnProperty("wa") && req.query.hasOwnProperty("wtrealm") ){   // user does is not logged in and requests a login
        const sessData = req.session;
        sessData.wsfed_args = Object.assign({},req.query);
        req.session.save();
        res.redirect(req.app.get("SAML2_ROOT") + "/login");
    }else if(req.isAuthenticated()) { // user is authenticated, but now valid session data is present, destroy the session as it is not valid
        res.redirect(req.app.get("SAML2_ROOT") + "/logout");
    }else { // user is neither authenticated nor does he present valid WSFED arguments
        if (req.app.get("INVALID_LOGIN_REDIRECT") !== ""){
            res.redirect(303, req.app.get("INVALID_LOGIN_REDIRECT"))
        }else{
            res.sendStatus(400)
        }
    }
},(req,res,next)=>{
   return wsfed.auth({
    issuer:     req.app.get("WSFED_ISSUER"),
    cert:       fs.readFileSync(path.join(__dirname, '../certs', req.app.get("WSFED_CERT"))),
    key:        fs.readFileSync(path.join(__dirname, '../certs', req.app.get("WSFED_KEY"))),
    profileMapper: profileMapper,
    getPostURL: function (wtrealm, wreply, req, callback) {
        // immediately destroy the session data
        req.session.destroy(function (err){
            if(err){
                console.log(err)
            }
            res.clearCookie("connect.sid")
        });
        let redirectUrl = ""
        if(wreply === undefined) {
            redirectUrl = wtrealm;
        }else{
            redirectUrl = wreply;
        }
        return callback(null, redirectUrl)
    }
})(req,res,next)
});

router.get('/FederationMetadata/2007-06/FederationMetadata.xml', (req,res, next)=> {
    return wsfed.metadata({
        issuer: 'the-issuer',
        cert: fs.readFileSync(path.join(__dirname, '../certs/', req.app.get("WSFED_CERT"))),
    })(req, res)
});

router.get('/adfs/fs/federationserverservice.asmx',
    wsfed.federationServerService.wsdl);

router.post('/adfs/fs/federationserverservice.asmx',
    (req,res,next) => {
    return wsfed.federationServerService.thumbprint({
      pkcs7: fs.readFileSync(path.join(__dirname, '../certs/', req.app.get("WSFED_PKCS7"))),
      cert:  fs.readFileSync(path.join(__dirname, '../certs/', req.app.get("WSFED_CERT")))
    })(req, res)
});



module.exports = router;
