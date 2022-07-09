const express = require('express');
const wsfed = require("wsfed");
const fs = require("fs");
const path = require("path");
const profileMapper = require("../util/OWAProfileMapper");
const router = express.Router();



router.get('/',(req,res,next)=>{
    if(req.query.hasOwnProperty("wa")&& req.query.wa === "wsignout1.0") {
        res.redirect("/saml2/logout");
    }
    else if(req.isAuthenticated()){
        const sessData = req.session;
        req.query = sessData.wsfed_args

        next();
    }else {
        const sessData = req.session;
        sessData.wsfed_args = Object.assign({},req.query);
        req.session.save();
        res.redirect("/saml2/login");
    }
},(req,res,next)=>{
   return wsfed.auth({
    issuer:     req.app.get("WSFED_ISSUER"),
    cert:       fs.readFileSync(path.join(__dirname, '../certs', req.app.get("WSFED_CERT"))),
    key:        fs.readFileSync(path.join(__dirname, '../certs', req.app.get("WSFED_KEY"))),
    profileMapper: profileMapper,
    getPostURL: function (wtrealm, wreply, req, callback) {
        req.session.destroy();
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
