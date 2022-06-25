
# WSFED Proxy

a simple WS-Fed SAML2 proxy, made to connect Outlook Web Access(OWA), to an arbitrary SAML2 IDP, via the WS-Fed Protocol
(http://docs.oasis-open.org/wsfed/federation/v1.2/ws-federation.html), used by ADFS

## configuration
configuration is done via, the following environment variables:

- SAML2_ISSUER (SAML2 issuer to be used by this SAML2 client)
- SAML2_IDENTIFIER_FORMAT (SAML2 identifier format set by the IDP)
- SAML2_IDP (address of the SAML2 IDP)
- SAML2_CLAIMS_UPN (name of the SAML2 claim holding the UPN)
- SAML2_CLAIMS_SID (name of the SAML2 claim holding the SID)
- SAML2_IDP_PUB_KEY (public key from the SAML2 IDP)
- WSFED_ISSUER (issuer to used in the assertion, has to be the URI to this Proxy including path to WS-Fed endpoint, e.g. https://ws-fed-proxy/wsfed)
- WSFED_CERT (path to PEM cert for signing the assertion)
- WSFED_KEY (path to KEY for WSFED_CERT)
- WSFED_PKCS7 (path to WSFED_CERT in PKCS7 format, for use with WSFED metadata.xml)



## endpoints

- /saml2/callback (callback for SAML2 login)
- /saml2/login (initiates SAML2 login)
- /saml2/logout (SAML2 logout) "not implemented yet"
- /wsfed (WS-Fed endpoint)
- /wsfed/FederationMetadata/2007-06/FederationMetadata.xml (metadata)
- /wsfed/adfs/fs/federationserverservice.asmx (metadata)

## examples

### authenticate Exchange OWA with Keycloak

#### configure Keycloak

1. make sure SID and UPN are available as user attributes
2. create a new SAML2 client e.g. "wsfed-proxy"
3. create a mapper for upn and sid e.g. sid -> sid, upn->upn

#### configure WS-Fed proxy

1. generate cert for signing assertions
e.g.
```bash
openssl req -new \
-newkey rsa:2048 -nodes -keyout signing_cert.key \
-out signing_cert.csr \
-subj "/CN=mycorp"
```
```bash
openssl x509 -signkey signing_cert.key -in cert_req.csr -req -days 365 -out signing_cert.crt -days 365
```
```bash
openssl crl2pkcs7 -nocrl -certfile signing_cert.crt -out signing_cert.p7b
```

or via Exchange
```PowerShell
New-ExchangeCertificate -subjectname "CN=mycorp" -PrivateKeyExportable $true
```

#### configure Exchange

1. install signing cert into trusted people store

2. get fingerprint from WS-Fed Proxy signing cert
```bash
cut -d "=" -f2  <<< $(openssl x509 -noout -fingerprint -sha1 -inform pem -in signing_cert.crt) | tr -d ":" 
```

2. configure Excnahge for ADFS
```PowerShell
$issuer = "<use value from WSFED_ISSUER>"
$cert = '<fingerprint from WS-Fed Proxy signing cert>'

Set-OrganizationConfig -AdfsIssuer $issuer -AdfsAudienceUris "https://<exchange URI>/owa/, https://<exchange URI>/ecp/" -AdfsSignCertificateThumbprint $cert

Get-EcpVirtualDirectory | Set-EcpVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false
Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false
```

#### debugging WS-Fed authmethod with Exchange

in OWA web.config e.g. (C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\web.config)
add
```xml
<system.diagnostics>
    <sources>
        <source name="Microsoft.IdentityModel" switchValue="Warning">
            <listeners>
                <add name="traceListener" type="System.Diagnostics.XmlWriterTraceListener" initializeData="<logpath>\WIFTrace.log" />
            </listeners>
        </source>
    </sources>
</system.diagnostics>
```






