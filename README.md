Keycloak:

mapper:
ObjectSID(AD property) -> sid
upn -> upn



openssl req -new \
-newkey rsa:2048 -nodes -keyout signing_cert.key \
-out signing_cert.csr \
-subj "/CN=mycorp"

openssl x509 -signkey signing_cert.key -in cert_req.csr -req -days 365 -out signing_cert.crt -days 365

openssl crl2pkcs7 -nocrl -certfile signing_cert.crt -out signing_cert.p7b

cut -d "=" -f2  <<< $(openssl x509 -noout -fingerprint -sha1 -inform pem -in signing_cert.crt) | tr -d ":" 

or 

New-ExchangeCertificate -subjectname "CN=mycorp" -PrivateKeyExportable $true
openssl crl2pkcs7 -nocrl -certfile signing_cert.crt -out signing_cert.p7b



Exchange config

install signing cert into trsuted people store

$issuer = "http://armin-thinkpad-p50:3000/wsfed"
$audience = "https://localhost/owa/, https://localhost/ecp/"
$cert = '499FDF1C2218A99C8595AAC2FD95CE36F0A6D59D'

Set-OrganizationConfig -AdfsIssuer $issuer -AdfsAudienceUris $audience -AdfsSignCertificateThumbprint $cert

Get-EcpVirtualDirectory | Set-EcpVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false
Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false


Debugging

in C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\web.config

<system.diagnostics>
<sources>
<source name="Microsoft.IdentityModel" switchValue="Warning">
<listeners>
<add name="traceListener" type="System.Diagnostics.XmlWriterTraceListener" initializeData="c:\temp\WIFTrace.log" />
</listeners>
</source>
</sources>
</system.diagnostics>
