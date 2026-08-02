
# WSFED Proxy

A WS-Fed / SAML2 proxy that connects Outlook Web Access (OWA) to an arbitrary SAML2 IdP via the WS-Federation protocol used by ADFS.

## Configuration

All configuration is done via environment variables.

### Server

| Variable | Default | Description |
|---|---|---|
| `HTTPS` | — | Set to `true` to enable HTTPS on the Node server directly |
| `HTTPS_KEY` | `../selfsigned.key` | Path to the TLS private key (relative to `bin/`) |
| `HTTPS_CERT` | `../selfsigned.crt` | Path to the TLS certificate (relative to `bin/`) |
| `PORT` | `3000` | Listening port |
| `TRUST_PROXY` | `false` | Set to `true` when running behind a reverse proxy (sets `X-Forwarded-*` trust) |
| `SESSION_SECRET` | random | Secret used to sign the session cookie. **Must be set to a stable secret in production.** |
| `SESSION_MAX_STORE` | `500` | Maximum number of concurrent sessions held in memory. Prevents unbounded memory growth. |
| `INVALID_LOGIN_REDIRECT` | — | URL to redirect to when a request arrives at `/wsfed` with no valid WS-Fed parameters. Returns `400` if unset. |
| `NODE_ENV` | — | Set to `production` to enable production guards (e.g. fatal startup error if `WSFED_ISSUER` contains `localhost`) |

### WS-Federation

| Variable | Default | Description |
|---|---|---|
| `WSFED_ISSUER` | `https://localhost:3000/wsfed` | Full URI of this proxy's WS-Fed endpoint. Must match `AdfsIssuer` configured in Exchange. **Required in production.** |
| `WSFED_CERT` | `exchange.crt` | Filename of the signing certificate (PEM), relative to `certs/` |
| `WSFED_KEY` | `exchange.key` | Filename of the signing private key (PEM), relative to `certs/` |
| `WSFED_PKCS7` | `exchange.p7b` | Filename of the signing certificate in PKCS#7 format, relative to `certs/`. Used by the ADFS SOAP metadata endpoint. |
| `WSFED_ROOT` | `/wsfed` | URL path prefix for WS-Fed endpoints |
| `WSFED_TOKEN_LIFETIME` | `600` | Lifetime in seconds of the issued WS-Fed token. This is the only credential that outlives the session (destroyed as soon as the token is issued), so it is deliberately short. |
| `WSFED_ALLOWED_REALMS` | — | Comma-separated list of allowed `wtrealm` URLs (e.g. `https://exchange.corp/owa/,https://exchange.corp/ecp/`). When set, any `wtrealm` or `wreply` whose origin is not in this list is rejected with `403`. When unset, `wreply` must share the same origin as `wtrealm` (same-origin fallback). |

### SAML2

| Variable | Default | Description |
|---|---|---|
| `SAML2_IDP` | `https://localhost:8443/auth/realms/master/protocol/saml` | Entry point URL of the SAML2 IdP |
| `SAML2_IDP_PUB_KEY` | `idp.pem` | Filename of the IdP's public key/certificate (PEM), relative to `certs/` |
| `SAML2_ISSUER` | `passport-js` | SAML2 `Issuer` sent in the `AuthnRequest` to the IdP |
| `SAML2_IDENTIFIER_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | NameID format requested from the IdP |
| `SAML2_CLAIMS_UPN` | `upn` | Name of the SAML2 attribute holding the User Principal Name |
| `SAML2_CLAIMS_SID` | `sid` | Name of the SAML2 attribute holding the Windows SID |
| `SAML2_CLAIMS_SID_BASE64` | `true` | Set to `false` if the IdP sends the SID as a plain string rather than base64-encoded binary |
| `SAML2_ROOT` | `/saml2` | URL path prefix for SAML2 endpoints |
| `SAML2_WANT_ASSERTIONS_SIGNED` | `true` | Require individual SAML assertions to be signed in addition to the response envelope. Set to `false` only if your IdP signs the response but not individual assertions. |

## Endpoints

| Path | Description |
|---|---|
| `{WSFED_ROOT}` | WS-Fed passive sign-in / sign-out entry point |
| `{WSFED_ROOT}/FederationMetadata/2007-06/FederationMetadata.xml` | WS-Fed metadata document (used by Exchange for discovery) |
| `{WSFED_ROOT}/adfs/fs/federationserverservice.asmx` | ADFS SOAP endpoint (returns signing cert thumbprint to Exchange) |
| `{SAML2_ROOT}/login` | Initiates SAML2 authentication |
| `{SAML2_ROOT}/callback` | SAML2 assertion consumer (POST binding) |
| `{SAML2_ROOT}/logout` | Initiates SAML2 logout. Reachable only via `{WSFED_ROOT}?wa=wsignout1.0`, which sets a single-use session flag; a direct or cross-origin request returns `403` so a third-party page cannot force a single logout. |

## Logging

All log output is written to **stdout** as ECS-compliant JSON, suitable for ingestion by Elastic/Kibana or any JSON log shipper.

Every log line contains `http.request.id` — a UUID generated per request. Use it to correlate access log entries with error/warning entries for the same request:

```
# access log entry
{"@timestamp":"…","log.level":"info","message":"access_log","http.request.id":"a1b2c3d4-…",…}

# error log entry for the same request
{"@timestamp":"…","log.level":"warn","message":"wtrealm not in allowlist: …","http.request.id":"a1b2c3d4-…",…}
```

Log levels:
- `info` — every completed request (access log)
- `warn` — client errors (4xx) with the reason
- `error` — server errors (5xx) with full stack trace

## Examples

### Authenticate Exchange OWA with Keycloak

#### Configure Keycloak

1. Ensure SID and UPN are available as user attributes
2. Create a SAML2 client (e.g. `wsfed-proxy`)
3. Add attribute mappers: `upn` → `upn`, `sid` → `sid`

#### Generate a signing certificate

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout signing_cert.key \
  -out signing_cert.csr -subj "/CN=mycorp"
openssl x509 -signkey signing_cert.key -in signing_cert.csr -req \
  -days 365 -out signing_cert.crt
openssl crl2pkcs7 -nocrl -certfile signing_cert.crt -out signing_cert.p7b
```

#### Configure Exchange

1. Install the signing certificate into the Trusted People store on Exchange.

2. Get the certificate thumbprint:
```bash
cut -d= -f2 <<< $(openssl x509 -noout -fingerprint -sha1 -inform pem -in signing_cert.crt) | tr -d ":"
```

3. Configure Exchange for ADFS authentication:
```powershell
$issuer = "<value of WSFED_ISSUER>"
$cert   = "<thumbprint from step 2>"

Set-OrganizationConfig `
  -AdfsIssuer $issuer `
  -AdfsAudienceUris "https://<exchange>/owa/","https://<exchange>/ecp/" `
  -AdfsSignCertificateThumbprint $cert

Get-EcpVirtualDirectory | Set-EcpVirtualDirectory `
  -AdfsAuthentication $true -BasicAuthentication $false `
  -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false

Get-OwaVirtualDirectory | Set-OwaVirtualDirectory `
  -AdfsAuthentication $true -BasicAuthentication $false `
  -DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false
```

> **Note:** `AdfsAudienceUris` must exactly match the `wtrealm` value OWA sends, which is derived from the URL the user uses to access OWA. If users access OWA via multiple hostnames, add all of them.

#### Debugging WS-Fed authentication with Exchange

Add to `web.config` on the Exchange front-end (e.g. `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\web.config`):

```xml
<system.diagnostics>
  <sources>
    <source name="Microsoft.IdentityModel" switchValue="Warning">
      <listeners>
        <add name="traceListener"
             type="System.Diagnostics.XmlWriterTraceListener"
             initializeData="C:\logs\WIFTrace.log" />
      </listeners>
    </source>
  </sources>
</system.diagnostics>
```
