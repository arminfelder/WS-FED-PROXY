
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
| `TRUST_PROXY` | `0` | **Number of reverse-proxy hops** in front of the app. Drives Express' `trust proxy`, so `req.ip`, the rate limiters and the secure-cookie check read the real client. `0` trusts nothing; use `1` behind a single nginx. The legacy values `true`/`false` are still accepted and mean `1`/`0`. The proxy must send `X-Forwarded-For` — otherwise every request appears to come from the proxy and the per-client rate limits collapse into one shared bucket. |
| `SESSION_SECRET` | random | Secret used to sign the session cookie. **Must be set to a stable secret in production.** |
| `SESSION_SAMESITE` | `none` | `SameSite` of the session cookie: `none`, `lax` or `strict`. Keep `none` when the IdP is on another site than this proxy (another registrable domain): the IdP's cross-site POST to `{SAML2_ROOT}/callback` then carries the session cookie. `lax` blocks that POST just like `strict`. `strict` works only with an IdP on the same site. With every value, `{SAML2_ROOT}/callback` accepts a response only with the `RelayState` of a sign-in that the same browser session started. Any other value stops the proxy at startup. |
| `SESSION_MAX_STORE` | `500` | Maximum number of concurrent sessions held in memory. Prevents unbounded memory growth. |
| `INVALID_LOGIN_REDIRECT` | — | URL to redirect to when a request arrives at `/wsfed` with no valid WS-Fed parameters. Returns `400` if unset. |
| `NODE_ENV` | — | Set to `production` to enable production guards: fatal startup error if `WSFED_ISSUER` contains `localhost`, or if either SAML signature requirement has been disabled. |

### WS-Federation

| Variable | Default | Description |
|---|---|---|
| `WSFED_ISSUER` | `https://localhost:3000/wsfed` | Full URI of this proxy's WS-Fed endpoint. Must match `AdfsIssuer` configured in Exchange. **Required in production.** Browsers must reach the proxy at this host: the SAML callback URL is derived from it, and the session cookie (`__Host-sid`: Secure, host-only, no `Domain`) is set for the host that served the request. |
| `WSFED_CERT` | `exchange.crt` | Filename of the signing certificate (PEM), relative to `certs/` |
| `WSFED_KEY` | `exchange.key` | Filename of the signing private key (PEM), relative to `certs/` |
| `WSFED_PKCS7` | `exchange.p7b` | Filename of the signing certificate in PKCS#7 format, relative to `certs/`. Used by the ADFS SOAP metadata endpoint. |
| `WSFED_ROOT` | `/wsfed` | URL path prefix for WS-Fed endpoints |
| `WSFED_TOKEN_LIFETIME` | `600` | Maximum lifetime in seconds of the issued WS-Fed token. This is the only credential that outlives the session (destroyed as soon as the token is issued), so it is deliberately short. The actual lifetime is the smallest of this value, the `wfresh` request parameter (minutes), and the time left until the IdP session ends (`SessionNotOnOrAfter` in the SAML assertion). If the IdP session has ended, or its end time cannot be read, no token is issued (`403`). Every sign-in goes to the IdP; the IdP decides whether to prompt again, except for `wfresh=0`, which sends `ForceAuthn`. |
| `WSFED_ALLOWED_REALMS` | — | **Required.** Comma-separated list of allowed `wtrealm` URLs (e.g. `https://exchange.corp/owa/,https://exchange.corp/ecp/`). Any `wtrealm` or `wreply` whose origin is not in this list is rejected with `403`, and a `wreply` must also share the origin of its `wtrealm` (the token is issued for `wtrealm`; WS-Federation 1.2 §13.2.2 defines it as the realm whose URLs only the resource controls). Only the origin (scheme, host, port) is compared — the path is ignored. The `wreply` of `wsignoutcleanup1.0` has no `wtrealm` and is checked against the list only. The app **refuses to start** when this is empty: it is the only control over where the signed token is delivered, and there is no safe default. |

### SAML2

| Variable | Default | Description |
|---|---|---|
| `SAML2_IDP` | `https://localhost:8443/auth/realms/master/protocol/saml` | Entry point URL of the SAML2 IdP |
| `SAML2_IDP_PUB_KEY` | `idp.pem` | Filename of the IdP's public key/certificate (PEM), relative to `certs/` |
| `SAML2_ISSUER` | `passport-js` | SAML2 `Issuer` sent in the `AuthnRequest` to the IdP |
| `SAML2_IDENTIFIER_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | NameID format requested from the IdP |
| `SAML2_CLAIMS_UPN` | `upn` | Name of the SAML2 attribute holding the User Principal Name. **Required in every assertion**: Exchange claims-based authentication needs the UPN and primary SID claims ([Microsoft Learn](https://learn.microsoft.com/exchange/clients/outlook-on-the-web/ad-fs-claims-based-auth), step 4b). An assertion without it, with an empty value, or with more than one value (also across repeated `<Attribute>` elements) is refused (`/saml2/failure`, logged as `saml assertion rejected`). |
| `SAML2_CLAIMS_SID` | `sid` | Name of the SAML2 attribute holding the Windows SID. **Required**, like the UPN; the value must decode to a well-formed SID (`S-1-…`) or the assertion is refused. |
| `SAML2_CLAIMS_SID_BASE64` | `true` | `true` if the IdP sends the SID as base64-encoded binary, `false` if it sends the textual `S-1-…` form. Any other value stops the proxy at startup. |
| `SAML2_ROOT` | `/saml2` | URL path prefix for SAML2 endpoints |
| `SAML2_SLO` | `true` | SAML2 single logout. `true`: `wsignout1.0` also ends the IdP session, and a `LogoutRequest` from the IdP ends the local session and the RP sessions. `false`: `wsignout1.0` ends only the proxy session and the RP sessions (`wsignoutcleanup1.0`); the IdP session stays, so the next sign-in can complete without a password prompt. `{SAML2_ROOT}/logout/callback` then returns `404`. Any other value stops the proxy at startup. |
| `WSFED_SIGNOUT_CLEANUP` | `redirect` | How sign-out reaches the RPs with `wsignoutcleanup1.0`. `redirect`: the browser goes to each RP in turn with `wreply` set to `{WSFED_ROOT}/signout/continue`, then on to the next sign-out step. This is necessary when the RP is on another site than the proxy: OWA sets `FedAuth` without `SameSite`, so Chromium does not send it with a cross-site image request and OWA stays signed in (tested against Exchange 2016). `image`: one page loads all cleanup URLs as images; use it only for RPs that do not go back to `wreply`. Any other value stops the proxy at startup. |
| `WSFED_SSO_RECORD_MAX_AGE` | `28800` | Seconds (60–604800) the browser keeps the encrypted sign-out record (`__Host-wsfed_sso` cookie: the realms that got a token and the SAML NameID/SessionIndex). After that, `wsignout1.0` can no longer reach those RPs or the IdP session. The cookie is `SameSite=None` when `SESSION_SAMESITE=none` (a cross-site IdP posts its `LogoutRequest`), otherwise `Lax`. |
| `SAML2_AUDIENCE` | value of `SAML2_ISSUER` | Audience the IdP's assertion must be scoped to. |
| `SAML2_CLOCK_SKEW_MS` | `3000` | Tolerance for clock drift between the IdP and this proxy when checking assertion validity windows. |
| `SAML2_WANT_ASSERTIONS_SIGNED` | `true` | Require individual SAML assertions to be signed in addition to the response envelope. Set to `false` only if your IdP signs the response but not individual assertions. Cannot be disabled when `NODE_ENV=production`. |
| `SAML2_WANT_AUTHN_RESPONSE_SIGNED` | `true` | Require the SAML response envelope itself to be signed. Cannot be disabled when `NODE_ENV=production`. |

## Endpoints

| Path | Description |
|---|---|
| `{WSFED_ROOT}` | WS-Fed passive sign-in / sign-out entry point. `wsignout1.0` accepts an allowlisted `wreply`. Like AD FS, `wsignout1.0` has no confirmation step, so any website can sign a user out with a link (logout CSRF; it ends the session, it does not grant access). Checking the request origin is not possible because OWA sends no `Referer`. |
| `{WSFED_ROOT}/FederationMetadata/2007-06/FederationMetadata.xml` | WS-Fed metadata document (used by Exchange for discovery) |
| `{WSFED_ROOT}/adfs/fs/federationserverservice.asmx` | ADFS SOAP endpoint (returns signing cert thumbprint to Exchange) |
| `{SAML2_ROOT}/login` | Initiates SAML2 authentication. `{WSFED_ROOT}?wa=wsignin1.0` sends the AuthnRequest itself and does not pass through this path, because browsers omit SameSite=Strict cookies on a second hop of a redirect chain that started on another site. |
| `{SAML2_ROOT}/callback` | SAML2 assertion consumer (POST binding). A response must carry the `RelayState` that this proxy sent with the AuthnRequest of a sign-in in the same browser session; any other response is refused with `403`, so a response obtained by someone else cannot be injected into the session (login CSRF). Up to 5 sign-ins (for example browser tabs) can wait for the IdP at the same time, each with its own `wtrealm`. Only the redirect binding for the AuthnRequest is supported. It accepts a sign-in `SAMLResponse` only; a `LogoutRequest` or `LogoutResponse` posted here gets `400`, the IdP must send those to `{SAML2_ROOT}/logout/callback`. |
| `{SAML2_ROOT}/logout` | Sends the SAML2 `LogoutRequest`. Reachable only with the one-time `state` that `{WSFED_ROOT}?wa=wsignout1.0` issues; a signed-in request without it returns `403`, and an expired or unknown `state` returns `400` "Sign-out not complete". |
| `{SAML2_ROOT}/logout/callback` | IdP `LogoutResponse`, and a `LogoutRequest` for a sign-out started at the IdP (GET with `Signature`, or signed POST). A `LogoutRequest` acts only if its NameID, and its SessionIndex when present, match this browser's user. Configure it as the IdP's single-logout URL for this client. `404` when `SAML2_SLO=false`. |

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
