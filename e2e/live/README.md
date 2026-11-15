# Browser tests against the lab

Eight Playwright tests with a real Exchange 2016 OWA, this proxy and Keycloak:
sign-in to the mailbox, two tabs, sign-out started in OWA, sign-out started at Keycloak.
They are not part of `npm test` or of CI, because they need the lab.

The instructions follow ASD-STE100 Simplified Technical English.

## Before you start

- The Exchange VM `server` (192.168.102.2) must be on. `https://192.168.102.2/owa/` must answer with a redirect to the proxy.
- The stack in `docker-compose.yaml` must be on: `docker compose up -d --build`. It builds the proxy from the working tree.
- `certs/idp.pem` must be the signing certificate of the Keycloak realm.
- The Keycloak user must have the `upn` and `sid` attributes of the mailbox owner.

## Run

1. Do the tests: `e2e/live/run.sh`
2. To do one test, give a part of its name: `e2e/live/run.sh -g "two tabs"`
3. If a test fails, look at the screenshot and the trace in `e2e/live/test-results/`.

`run.sh` reads `.env` in the repository root. It uses `KC_ADMIN_PW` as the password of the user `admin`.
Set `E2E_USER` and `E2E_PW` in `.env` for a different user. The header of `run.sh` lists all settings.

## Keycloak 26

The default stack has Keycloak 16.1.0. To do the same tests with Keycloak 26.6.4:

1. Start the stack with Keycloak 26: `e2e/kc26/up.sh`
2. Do the tests: `e2e/kc26/run.sh`
3. Go back to Keycloak 16: `docker compose up -d`

`up.sh` makes the realm `lab` with the user `admin` and the password `KC_ADMIN_PW`.
It writes the certificate of the realm into `certs/idp-kc26.pem`. It does not change `certs/idp.pem`.

## If the tests fail

| Symptom | Cause | Correction |
|---|---|---|
| A sign-in test stops after `POST /owa/`, and OWA does not answer | The Exchange mailbox store does not answer. `Test-MapiConnectivity` in the VM fails. | Restart the service `MSExchangeIS` and do `iisreset` in the VM. |
| OWA shows "too many active sessions connected to this mailbox" | Too many OWA sessions of the test user are open. Each sign-in opens one. | Recycle the application pool `MSExchangeOWAAppPool`, or wait some minutes. |
| The proxy answers `429` | One run sends approximately 40 requests. The default limit is 60 in one minute for each client address. | Wait one minute between two runs, or set `RATE_LIMIT_PER_MINUTE` for the proxy. |
| `/saml2/failure` after the Keycloak login, with `Invalid document signature` in the proxy log | `certs/idp.pem` is not the certificate of the realm. | Export the certificate from the realm again, then restart the proxy. |
| OWA shows an error 500 immediately after a VM start or `iisreset` | Exchange is not ready. | Wait some minutes. |
