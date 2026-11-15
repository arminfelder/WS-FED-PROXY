#!/usr/bin/env bash
# Starts the lab stack with Keycloak 26 in place of Keycloak 16.
#
#   e2e/kc26/up.sh         start, then print how to run the tests
#   docker compose up -d   go back to Keycloak 16 (recreates the keycloak and proxy containers)
#
# The realm "lab" gets the user "admin" with the password KC_ADMIN_PW from .env, and with the
# upn and sid attributes that realm.json has for its admin user.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

set -a
# shellcheck disable=SC1091
. ./.env
set +a
: "${KC_ADMIN_PW:?set KC_ADMIN_PW in .env}"
export PROXY_ORIGIN="${E2E_PROXY:-https://192.168.102.1}"
kc_local=https://127.0.0.1:8443

# The realm file holds the password, so only the owner can read the directory.
# Keycloak runs as uid 1000 in the container. Thus the owner of the file must be uid 1000.
install -d -m 700 e2e/kc26/.run/import
python3 - <<'PY'
import json, os
realm = json.load(open('realm.json'))
realm = realm[0] if isinstance(realm, list) else realm
user = next(u for u in realm['users'] if 'sid' in u.get('attributes', {}))
values = {
    '@@TEST_PW@@': os.environ['KC_ADMIN_PW'],
    '@@PROXY_ORIGIN@@': os.environ['PROXY_ORIGIN'],
    '@@UPN@@': user['attributes']['upn'][0],
    '@@SID@@': user['attributes']['sid'][0],
}
text = open('e2e/kc26/realm.json.tmpl').read()
for token, value in values.items():
    # json.dumps escapes the value for a JSON string; [1:-1] removes the quotes
    text = text.replace(token, json.dumps(value)[1:-1])
json.loads(text)
fd = os.open('e2e/kc26/.run/import/lab.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as out:
    out.write(text)
print(f"realm file: upn {values['@@UPN@@']}, sid {values['@@SID@@']}")
PY

compose=(docker compose -f docker-compose.yaml -f e2e/kc26/compose.yaml)

"${compose[@]}" up -d keycloak
printf 'wait for Keycloak 26 '
for _ in $(seq 1 60); do
    if curl -sk -m 5 -o /dev/null -f "$kc_local/realms/lab/protocol/saml/descriptor"; then break; fi
    printf '.'; sleep 3
done
echo

# Keycloak makes the realm key at the import. The proxy needs its certificate before it starts.
# The request goes to the loopback address of this host.
curl -sk -m 10 -f "$kc_local/realms/lab/protocol/saml/descriptor" | python3 -c '
import re, sys, textwrap
body = re.search(r"X509Certificate>([^<]+)<", sys.stdin.read()).group(1).strip()
open("certs/idp-kc26.pem", "w").write("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(body, 64)) + "\n-----END CERTIFICATE-----\n")
'
openssl x509 -in certs/idp-kc26.pem -noout -subject -fingerprint -sha256

"${compose[@]}" up -d --build proxy nginx
"${compose[@]}" ps

cat <<'MSG'

Keycloak 26 is on. Do the tests:
  e2e/kc26/run.sh
Go back to Keycloak 16:
  docker compose up -d
MSG
