#!/usr/bin/env bash
# Runs the browser tests of e2e/live against the Keycloak 26 stack that up.sh started.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kc="${E2E_KC:-https://192.168.102.1:8443}"
export E2E_KC="$kc"
export E2E_KC_REALM="$kc/realms/lab"
export E2E_KC_LOGOUT=endsession
exec "$here/../live/run.sh" "$@"
