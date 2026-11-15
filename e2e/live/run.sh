#!/usr/bin/env bash
# Runs the browser tests in e2e/live against the lab, in the Playwright container.
# The container uses the host network: the lab hosts are on a libvirt network.
#
#   e2e/live/run.sh                    all tests
#   e2e/live/run.sh -g "two tabs"      the tests that match
#
# Settings (environment, or the .env file in the repository root):
#   E2E_USER   Keycloak user that has the upn and sid attributes (default: admin)
#   E2E_PW     its password (default: KC_ADMIN_PW)
#   E2E_OWA    OWA URL (default: https://192.168.102.2/owa/)
#   E2E_PROXY  proxy origin (default: https://192.168.102.1)
#   E2E_KC     Keycloak origin (default: https://192.168.102.1:8443)
#   E2E_KC_REALM   realm URL (default: $E2E_KC/auth/realms/master, the Keycloak 16 stack)
#   E2E_KC_LOGOUT  account or endsession: how the test signs out at Keycloak (default: account)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [ -f "$root/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$root/.env"
    set +a
fi

export E2E_USER="${E2E_USER:-admin}"
export E2E_PW="${E2E_PW:-${KC_ADMIN_PW:-}}"
export E2E_OWA="${E2E_OWA:-https://192.168.102.2/owa/}"
export E2E_PROXY="${E2E_PROXY:-https://192.168.102.1}"
export E2E_KC="${E2E_KC:-https://192.168.102.1:8443}"

if [ -z "$E2E_PW" ]; then
    echo "run.sh: set E2E_PW (or KC_ADMIN_PW in $root/.env)" >&2
    exit 2
fi

# The image has the browsers of this Playwright version. package.json pins the same version.
image=mcr.microsoft.com/playwright:v1.55.0-noble

# Only the names go on the command line. docker reads the values from the environment.
exec docker run --rm --network host --ipc host \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -e E2E_USER -e E2E_PW -e E2E_OWA -e E2E_PROXY -e E2E_KC -e E2E_KC_REALM -e E2E_KC_LOGOUT \
    -v "$here":/work -w /work \
    "$image" \
    bash -c 'npm install --no-audit --no-fund --ignore-scripts >/dev/null && exec npx playwright test "$@"' -- "$@"
