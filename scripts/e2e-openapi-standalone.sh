#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${GOAUTHY_OPENAPI_PORT:=18087}"
export GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS='["http://localhost:5555/logout?from=goauthy"]'
export GOAUTHY_BOOTSTRAP_FORCE_MFA=false
for command in curl go nc; do command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }; done
case "$GOAUTHY_OPENAPI_PORT" in ''|*[!0-9]*) echo 'GOAUTHY_OPENAPI_PORT must be decimal' >&2; exit 1;; esac
[ "$GOAUTHY_OPENAPI_PORT" -ge 1024 ] && [ "$GOAUTHY_OPENAPI_PORT" -le 65532 ] || exit 1
. "$root/scripts/e2e-port-lock.sh"; e2e_port_lock_acquire
temp_dir=$(mktemp -d); pid=
cleanup() { status=$?; trap - 0 1 2 15; [ -z "$pid" ] || { kill -TERM "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }; rm -rf "$temp_dir"; e2e_port_lock_release; exit "$status"; }
trap cleanup 0 1 2 15
nc -z 127.0.0.1 "$GOAUTHY_OPENAPI_PORT" >/dev/null 2>&1 && { echo "port is in use" >&2; exit 1; }
mkdir -p "$temp_dir/data" "$temp_dir/keys"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/keys/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password" >"$temp_dir/password-phc"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
start() { mode=$1; GOAUTHY_BOOTSTRAP_USER_MFA=false GOAUTHY_LISTEN_ADDR="127.0.0.1:$GOAUTHY_OPENAPI_PORT" GOAUTHY_ISSUER="http://localhost:$GOAUTHY_OPENAPI_PORT" GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=openapi-standalone-e2e GOAUTHY_NODE_ID=openapi-standalone-0 GOAUTHY_DATA_DIR="$temp_dir/data" GOAUTHY_MASTER_KEY_DIR="$temp_dir/keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/password-phc" GOAUTHY_SWAGGER_UI_ENABLE=$([ "$mode" != disabled ] && echo true || echo false) GOAUTHY_SWAGGER_UI_PUBLIC=$([ "$mode" = public ] && echo true || echo false) "$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 & pid=$!; curl --fail --silent --retry 120 --retry-connrefused --retry-delay 0 --retry-max-time 30 "http://localhost:$GOAUTHY_OPENAPI_PORT/readyz" >/dev/null || { cat "$temp_dir/server.log" >&2; exit 1; }; }
run() { mode=$1; phase=$2; GOAUTHY_E2E_OPENAPI=1 GOAUTHY_E2E_OPENAPI_MODE="$mode" GOAUTHY_E2E_OPENAPI_PHASE="$phase" GOAUTHY_E2E_OPENAPI_URLS="http://localhost:$GOAUTHY_OPENAPI_PORT" GOAUTHY_E2E_OPENAPI_STATE="$temp_dir/session.json" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v "$root/test/e2e/browser" -run '^TestOpenAPIDocs$'; }
start disabled; run disabled initial; kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; pid=
start private; run private initial; kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; pid=
start private; run private post-restart; kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; pid=
start public; run public initial
echo 'standalone OpenAPI E2E passed'
