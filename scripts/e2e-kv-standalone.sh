#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
port=${GOAUTHY_KV_PORT:-18086}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_KV_PORT must be decimal' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'GOAUTHY_KV_PORT must be between 1024 and 65535' >&2; exit 1; }
for command in curl go nc; do command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }; done
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
temp_dir=$(mktemp -d); pid=
cleanup() { status=$?; trap - 0 1 2 15; [ -z "$pid" ] || { kill -TERM "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }; rm -rf "$temp_dir"; e2e_port_lock_release; exit "$status"; }
trap cleanup 0 1 2 15
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { echo "port $port is already in use" >&2; exit 1; }
data_dir=$temp_dir/data; master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password" >"$temp_dir/bootstrap-user-password-phc"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="http://localhost:$port" \
	GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=kv-standalone-e2e GOAUTHY_NODE_ID=kv-standalone-0 \
	GOAUTHY_DATA_DIR="$data_dir" GOAUTHY_MASTER_KEY_DIR="$master_key_dir" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' "$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 & pid=$!
}
wait_ready() { curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "http://localhost:$port/readyz" >/dev/null || { cat "$temp_dir/server.log" >&2; exit 1; }; }
run_phase() {
	phase=$1
	GOAUTHY_E2E_KV=1 GOAUTHY_E2E_KV_URLS="http://localhost:$port" GOAUTHY_E2E_KV_STATE="$temp_dir/kv-state.json" GOAUTHY_E2E_KV_PHASE="$phase" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v "$root/test/e2e/browser" -run '^TestKVAPI$'
}
start; wait_ready; run_phase initial
kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; pid=
start; wait_ready; run_phase post-restart
echo 'standalone KV E2E passed'
