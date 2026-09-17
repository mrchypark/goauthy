#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
port=${GOAUTHY_ADMIN_PASSKEY_PORT:-18088}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_ADMIN_PASSKEY_PORT must be decimal' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'port must be between 1024 and 65535' >&2; exit 1; }
for command in curl go nc; do command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }; done
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
temp_dir=$(mktemp -d); pid=
cleanup() {
	status=$?; trap - 0 1 2 15
	[ -z "$pid" ] || { kill -TERM "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	[ "$status" -eq 0 ] || { [ ! -f "$temp_dir/server.log" ] || tail -n 60 "$temp_dir/server.log" >&2; }
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { echo "port $port is already in use" >&2; exit 1; }
umask 077
mkdir -p "$temp_dir/data" "$temp_dir/keys"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/keys/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/passkey-key"
printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password >"$temp_dir/password-phc"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="http://localhost:$port" \
GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=admin-passkey-standalone-e2e GOAUTHY_NODE_ID=admin-passkey-standalone-0 \
GOAUTHY_DATA_DIR="$temp_dir/data" GOAUTHY_MASTER_KEY_DIR="$temp_dir/keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/password-phc" GOAUTHY_BOOTSTRAP_FORCE_MFA=false \
GOAUTHY_PASSKEY_RP_ID=localhost GOAUTHY_PASSKEY_ORIGINS="http://localhost:$port" GOAUTHY_PASSKEY_KEY_FILE="$temp_dir/passkey-key" GOAUTHY_PASSKEY_FORCE_UV=true \
GOAUTHY_SSP_THRESHOLD="${GOAUTHY_E2E_USER_LIST_THRESHOLD:-200}" GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT=90m "$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 & pid=$!
curl --fail --silent --show-error --retry 120 --retry-connrefused --retry-delay 0 --retry-max-time 30 "http://localhost:$port/readyz" >/dev/null
# Reuse the same observable API flow, with every request hitting the single peer.
GOAUTHY_E2E_ADMIN_PASSKEY=1 GOAUTHY_E2E_URL="http://localhost:$port" \
GOAUTHY_E2E_SECONDARY_URL="http://localhost:$port" GOAUTHY_E2E_TERTIARY_URL="http://localhost:$port" \
GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin \
go test -mod=readonly -count=1 -timeout=3m -v ./test/e2e/passkey -run '^TestAdminPasskeyManagementAcrossPods$'
echo 'standalone admin passkey E2E passed'
