#!/bin/sh
# Exercises the opt-in trusted-country-header geoblock path against one
# disposable standalone process. This gate verifies a real MaxMind lookup,
# health bypass, and live allow/deny admission.
set -eu

for command in curl dirname go nc seq sleep; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_GEOBLOCK_STANDALONE_PORT:-18089}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_GEOBLOCK_STANDALONE_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_GEOBLOCK_STANDALONE_PORT must be between 1024 and 65535' >&2
	exit 1
}
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone geoblock port $port is already in use; choose GOAUTHY_GEOBLOCK_STANDALONE_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
temp_dir=$(mktemp -d)
pid=
base=http://127.0.0.1:$port
cd "$root"

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf 'correct-horse-browser-staple\n' | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"

binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-geoblock-e2e \
	GOAUTHY_NODE_ID=standalone-geoblock-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_TRUSTED_PROXIES=127.0.0.0/8 \
	GOAUTHY_GEOBLOCK_ENABLED=true \
	GOAUTHY_GEOBLOCK_TYPE=whitelist \
	GOAUTHY_GEOBLOCK_COUNTRIES=KR \
	GOAUTHY_GEOBLOCK_BLOCK_UNKNOWN=true \
	GOAUTHY_GEOBLOCK_MAXMIND_DB="$root/internal/geoblock/testdata/GeoIP2-Country-Test.mmdb" \
	GOAUTHY_GEOBLOCK_COUNTRY_HEADER=X-Country \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	if ! curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$base/readyz" >/dev/null 2>&1; then
		cat "$temp_dir/server.log" >&2
		return 1
	fi
}

expect_status() {
	want=$1
	label=$2
	shift 2
	got=$(curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' "$@" "$base/oidc/jwks.json")
	[ "$got" = "$want" ] || {
		echo "$label status=$got want $want" >&2
		return 1
	}
}

start
wait_ready

# Health remains available for orchestration even when an admission source is
# absent, while a protected route is denied without a country result.
health_status=$(curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' "$base/livez")
[ "$health_status" = 204 ] || { echo "livez status=$health_status want 204" >&2; exit 1; }
expect_status 403 unknown-country
expect_status 200 allowed-country -H 'X-Forwarded-For: 2001:220::1'
expect_status 403 denied-country -H 'X-Forwarded-For: 149.101.100.1'
expect_status 403 unknown-forwarded-country -H 'X-Forwarded-For: 214.1.1.1'

# A country header cannot override the configured database lookup.
expect_status 200 trusted-header-overrides-db -H 'X-Country: KR' -H 'X-Forwarded-For: 149.101.100.1'
expect_status 200 trusted-header -H 'X-Country: KR'
expect_status 403 denied-header -H 'X-Country: US'
expect_status 403 ambiguous-header -H 'X-Country: KR,US'

# The outer canonical peer parser rejects malformed forwarding from the
# trusted loopback proxy before geoblock can admit the request.
expect_status 400 malformed-forwarded -H 'X-Country: KR' -H 'Forwarded: for=unknown'
expect_status 400 conflicting-forwarded -H 'X-Country: KR' -H 'Forwarded: for=198.51.100.9' -H 'X-Forwarded-For: 198.51.100.9'

echo 'standalone geoblock health, MaxMind allow/deny/unknown, and forwarding gates passed'
