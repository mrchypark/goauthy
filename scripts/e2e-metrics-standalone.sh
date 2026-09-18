#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${GOAUTHY_STANDALONE_PORT:=18880}"
: "${GOAUTHY_STANDALONE_METRICS_PORT:=$((GOAUTHY_STANDALONE_PORT + 1))}"
for command in curl go grep nc sed tr; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
for value_name in GOAUTHY_STANDALONE_PORT GOAUTHY_STANDALONE_METRICS_PORT; do
	value=$(eval "printf '%s' \"\${$value_name}\"")
	case "$value" in ''|*[!0-9]*) echo "$value_name must be a decimal TCP port" >&2; exit 1;; esac
	[ "$value" -ge 1024 ] && [ "$value" -le 65535 ] || { echo "$value_name must be between 1024 and 65535" >&2; exit 1; }
done
[ "$GOAUTHY_STANDALONE_PORT" != "$GOAUTHY_STANDALONE_METRICS_PORT" ] || { echo 'standalone app and metrics ports must differ' >&2; exit 1; }

temp_dir=$(mktemp -d)
pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire
for port in "$GOAUTHY_STANDALONE_PORT" "$GOAUTHY_STANDALONE_METRICS_PORT" "$((GOAUTHY_STANDALONE_METRICS_PORT + 1))"; do
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E port $port is already in use" >&2; exit 1; }
done

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' metrics-e2e-token >"$temp_dir/metrics-token"
browser_password=correct-horse-browser-staple
printf '%s\n' "$browser_password" | go run "$root/cmd/goauthy-password" >"$temp_dir/bootstrap-user-password-phc"
binary=$temp_dir/goauthy
go build -trimpath -o "$binary" "$root/cmd/goauthy"
base=http://127.0.0.1:$GOAUTHY_STANDALONE_PORT
metrics=http://127.0.0.1:$GOAUTHY_STANDALONE_METRICS_PORT

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$GOAUTHY_STANDALONE_PORT" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_METRICS_LISTEN_ADDR="127.0.0.1:$GOAUTHY_STANDALONE_METRICS_PORT" \
	GOAUTHY_METRICS_TOKEN_FILE="$temp_dir/metrics-token" \
	GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=standalone-metrics-e2e \
	GOAUTHY_NODE_ID=standalone-metrics-0 GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	for _ in $(seq 1 300); do
		kill -0 "$pid" 2>/dev/null || { cat "$temp_dir/server.log" >&2; return 1; }
		if curl --fail --silent "$base/livez" >/dev/null 2>&1 && curl --fail --silent "$base/readyz" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	cat "$temp_dir/server.log" >&2
	return 1
}

status() {
	method=$1
	url=$2
	shift 2
	curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' -X "$method" "$@" "$url"
}
expect_status() {
	want=$1
	shift
	got=$(status "$@")
	[ "$got" = "$want" ] || { echo "unexpected HTTP status=$got want=$want" >&2; exit 1; }
}

start
wait_ready
expect_status 401 GET "$metrics/metrics"
expect_status 401 GET "$metrics/metrics" -H 'Authorization: Bearer wrong'
metrics_body=$temp_dir/metrics.body
curl --fail --silent --show-error -H 'Authorization: Bearer metrics-e2e-token' "$metrics/metrics" >"$metrics_body"
grep -q '^# HELP ' "$metrics_body"
expect_status 404 GET "$base/metrics"
expect_status 404 GET "$metrics/livez"
expect_status 404 GET "$metrics/oidc/jwks.json"
expect_status 404 GET "$metrics/auth/v1/admin"

# A second process must fail when it cannot bind the configured metrics
# listener, even with a distinct application listener and data directory.
collision_dir=$temp_dir/collision
mkdir -p "$collision_dir"
set +e
GOAUTHY_LISTEN_ADDR="127.0.0.1:$((GOAUTHY_STANDALONE_METRICS_PORT + 1))" \
GOAUTHY_ISSUER="http://127.0.0.1:$((GOAUTHY_STANDALONE_METRICS_PORT + 1))" \
GOAUTHY_METRICS_LISTEN_ADDR="127.0.0.1:$GOAUTHY_STANDALONE_METRICS_PORT" \
GOAUTHY_METRICS_TOKEN_FILE="$temp_dir/metrics-token" GOAUTHY_RHIZA_PROFILE=standalone \
GOAUTHY_CLUSTER_ID=standalone-metrics-collision GOAUTHY_NODE_ID=collision-0 GOAUTHY_DATA_DIR="$collision_dir" \
GOAUTHY_MASTER_KEY_DIR="$master_key_dir" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
"$binary" >"$temp_dir/collision.log" 2>&1
collision_status=$?
set -e
[ "$collision_status" -ne 0 ] || { cat "$temp_dir/collision.log" >&2; echo 'metrics bind collision unexpectedly succeeded' >&2; exit 1; }

jwks_before=$(curl --fail --silent "$base/oidc/jwks.json")
kill "$pid"
wait "$pid" 2>/dev/null || true
pid=
start
wait_ready
curl --fail --silent -H 'Authorization: Bearer metrics-e2e-token' "$metrics/metrics" >/dev/null
jwks_after=$(curl --fail --silent "$base/oidc/jwks.json")
[ "$jwks_before" = "$jwks_after" ] || { echo 'standalone replacement changed persisted JWKS' >&2; exit 1; }
echo 'standalone separate metrics listener E2E passed'
