#!/bin/sh
set -eu

for command in curl go head nc sed tr; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done

port=${GOAUTHY_STANDALONE_PORT:-18081}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'GOAUTHY_STANDALONE_PORT must be between 1024 and 65535' >&2; exit 1; }
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone port $port is already in use; choose GOAUTHY_STANDALONE_PORT" >&2
	exit 1
fi

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
	exit "$status"
}
trap cleanup 0 1 2 15

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
browser_password=correct-horse-browser-staple
printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"
binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy
current_binary=$binary
# Optional cold-upgrade gate: create data with the supplied previous build,
# then reopen exactly that directory with the current source build below.
if [ -n "${GOAUTHY_STANDALONE_PREVIOUS_BINARY:-}" ]; then
	[ -x "$GOAUTHY_STANDALONE_PREVIOUS_BINARY" ] || { echo 'previous binary must be executable' >&2; exit 1; }
	binary=$GOAUTHY_STANDALONE_PREVIOUS_BINARY
fi

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="http://127.0.0.1:$port" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-e2e \
	GOAUTHY_NODE_ID=standalone-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	for _ in $(seq 1 300); do
		kill -0 "$pid" 2>/dev/null || { cat "$temp_dir/server.log" >&2; return 1; }
		if curl --fail --silent "http://127.0.0.1:$port/livez" >/dev/null 2>&1 && curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	cat "$temp_dir/server.log" >&2
	return 1
}

jwks_kid() {
	curl --fail --silent "http://127.0.0.1:$port/oidc/jwks.json" | tr ',' '\n' | sed -n 's/.*"kid":"\([^"]*\)".*/\1/p' | head -n 1
}

verify_runtime() {
 if [ "${GOAUTHY_E2E_MANAGED_CLIENTS:-0}" = 1 ]; then
  GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
  GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
  GOAUTHY_E2E_BROWSER_USERNAME=admin \
  GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
  go test -count=1 -v ./test/e2e -run '^TestManagedClientsHTTPWorkflow$'
 fi
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -count=1 ./test/e2e -run '^(TestCurrentProfile|TestCrossPodRevocation|TestClientCredentialsPublic)$'
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -count=1 ./test/e2e/browser -run '^TestAuthorizationCodeLoginAcrossPods$'
	if [ "${GOAUTHY_E2E_EXCHANGE_USER_CLAIMS:-0}" = 1 ]; then
		GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_BROWSER_USERNAME=admin \
		GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
		GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
		go test -count=1 -v ./test/e2e/browser -run '^TestTokenExchangeUserClaimsAcrossPods$'
	fi
	if [ "${GOAUTHY_E2E_MACHINE_EXCHANGE:-0}" = 1 ]; then
		GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_BROWSER_USERNAME=admin \
		GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
		GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
		go test -count=1 -v ./test/e2e/browser -run '^TestMachineExchangeAcrossPods$'
	fi
	if [ "${GOAUTHY_E2E_MANAGED_DEFAULT_AUDIENCE:-0}" = 1 ]; then
		GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$port" \
		GOAUTHY_E2E_BROWSER_USERNAME=admin \
		GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
		GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
		go test -count=1 -v ./test/e2e/browser -run '^TestManagedDefaultAudienceLive$'
	fi
}

start
wait_ready
verify_runtime
if [ "${GOAUTHY_E2E_FORCED_LOGOUT:-0}" = 1 ]; then
	GOAUTHY_E2E_FORCED_LOGOUT_STATE="$temp_dir/forced-logout.json" \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -mod=readonly -count=1 -timeout=5m -v ./test/e2e/browser -run '^TestForcedLogoutUserLifecycle$'
fi
first_kid=$(jwks_kid)
[ -n "$first_kid" ]
kill "$pid"
wait "$pid" 2>/dev/null || true
pid=

binary=$current_binary
start
wait_ready
second_kid=$(jwks_kid)
[ "$second_kid" = "$first_kid" ] || { echo 'standalone restart changed the persisted JWKS kid' >&2; exit 1; }
verify_runtime
if [ "${GOAUTHY_E2E_FORCED_LOGOUT:-0}" = 1 ]; then
	GOAUTHY_E2E_FORCED_LOGOUT_PERSISTENCE=1 \
	GOAUTHY_E2E_FORCED_LOGOUT_STATE="$temp_dir/forced-logout.json" \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -mod=readonly -count=1 -timeout=5m -v ./test/e2e/browser -run '^TestForcedLogoutUserPersisted$'
fi
echo 'standalone runtime smoke and browser authorization flow passed'
