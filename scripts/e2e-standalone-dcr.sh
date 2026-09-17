#!/bin/sh
set -eu

for command in curl go jq nc; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done

port=${GOAUTHY_STANDALONE_PORT:-18082}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'GOAUTHY_STANDALONE_PORT must be between 1024 and 65535' >&2; exit 1; }
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { echo "standalone port $port is already in use; choose GOAUTHY_STANDALONE_PORT" >&2; exit 1; }

temp_dir=$(mktemp -d)
pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	rm -rf "$temp_dir"
	exit "$status"
}
trap cleanup 0 1 2 15

mkdir -p "$temp_dir/data" "$temp_dir/master-keys"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/master-keys/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy

start() {
	cleanup_minutes=$1
	if [ -n "$cleanup_minutes" ]; then
		GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="http://127.0.0.1:$port" GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=standalone-dcr-e2e GOAUTHY_NODE_ID=standalone-dcr-0 GOAUTHY_DATA_DIR="$temp_dir/data" GOAUTHY_MASTER_KEY_DIR="$temp_dir/master-keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" GOAUTHY_DCR_ANONYMOUS=true GOAUTHY_DCR_RATE_LIMIT_SECONDS=3600 GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES="$cleanup_minutes" GOAUTHY_TRUSTED_PROXIES=127.0.0.0/8 "$binary" >"$temp_dir/server.log" 2>&1 &
	else
		GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="http://127.0.0.1:$port" GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=standalone-dcr-e2e GOAUTHY_NODE_ID=standalone-dcr-0 GOAUTHY_DATA_DIR="$temp_dir/data" GOAUTHY_MASTER_KEY_DIR="$temp_dir/master-keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" GOAUTHY_DCR_ANONYMOUS=true GOAUTHY_DCR_RATE_LIMIT_SECONDS=3600 GOAUTHY_TRUSTED_PROXIES=127.0.0.0/8 "$binary" >"$temp_dir/server.log" 2>&1 &
	fi
	pid=$!
	for _ in $(seq 1 300); do
		kill -0 "$pid" 2>/dev/null || { cat "$temp_dir/server.log" >&2; exit 1; }
		curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	cat "$temp_dir/server.log" >&2
	return 1
}

start ''
GOAUTHY_E2E_DCR_ANONYMOUS=true GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" go test -count=1 ./test/e2e -run '^TestAnonymousDynamicClientRegistrationAcrossPods$'
cleanup_registration=$(curl --fail --silent --show-error -H 'Content-Type: application/json' -H 'Idempotency-Key: standalone-cleanup' -H 'Forwarded: for=198.51.100.99' --data '{"redirect_uris":["https://cleanup.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"standalone cleanup"}' "http://127.0.0.1:$port/oidc/register")
cleanup_uri=$(printf '%s' "$cleanup_registration" | jq -er '.registration_client_uri')
cleanup_token=$(printf '%s' "$cleanup_registration" | jq -er '.registration_access_token')
kill "$pid" >/dev/null 2>&1 || true
wait "$pid" 2>/dev/null || true
pid=
start 0
cleanup_status=
for _ in $(seq 1 50); do
	cleanup_status=$(curl --silent --output "$temp_dir/cleanup-get.json" --write-out '%{http_code}' -H "Authorization: Bearer $cleanup_token" "$cleanup_uri")
	[ "$cleanup_status" = 401 ] && break
	sleep 0.1
done
[ "$cleanup_status" = 401 ] || { echo "startup cleanup management status=$cleanup_status" >&2; cat "$temp_dir/server.log" >&2; exit 1; }
echo 'standalone anonymous DCR E2E passed'
