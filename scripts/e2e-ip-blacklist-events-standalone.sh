#!/bin/sh
# Runs the IP-blacklist lifecycle/event persistence gate against one fresh,
# exact-one Rhiza standalone deployment.
set -eu

for command in curl go nc dirname mktemp rm mkdir printf cat tail; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_IP_BLACKLIST_EVENTS_PORT:-18095}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_IP_BLACKLIST_EVENTS_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_IP_BLACKLIST_EVENTS_PORT must be between 1024 and 65535' >&2
	exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && {
	echo "IP-blacklist events standalone port $port is already in use; choose GOAUTHY_IP_BLACKLIST_EVENTS_PORT" >&2
	e2e_port_lock_release
	exit 1
}

umask 077
temp_dir=$(mktemp -d)
pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	[ "$status" -eq 0 ] || { test ! -f "$temp_dir/server.log" || tail -n 80 "$temp_dir/server.log" >&2 || true; }
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy

issuer=http://localhost:$port
start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=ip-blacklist-events-standalone-e2e \
	GOAUTHY_NODE_ID=ip-blacklist-events-standalone-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT=30m \
	GOAUTHY_IP_BLACKLIST_ENABLED=true \
	GOAUTHY_TRUSTED_PROXIES=127.0.0.1/32,::1/128 \
	"$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}
wait_ready() {
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$issuer/readyz" >/dev/null || {
		cat "$temp_dir/server.log" >&2
		return 1
	}
}
stop() {
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
		pid=
	fi
}
run_events() {
	GOAUTHY_E2E_IP_BLACKLIST_EVENTS=1 \
	GOAUTHY_E2E_IP_BLACKLIST_TEST_IP=192.0.2.200 \
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE="$temp_dir/ip-blacklist-event.json" \
	GOAUTHY_E2E_URL="$issuer" \
	GOAUTHY_E2E_SECONDARY_URL="$issuer" \
	GOAUTHY_E2E_TERTIARY_URL="$issuer" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -timeout=4m -count=1 -v ./test/e2e/browser -run '^TestIPBlacklistEvents$'
}
run_persistence() {
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_PERSISTENCE=1 \
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE="$temp_dir/ip-blacklist-event.json" \
	GOAUTHY_E2E_URL="$issuer" \
	GOAUTHY_E2E_SECONDARY_URL="$issuer" \
	GOAUTHY_E2E_TERTIARY_URL="$issuer" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -timeout=4m -count=1 -v ./test/e2e/browser -run '^TestIPBlacklistEventPersisted$'
}

start
wait_ready
run_events
stop
start
wait_ready
run_persistence
echo 'standalone IP-blacklist event and persistence E2E passed'
