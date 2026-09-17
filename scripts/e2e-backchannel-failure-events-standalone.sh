#!/bin/sh
# Runs the back-channel delivery-failure event and persistence gate against
# one fresh, exact-one Rhiza standalone deployment.
set -eu

for command in curl go nc dirname mktemp rm mkdir printf cat tail; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done

port=${GOAUTHY_BACKCHANNEL_FAILURE_EVENTS_PORT:-22481}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_BACKCHANNEL_FAILURE_EVENTS_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65534 ] || { echo 'GOAUTHY_BACKCHANNEL_FAILURE_EVENTS_PORT must leave room for sink port' >&2; exit 1; }
sink_port=$((port + 1))

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
for candidate in "$port" "$sink_port"; do
	nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1 && { echo "backchannel E2E port $candidate is already in use" >&2; e2e_port_lock_release; exit 1; }
done

umask 077
temp_dir=$(mktemp -d)
pid=
sink_pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for process in "$pid" "$sink_pid"; do
		[ -n "$process" ] || continue
		kill -TERM "$process" >/dev/null 2>&1 || true
		wait "$process" 2>/dev/null || true
	done
	if [ "$status" -ne 0 ]; then
		for log in "$temp_dir/server.log" "$temp_dir/sink.log"; do
			test ! -f "$log" || tail -n 80 "$log" >&2 || true
		done
	fi
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
go build -trimpath -o "$temp_dir/backchannel-sink" ./cmd/goauthy-backchannel-sink

sink_url=http://127.0.0.1:$sink_port
issuer=http://localhost:$port
start_sink() {
	LISTEN_ADDR="127.0.0.1:$sink_port" "$temp_dir/backchannel-sink" >"$temp_dir/sink.log" 2>&1 & sink_pid=$!
	curl --fail --silent --show-error --retry 100 --retry-connrefused --retry-delay 0 --retry-max-time 10 "$sink_url/livez" >/dev/null || { cat "$temp_dir/sink.log" >&2; return 1; }
}
start_server() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=backchannel-failure-events-standalone-e2e \
	GOAUTHY_NODE_ID=backchannel-failure-events-standalone-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS='["http://localhost:5555/logout?from=goauthy"]' \
	GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI="$sink_url/backchannel" \
	GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE=true \
	GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP=true \
	GOAUTHY_BACKCHANNEL_RETRY_BASE=1s \
	GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT=30m \
	"$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 & pid=$!
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$issuer/readyz" >/dev/null || { cat "$temp_dir/server.log" >&2; return 1; }
}
stop_server() {
	if [ -n "$pid" ]; then kill -TERM "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; pid=; fi
}
run_events() {
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENTS=1 \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE="$temp_dir/backchannel-failure-event.json" \
	GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url" \
	GOAUTHY_E2E_URL="$issuer" GOAUTHY_E2E_SECONDARY_URL="$issuer" GOAUTHY_E2E_TERTIARY_URL="$issuer" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -timeout=8m -count=1 -v ./test/e2e/browser -run '^TestBackchannelFailureEvents$'
}
run_persistence() {
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_PERSISTENCE=1 \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE="$temp_dir/backchannel-failure-event.json" \
	GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url" \
	GOAUTHY_E2E_URL="$issuer" GOAUTHY_E2E_SECONDARY_URL="$issuer" GOAUTHY_E2E_TERTIARY_URL="$issuer" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -timeout=2m -count=1 -v ./test/e2e/browser -run '^TestBackchannelFailureEventPersisted$'
}

start_sink
start_server
if [ "${GOAUTHY_E2E_GLOBAL_LOGOUT_BACKCHANNEL:-0}" = 1 ]; then
	export GOAUTHY_E2E_GLOBAL_LOGOUT_STATE="$temp_dir/global-logout.json"
	export GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url"
	export GOAUTHY_E2E_URL="$issuer" GOAUTHY_E2E_SECONDARY_URL="$issuer" GOAUTHY_E2E_TERTIARY_URL="$issuer"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=prepare go test -mod=readonly -timeout=3m -count=1 -v ./test/e2e/browser -run '^TestGlobalLogoutBackchannel$'
	stop_server
	start_server
	GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=after-restart go test -mod=readonly -timeout=3m -count=1 -v ./test/e2e/browser -run '^TestGlobalLogoutBackchannel$'
	echo 'standalone subject-only global backchannel logout after restart passed'
	exit 0
fi
run_events
stop_server
start_server
run_persistence
echo 'standalone backchannel failure event and persistence E2E passed'
