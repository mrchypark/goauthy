#!/bin/sh
# Runs the back-channel delivery-failure event and persistence gate against
# one fresh, exact-one Rhiza standalone deployment.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
port_var=GOAUTHY_BACKCHANNEL_FAILURE_EVENTS_PORT
port=${GOAUTHY_BACKCHANNEL_FAILURE_EVENTS_PORT:-22481}
max_port=65534
sink_port=$((port + 1))
extra_ports="$sink_port"
cluster_id=backchannel-failure-events-standalone-e2e
node_id=backchannel-failure-events-standalone-0
. "$script_dir/lib-standalone-events.sh"
standalone_events_init

go build -trimpath -o "$temp_dir/backchannel-sink" ./cmd/goauthy-backchannel-sink
sink_url=http://127.0.0.1:$sink_port
LISTEN_ADDR="127.0.0.1:$sink_port" "$temp_dir/backchannel-sink" >"$temp_dir/sink.log" 2>&1 &
sink_pid=$!
curl --fail --silent --show-error --retry 100 --retry-connrefused --retry-delay 0 --retry-max-time 10 "$sink_url/livez" >/dev/null || {
	cat "$temp_dir/sink.log" >&2
	exit 1
}

start_server() {
	standalone_events_start_server \
		GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS='["http://localhost:5555/logout?from=goauthy"]' \
		GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI="$sink_url/backchannel" \
		GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE=true \
		GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP=true \
		GOAUTHY_BACKCHANNEL_RETRY_BASE=1s
}

start_server
if [ "${GOAUTHY_E2E_GLOBAL_LOGOUT_BACKCHANNEL:-0}" = 1 ]; then
	standalone_events_run_browser_test 3m '^TestGlobalLogoutBackchannel$' \
		GOAUTHY_E2E_GLOBAL_LOGOUT_STATE="$temp_dir/global-logout.json" \
		GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url" \
		GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=prepare
	standalone_events_stop_server
	start_server
	standalone_events_run_browser_test 3m '^TestGlobalLogoutBackchannel$' \
		GOAUTHY_E2E_GLOBAL_LOGOUT_STATE="$temp_dir/global-logout.json" \
		GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url" \
		GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=after-restart
	echo 'standalone subject-only global backchannel logout after restart passed'
	exit 0
fi

standalone_events_run_browser_test 8m '^TestBackchannelFailureEvents$' \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENTS=1 \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE="$temp_dir/backchannel-failure-event.json" \
	GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url"
standalone_events_stop_server
start_server
standalone_events_run_browser_test 2m '^TestBackchannelFailureEventPersisted$' \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_PERSISTENCE=1 \
	GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE="$temp_dir/backchannel-failure-event.json" \
	GOAUTHY_E2E_BACKCHANNEL_SINK_URL="$sink_url"
echo 'standalone backchannel failure event and persistence E2E passed'
