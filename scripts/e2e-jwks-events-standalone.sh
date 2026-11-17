#!/bin/sh
# Runs the real five-minute signing-key rotation/event persistence gate against
# one fresh, exact-one Rhiza standalone deployment.
set -eu

[ "${GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION:-}" = 1 ] || {
	echo 'refusing JWKS wall-clock E2E: set GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1 explicitly' >&2
	exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
port_var=GOAUTHY_JWKS_EVENTS_PORT
port=${GOAUTHY_JWKS_EVENTS_PORT:-18094}
cluster_id=jwks-events-standalone-e2e
node_id=jwks-events-standalone-0
. "$script_dir/lib-standalone-events.sh"
standalone_events_init

start_server() {
	standalone_events_start_server \
		GOAUTHY_SIGNING_KEY_ROTATION_PERIOD=5m
}

start_server
standalone_events_run_browser_test 10m '^TestJWKSRotationEvents$' \
	GOAUTHY_E2E_JWKS_ROTATION_EVENTS=1 \
	GOAUTHY_E2E_JWKS_EVENT_STATE="$temp_dir/jwks-event.json" \
	GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1
standalone_events_stop_server
start_server
standalone_events_run_browser_test 10m '^TestJWKSRotationEventPersisted$' \
	GOAUTHY_E2E_JWKS_EVENT_PERSISTENCE=1 \
	GOAUTHY_E2E_JWKS_EVENT_STATE="$temp_dir/jwks-event.json" \
	GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1
echo 'standalone JWKS rotation event and persistence E2E passed'
