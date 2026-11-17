#!/bin/sh
# Runs the IP-blacklist lifecycle/event persistence gate against one fresh,
# exact-one Rhiza standalone deployment.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
port_var=GOAUTHY_IP_BLACKLIST_EVENTS_PORT
port=${GOAUTHY_IP_BLACKLIST_EVENTS_PORT:-18095}
cluster_id=ip-blacklist-events-standalone-e2e
node_id=ip-blacklist-events-standalone-0
. "$script_dir/lib-standalone-events.sh"
standalone_events_init

start_server() {
	standalone_events_start_server \
		GOAUTHY_IP_BLACKLIST_ENABLED=true \
		GOAUTHY_TRUSTED_PROXIES=127.0.0.1/32,::1/128
}

start_server
standalone_events_run_browser_test 4m '^TestIPBlacklistEvents$' \
	GOAUTHY_E2E_IP_BLACKLIST_EVENTS=1 \
	GOAUTHY_E2E_IP_BLACKLIST_TEST_IP=192.0.2.200 \
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE="$temp_dir/ip-blacklist-event.json"
standalone_events_stop_server
start_server
standalone_events_run_browser_test 4m '^TestIPBlacklistEventPersisted$' \
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_PERSISTENCE=1 \
	GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE="$temp_dir/ip-blacklist-event.json"
echo 'standalone IP-blacklist event and persistence E2E passed'
