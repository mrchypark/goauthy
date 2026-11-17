#!/bin/sh
# Shared setup/lifecycle helpers for standalone event-persistence E2E scripts.
# Expects caller to set:
#   port_var, port, max_port (default 65535), extra_ports (optional space-separated)
#   cluster_id, node_id

standalone_events_init() {
	for command in curl go nc dirname mktemp rm mkdir printf cat tail; do
		command -v "$command" >/dev/null 2>&1 || {
			echo "missing required tool: $command" >&2
			exit 1
		}
	done

	case "$port" in
		''|*[!0-9]*) echo "$port_var must be a decimal TCP port" >&2; exit 1 ;;
	esac
	[ "$port" -ge 1024 ] && [ "$port" -le "${max_port:-65535}" ] || {
		echo "$port_var must be between 1024 and ${max_port:-65535}" >&2
		exit 1
	}

	cd "$root"
	. "$root/scripts/e2e-port-lock.sh"
	e2e_port_lock_acquire
	for candidate in "$port" ${extra_ports:-}; do
		nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1 && {
			echo "E2E port $candidate is already in use; choose $port_var" >&2
			e2e_port_lock_release
			exit 1
		}
	done

	umask 077
	temp_dir=$(mktemp -d)
	pid=
	sink_pid=
	trap standalone_events_cleanup 0 1 2 15

	data_dir=$temp_dir/data
	master_key_dir=$temp_dir/master-keys
	mkdir -p "$data_dir" "$master_key_dir"
	printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
	printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
	printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
	printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"
	go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
	issuer=http://localhost:$port
}

standalone_events_cleanup() {
	status=$?
	trap - 0 1 2 15
	for process in "${pid:-}" "${sink_pid:-}"; do
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

standalone_events_start_server() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID="$cluster_id" \
	GOAUTHY_NODE_ID="$node_id" \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT=30m \
	env "$@" "$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 &
	pid=$!
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$issuer/readyz" >/dev/null || {
		cat "$temp_dir/server.log" >&2
		return 1
	}
}

standalone_events_stop_server() {
	if [ -n "${pid:-}" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
		pid=
	fi
}

standalone_events_run_browser_test() {
	timeout=$1
	test_regex=$2
	shift 2
	env \
		GOAUTHY_E2E_URL="$issuer" \
		GOAUTHY_E2E_SECONDARY_URL="$issuer" \
		GOAUTHY_E2E_TERTIARY_URL="$issuer" \
		GOAUTHY_E2E_BROWSER_USERNAME=admin \
		GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
		GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
		"$@" \
		go test -timeout="$timeout" -count=1 -v ./test/e2e/browser -run "$test_regex"
}
