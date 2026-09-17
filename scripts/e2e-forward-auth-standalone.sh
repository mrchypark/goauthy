#!/bin/sh
# Runs the opt-in Forward Auth identity projection against one disposable
# standalone process. The companion browser test uses the public OAuth flow
# and deliberately sends spoofed, duplicate, malformed, and overlong headers.
set -eu

for command in cat curl dirname go grep nc seq sleep; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_STANDALONE_FORWARD_AUTH_PORT:-18087}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_FORWARD_AUTH_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_STANDALONE_FORWARD_AUTH_PORT must be between 1024 and 65535' >&2
	exit 1
}
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone forward-auth port $port is already in use; choose GOAUTHY_STANDALONE_FORWARD_AUTH_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
temp_dir=$(mktemp -d)
pid=
negative_pid=
base=http://127.0.0.1:$port

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	if [ -n "$negative_pid" ]; then
		kill -TERM "$negative_pid" >/dev/null 2>&1 || true
		wait "$negative_pid" 2>/dev/null || true
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

browser_password=correct-horse-browser-staple
printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"
binary=$temp_dir/goauthy
cd "$root"
go build -trimpath -o "$binary" ./cmd/goauthy

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-forward-auth-e2e \
	GOAUTHY_NODE_ID=standalone-forward-auth-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin@goauthy.e2e \
	GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_USER_ROLES='["forward-auth-admin"]' \
	GOAUTHY_BOOTSTRAP_USER_GROUPS='["forward-auth-group"]' \
	GOAUTHY_FORWARD_AUTH_HEADERS=true \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

start_force_mfa_without_passkey() {
	# Force-MFA is intentionally a startup error without optional passkey
	# configuration. This runs in its own data directory and never binds the
	# positive-gate port, so the later password-only flow starts cleanly.
	negative_data_dir=$temp_dir/negative-data
	negative_log=$temp_dir/negative.log
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-forward-auth-negative-e2e \
	GOAUTHY_NODE_ID=standalone-forward-auth-negative-0 \
	GOAUTHY_DATA_DIR="$negative_data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin@goauthy.e2e \
	GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_FORCE_MFA=true \
	GOAUTHY_FORWARD_AUTH_HEADERS=true \
	"$binary" >"$negative_log" 2>&1 &
	negative_pid=$!
	for _ in $(seq 1 300); do
		if ! kill -0 "$negative_pid" 2>/dev/null; then
			set +e
			wait "$negative_pid"
			status=$?
			set -e
			negative_pid=
			[ "$status" -ne 0 ] || {
				cat "$negative_log" >&2
				echo 'force-MFA startup unexpectedly succeeded without passkey configuration' >&2
				return 1
			}
			grep -q 'GOAUTHY_BOOTSTRAP_FORCE_MFA requires passkey configuration' "$negative_log" || {
				cat "$negative_log" >&2
				echo 'force-MFA startup failed for an unexpected reason' >&2
				return 1
			}
			return 0
		fi
		sleep 0.1
	done
	kill -TERM "$negative_pid" >/dev/null 2>&1 || true
	set +e
	wait "$negative_pid"
	set -e
	echo 'force-MFA startup remained alive without passkey configuration' >&2
	return 1
}

wait_ready() {
	# Readiness is bounded by curl attempts and wall time; no fixed sleep is
	# used as an assertion.
	if ! curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$base/readyz" >/dev/null 2>&1; then
		cat "$temp_dir/server.log" >&2
		return 1
	fi
}

stop_graceful() {
	target=$pid
	kill -TERM "$target"
	for _ in $(seq 1 300); do
		if ! kill -0 "$target" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done
	if kill -0 "$target" 2>/dev/null; then
		echo 'standalone forward-auth process did not exit after bounded SIGTERM wait' >&2
		kill -KILL "$target" >/dev/null 2>&1 || true
		wait "$target" 2>/dev/null || true
		pid=
		return 1
	fi
	set +e
	wait "$target"
	status=$?
	set -e
	pid=
	[ "$status" -eq 0 ] || {
		echo "standalone forward-auth process exited with status $status" >&2
		cat "$temp_dir/server.log" >&2
		return 1
	}
}

start_force_mfa_without_passkey
start
wait_ready
GOAUTHY_E2E_FORWARD_AUTH_STANDALONE=1 \
	GOAUTHY_E2E_URL="$base" \
	GOAUTHY_E2E_SECONDARY_URL="$base" \
	GOAUTHY_E2E_TERTIARY_URL="$base" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin@goauthy.e2e \
	GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
	GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -count=1 ./test/e2e/browser -run '^TestForwardAuthStandaloneMalformedTransport$'
stop_graceful
start
wait_ready
GOAUTHY_E2E_FORWARD_AUTH_STANDALONE=1 \
	GOAUTHY_E2E_URL="$base" \
	GOAUTHY_E2E_SECONDARY_URL="$base" \
	GOAUTHY_E2E_TERTIARY_URL="$base" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin@goauthy.e2e \
	GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
	GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -count=1 ./test/e2e/browser -run '^TestForwardAuthStandaloneMalformedTransport$'
stop_graceful
echo 'standalone forward-auth identity and hostile-header E2E passed'
