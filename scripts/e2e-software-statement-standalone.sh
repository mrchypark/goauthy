#!/bin/sh
# Exercises RFC 7591 software_statement trust and persistence against one
# disposable standalone process. The trust file and EdDSA statement fixture
# are static; the test runs twice to make the second POST an exact replay
# after a cold restart.
set -eu

for command in curl dirname go nc seq sleep; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_STANDALONE_SOFTWARE_STATEMENT_PORT:-18088}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_SOFTWARE_STATEMENT_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_STANDALONE_SOFTWARE_STATEMENT_PORT must be between 1024 and 65535' >&2
	exit 1
}
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone software-statement port $port is already in use; choose GOAUTHY_STANDALONE_SOFTWARE_STATEMENT_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
temp_dir=$(mktemp -d)
pid=
base=http://127.0.0.1:$port

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
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
printf '%s\n' standalone-dcr-registration-token-0123456789 >"$temp_dir/dcr-token"

binary=$temp_dir/goauthy
cd "$root"
go build -trimpath -o "$binary" ./cmd/goauthy

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-software-statement-e2e \
	GOAUTHY_NODE_ID=standalone-software-statement-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-token" \
	GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE="$root/test/e2e/fixtures/software_statement_trust.json" \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	# Startup is bounded by curl attempts and wall time; no fixed sleep is an
	# assertion.
	if ! curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$base/readyz" >/dev/null 2>&1; then
		cat "$temp_dir/server.log" >&2
		return 1
	fi
}

assert_readyz_fence() {
	# In standalone profile this exact-one readiness validator checks the
	# persisted software-statement trust digest and topology fence for the
	# single configured member before registration is admitted.
	status=$(curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' "$base/readyz")
	[ "$status" = 204 ] || {
		echo "standalone software-statement /readyz status=$status want=204" >&2
		cat "$temp_dir/server.log" >&2
		return 1
	}
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
		echo 'standalone software-statement process did not exit after bounded SIGTERM wait' >&2
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
		echo "standalone software-statement process exited with status $status" >&2
		cat "$temp_dir/server.log" >&2
		return 1
	}
}

run_test() {
	GOAUTHY_E2E_SOFTWARE_STATEMENT_STANDALONE=1 \
		GOAUTHY_E2E_URL="$base" \
		go test -count=1 ./test/e2e -run '^TestStandaloneSoftwareStatement$'
}

start
wait_ready
assert_readyz_fence
run_test
stop_graceful

# The second run replays the exact idempotency request against the persisted
# row, then authenticates its persisted registration-access token by GET.
start
wait_ready
assert_readyz_fence
run_test
stop_graceful
echo 'standalone RFC 7591 software-statement E2E passed'
