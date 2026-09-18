#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
"$root/scripts/e2e-preflight.sh" host-capacity
port=${GOAUTHY_GENERATED_BOOTSTRAP_STANDALONE_PORT:-18098}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_GENERATED_BOOTSTRAP_STANDALONE_PORT must be decimal' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'port must be between 1024 and 65535' >&2; exit 1; }
expiry_profile=${GOAUTHY_E2E_GENERATED_EXPIRY:-0}
case "$expiry_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_GENERATED_EXPIRY must be 0 or 1' >&2; exit 1;; esac
expiry_ttl=${GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS:-120}
case "$expiry_ttl" in ''|*[!0-9]*) echo 'GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS must be decimal' >&2; exit 1;; esac
[ "$expiry_ttl" -ge 90 ] && [ "$expiry_ttl" -le 900 ] || { echo 'generated expiry TTL must be between 90 and 900 seconds' >&2; exit 1; }
for command in cat cmp cp curl date go grep jq mkdir nc rm seq sleep; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire

temp_dir=$(mktemp -d); pid=; server_log=
cleanup() {
	status=$?; trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
		kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { echo "port $port is already in use" >&2; exit 1; }

umask 077
data_dir=$temp_dir/data
key_dir=$temp_dir/keys
artifact=$temp_dir/generated.secrets
generated_ttl=0
mkdir -p "$data_dir" "$key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' '[{"name":"generated-reader","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]' >"$temp_dir/api-keys.json"

go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
go build -trimpath -o "$temp_dir/goauthy-bootstrap-secrets" ./cmd/goauthy-bootstrap-secrets
issuer=http://127.0.0.1:$port

start() {
	server_log=$temp_dir/server-$1.log
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=generated-bootstrap-standalone-e2e GOAUTHY_NODE_ID=generated-bootstrap-standalone-0 \
	GOAUTHY_DATA_DIR="$data_dir" GOAUTHY_MASTER_KEY_DIR="$key_dir" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_API_KEY_BOOTSTRAP_FILE="$temp_dir/api-keys.json" \
	GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE="$artifact" GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS="$generated_ttl" \
	"$temp_dir/goauthy" >"$server_log" 2>&1 & pid=$!
	curl --fail --silent --show-error --retry 120 --retry-connrefused --retry-delay 0 --retry-max-time 30 "$issuer/readyz" >/dev/null
}

stop() {
	target=$pid
	kill -TERM "$target"
	for _ in $(seq 1 300); do
		kill -0 "$target" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$target" 2>/dev/null; then
		echo 'generated bootstrap server did not stop after bounded SIGTERM wait' >&2
		return 1
	fi
	wait "$target" 2>/dev/null || { echo 'generated bootstrap server exited unsuccessfully' >&2; return 1; }
	pid=
}

retrieve() {
	"$temp_dir/goauthy-bootstrap-secrets" -file "$artifact" -key-dir "$key_dir" >"$1"
	jq -e 'length == 1 and .[0].kind == "api-key" and .[0].id == "generated-reader" and .[0].field == "token" and (. [0].value | startswith("generated-reader$"))' "$1" >/dev/null
}

authorize_test() {
	entries=$1
	token_file=$temp_dir/token-$2.raw
	full_token_pattern=$temp_dir/token-$2.pattern
	bare_secret_file=$temp_dir/secret-$2.raw
	bare_secret_pattern=$temp_dir/secret-$2.pattern
	auth_config=$temp_dir/curl-$2.conf
	jq -jr '.[0].value' "$entries" >"$token_file"
	cp "$token_file" "$full_token_pattern"
	printf '\n' >>"$full_token_pattern"
	jq -jr '.[0].value | split("$")[1]' "$entries" >"$bare_secret_file"
	cp "$bare_secret_file" "$bare_secret_pattern"
	printf '\n' >>"$bare_secret_pattern"
	printf 'header = "Authorization: API-Key ' >"$auth_config"
	cat "$token_file" >>"$auth_config"
	printf '"\n' >>"$auth_config"
	curl --fail --silent --show-error --config "$auth_config" "$issuer/auth/v1/api_keys/generated-reader/test" >"$temp_dir/self-test-$2.json"
	jq -e '.name == "generated-reader"' "$temp_dir/self-test-$2.json" >/dev/null
	curl --fail --silent --show-error --config "$auth_config" "$issuer/auth/v1/clients" >"$temp_dir/test-$2.json"
	jq -e 'type == "array"' "$temp_dir/test-$2.json" >/dev/null
}

assert_server_log_redacted() {
	[ -r "$server_log" ] || { echo 'generated bootstrap server log is unreadable' >&2; return 1; }
	if grep -F -f "$1" "$server_log" >/dev/null || grep -F -f "$2" "$server_log" >/dev/null; then
		echo 'generated API-key token or secret appeared in server log' >&2
		return 1
	fi
}

wait_generated_export_expiry() {
	# TTL is deliberately at least 90 seconds. Startup completes and the export
	# is authenticated before this bounded wall-clock deadline is observed.
	deadline_floor=$((expiry_started_at + generated_ttl))
	deadline_upper=$((expiry_ready_at + generated_ttl + 10))
	while [ "$(date +%s)" -le "$deadline_upper" ]; do
		if "$temp_dir/goauthy-bootstrap-secrets" -file "$artifact" -key-dir "$key_dir" >"$temp_dir/expired-retrieval.json" 2>"$temp_dir/expired-retrieval.err"; then
			sleep 1
			continue
		fi
		if grep -F 'generated bootstrap secret container expired' "$temp_dir/expired-retrieval.err" >/dev/null; then
			[ ! -s "$temp_dir/expired-retrieval.json" ] || { echo 'expired retrieval emitted plaintext' >&2; return 1; }
			[ "$(date +%s)" -ge "$deadline_floor" ] || { echo 'generated export expired before its original deadline floor' >&2; return 1; }
			return 0
		fi
		echo 'generated export retrieval failed before its expected expiry' >&2
		return 1
	done
	echo 'generated export did not expire by its bounded original deadline' >&2
	return 1
}

wait_artifact_absent() {
	deadline=$(( $(date +%s) + 10 ))
	while [ -e "$artifact" ]; do
		kill -0 "$pid" 2>/dev/null || { echo 'generated bootstrap server exited while awaiting purge' >&2; return 1; }
		[ "$(date +%s)" -le "$deadline" ] || { echo 'expired generated export was not purged after bounded wait' >&2; return 1; }
		sleep 1
	done
	kill -0 "$pid" 2>/dev/null || { echo 'generated bootstrap server exited after purge' >&2; return 1; }
}

# First start generates one secret and commits it with the shared Rhiza record.
start first
test -s "$artifact"
retrieve "$temp_dir/entries-first.json"
authorize_test "$temp_dir/entries-first.json" first
cp "$artifact" "$temp_dir/artifact-first.encrypted"
stop
assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"

# A normal restart must reuse the committed winner and preserve the local export.
start restart
retrieve "$temp_dir/entries-restart.json"
cmp "$temp_dir/entries-first.json" "$temp_dir/entries-restart.json"
cmp "$temp_dir/artifact-first.encrypted" "$artifact"
authorize_test "$temp_dir/entries-restart.json" restart
stop
assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"

# A missing local export is recovered from the shared encrypted winner, without
# changing its token. The deletion is confined to this script's temporary file.
rm -f "$artifact"
test ! -e "$artifact"
start recovery
test -s "$artifact"
retrieve "$temp_dir/entries-recovery.json"
cmp "$temp_dir/entries-first.json" "$temp_dir/entries-recovery.json"
authorize_test "$temp_dir/entries-recovery.json" recovery
stop
assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"

if [ "$expiry_profile" = 1 ]; then
	# Use a separate Rhiza directory so the default non-expiring lifecycle above
	# remains its own assertion. The fixed, bounded TTL avoids startup races.
	data_dir=$temp_dir/expiry-data
	artifact=$temp_dir/expiry-generated.secrets
	generated_ttl=$expiry_ttl
	mkdir -p "$data_dir"
	expiry_started_at=$(date +%s)
	start expiry-initial
	expiry_ready_at=$(date +%s)
	test -s "$artifact"
	retrieve "$temp_dir/entries-expiry.json"
	authorize_test "$temp_dir/entries-expiry.json" expiry-initial
	stop
	assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"

	# The retrieval CLI itself establishes that the original encrypted export has
	# crossed its deadline. Do not delete it before this observation.
	wait_generated_export_expiry

	# The original API key remains valid, but a post-expiry server start consumes
	# the shared record into its initialization tombstone and publishes no export.
	start expiry-after
	wait_artifact_absent
	authorize_test "$temp_dir/entries-expiry.json" expiry-after
	stop
	assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"

	# A second cold start proves the marker prevents replacement generation.
	start expiry-tombstone
	wait_artifact_absent
	authorize_test "$temp_dir/entries-expiry.json" expiry-tombstone
	stop
	assert_server_log_redacted "$full_token_pattern" "$bare_secret_pattern"
fi

echo 'standalone shared generated-bootstrap E2E passed'
