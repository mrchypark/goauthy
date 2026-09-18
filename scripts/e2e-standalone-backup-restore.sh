#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
"$root/scripts/e2e-preflight.sh" host-capacity
for command in cat cmp cp curl date go grep jq mkdir nc rm seq sleep; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

source_port=${GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT:-18083}
restore_port=${GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT:-18084}
expiry_profile=${GOAUTHY_E2E_GENERATED_EXPIRY:-0}
case "$expiry_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_GENERATED_EXPIRY must be 0 or 1' >&2; exit 1;; esac
expiry_ttl=${GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS:-120}
case "$expiry_ttl" in ''|*[!0-9]*) echo 'GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS must be decimal' >&2; exit 1;; esac
[ "$expiry_ttl" -ge 90 ] && [ "$expiry_ttl" -le 900 ] || { echo 'generated expiry TTL must be between 90 and 900 seconds' >&2; exit 1; }
validate_port() {
	port_name=$1
	port=$2
	case "$port" in
		''|*[!0-9]*) echo "$port_name must be a decimal TCP port" >&2; exit 1 ;;
	esac
	[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
		echo "$port_name must be between 1024 and 65535" >&2
		exit 1
	}
}
validate_port source_port "$source_port"
validate_port restore_port "$restore_port"
[ "$source_port" != "$restore_port" ] || {
	echo 'source and restore ports must be different' >&2
	exit 1
}
. "$root/scripts/e2e-port-lock.sh"

temp_dir=$(mktemp -d)
pid=
server_log=
cleanup() {
	status=$?
	trap - 0 1 2 15
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
e2e_port_lock_acquire
for port in "$source_port" "$restore_port"; do
	if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
		echo "standalone backup/restore port $port is already in use" >&2
		exit 1
	fi
done

source_data=$temp_dir/source-data
backup_data=$temp_dir/backup-data
restore_data=$temp_dir/restore-data
master_key_dir=$temp_dir/master-keys
source_generated_artifact=$temp_dir/source-generated.secrets
restore_generated_artifact=$temp_dir/restore-generated.secrets
api_key_bootstrap=$temp_dir/api-keys.json
umask 077
generated_ttl=0
[ "$expiry_profile" = 0 ] || generated_ttl=$expiry_ttl
mkdir -p "$source_data" "$backup_data" "$restore_data" "$master_key_dir"

# These values are deliberately provisioned outside the data backup. A real
# deployment must restore them from its secret-management system separately.
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' '[{"name":"generated-reader","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]' >"$api_key_bootstrap"

binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy
go build -trimpath -o "$temp_dir/goauthy-bootstrap-secrets" ./cmd/goauthy-bootstrap-secrets

start() {
	data_dir=$1
	port=$2
	generated_artifact=$3
	server_log=$temp_dir/server-$port.log
	# Signing-key envelopes authenticate the normalized issuer. Keep the
	# restored identity stable while using a separate listener port.
	# The optional expiry profile keeps this source and restored issuer stable
	# while proving the winner's original deadline survives a cold data restore.
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-backup-restore-e2e \
	GOAUTHY_NODE_ID=standalone-backup-restore-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_API_KEY_BOOTSTRAP_FILE="$api_key_bootstrap" \
	GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE="$generated_artifact" \
	GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS="$generated_ttl" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	"$binary" >"$server_log" 2>&1 &
	pid=$!
	for _ in $(seq 1 300); do
		kill -0 "$pid" 2>/dev/null || {
			echo 'backup/restore server exited before readiness' >&2
			return 1
		}
		if curl --fail --silent "http://127.0.0.1:$port/livez" >/dev/null 2>&1 &&
			curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	echo 'backup/restore server did not become ready' >&2
	return 1
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
		echo "process $target did not exit after graceful shutdown" >&2
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
		echo "standalone process exited with status $status" >&2
		return 1
	}
}

issue_token() {
	base=$1
	out=$2
	curl --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" | jq -jr '.access_token' >"$out"
}

assert_active() {
	base=$1
	token_file=$2
	payload=$(curl --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token@$token_file" \
		"$base/oidc/introspect")
	[ "$(printf '%s' "$payload" | jq -er '.active')" = true ]
	[ "$(printf '%s' "$payload" | jq -er '.client_id')" = goauthy-dev ]
	[ "$(printf '%s' "$payload" | jq -er '.scope')" = goauthy.read ]
}

jwks_kid() {
	base=$1
	curl --fail --silent --show-error "$base/oidc/jwks.json" | jq -er '.keys[0].kid'
}

retrieve_generated() {
	artifact=$1
	out=$2
	"$temp_dir/goauthy-bootstrap-secrets" -file "$artifact" -key-dir "$master_key_dir" >"$out"
	jq -e 'length == 1 and .[0].kind == "api-key" and .[0].id == "generated-reader" and .[0].field == "token" and (.[0].value | startswith("generated-reader$"))' "$out" >/dev/null
}

assert_generated_api() {
	base=$1
	entries=$2
	label=$3
	token_file=$temp_dir/generated-token-$label.raw
	full_pattern=$temp_dir/generated-token-$label.pattern
	bare_file=$temp_dir/generated-secret-$label.raw
	bare_pattern=$temp_dir/generated-secret-$label.pattern
	auth_config=$temp_dir/generated-auth-$label.conf
	jq -jr '.[0].value' "$entries" >"$token_file"
	cp "$token_file" "$full_pattern"
	printf '\n' >>"$full_pattern"
	jq -jr '.[0].value | split("$")[1]' "$entries" >"$bare_file"
	cp "$bare_file" "$bare_pattern"
	printf '\n' >>"$bare_pattern"
	printf 'header = "Authorization: API-Key ' >"$auth_config"
	cat "$token_file" >>"$auth_config"
	printf '"\n' >>"$auth_config"
	curl --fail --silent --show-error --config "$auth_config" "$base/auth/v1/api_keys/generated-reader/test" >"$temp_dir/generated-self-test-$label.json"
	jq -e '.name == "generated-reader"' "$temp_dir/generated-self-test-$label.json" >/dev/null
	curl --fail --silent --show-error --config "$auth_config" "$base/auth/v1/clients" >"$temp_dir/generated-clients-$label.json"
	jq -e 'type == "array"' "$temp_dir/generated-clients-$label.json" >/dev/null
}

assert_generated_log_redacted() {
	[ -r "$server_log" ] || { echo 'backup/restore generated-key server log is unreadable' >&2; return 1; }
	if grep -F -f "$1" "$server_log" >/dev/null || grep -F -f "$2" "$server_log" >/dev/null; then
		echo 'generated API-key token or secret appeared in server log' >&2
		return 1
	fi
}

expired_export() {
	artifact=$1
	output=$2
	err=$3
	if "$temp_dir/goauthy-bootstrap-secrets" -file "$artifact" -key-dir "$master_key_dir" >"$output" 2>"$err"; then
		return 1
	else
		exit_status=$?
	fi
	[ "$exit_status" -eq 1 ] || { echo 'generated export retrieval returned an unexpected status' >&2; return 2; }
	[ ! -s "$output" ] || { echo 'expired generated export retrieval emitted plaintext' >&2; return 2; }
	grep -F 'goauthy-bootstrap-secrets: generated bootstrap secret container expired' "$err" >/dev/null || { echo 'generated export retrieval did not report authenticated expiry' >&2; return 2; }
	return 0
}

wait_original_deadline() {
	deadline_floor=$((expiry_started_at + generated_ttl))
	deadline_upper=$((expiry_ready_at + generated_ttl + 10))
	while [ "$(date +%s)" -le "$deadline_upper" ]; do
		source_expired=0
		restore_expired=0
		if expired_export "$source_generated_artifact" "$temp_dir/source-expired.json" "$temp_dir/source-expired.err"; then source_expired=1; else status=$?; [ "$status" -eq 1 ] || return "$status"; fi
		if expired_export "$restore_generated_artifact" "$temp_dir/restore-expired.json" "$temp_dir/restore-expired.err"; then restore_expired=1; else status=$?; [ "$status" -eq 1 ] || return "$status"; fi
		if [ "$source_expired" -eq 1 ] || [ "$restore_expired" -eq 1 ]; then
			[ "$(date +%s)" -ge "$deadline_floor" ] || { echo 'generated export expired before its original deadline floor' >&2; return 2; }
		fi
		if [ "$source_expired" -eq 1 ] && [ "$restore_expired" -eq 1 ]; then
			return 0
		fi
		sleep 1
	done
	echo 'source and restored generated exports did not expire by the original deadline' >&2
	return 1
}

wait_restore_export_absent() {
	deadline=$(( $(date +%s) + 10 ))
	while [ -e "$restore_generated_artifact" ]; do
		kill -0 "$pid" 2>/dev/null || { echo 'restored server exited while awaiting expired export purge' >&2; return 1; }
		[ "$(date +%s)" -le "$deadline" ] || { echo 'expired restored generated export was not purged' >&2; return 1; }
		sleep 1
	done
}

source_base="http://127.0.0.1:$source_port"
restore_base="http://127.0.0.1:$restore_port"
issuer=$source_base
expiry_started_at=0
[ "$expiry_profile" = 0 ] || expiry_started_at=$(date +%s)
start "$source_data" "$source_port" "$source_generated_artifact"
expiry_ready_at=0
[ "$expiry_profile" = 0 ] || expiry_ready_at=$(date +%s)
issue_token "$source_base" "$temp_dir/source-oidc-token"
assert_active "$source_base" "$temp_dir/source-oidc-token"
source_kid=$(jwks_kid "$source_base")
[ -n "$source_kid" ]
test -s "$source_generated_artifact"
retrieve_generated "$source_generated_artifact" "$temp_dir/source-generated.json"
assert_generated_api "$source_base" "$temp_dir/source-generated.json" source

# The process must be fully stopped before any data file is copied. This is a
# cold filesystem backup, not a live SQLite/WAL snapshot.
stop_graceful
assert_generated_log_redacted "$full_pattern" "$bare_pattern"
cp -R "$source_data/." "$backup_data/"
if [ "$expiry_profile" = 1 ]; then
	[ "$(date +%s)" -lt $((expiry_started_at + generated_ttl)) ] || { echo 'cold data backup did not finish before the original generated export deadline' >&2; exit 1; }
fi
test -e "$backup_data/qlog"
test -e "$backup_data/sqlite.db"
test -e "$backup_data/latticedb"
test ! -e "$backup_data/master-keys"
test ! -e "$backup_data/oauth-hmac"
test ! -e "$backup_data/bootstrap-client"
test ! -e "$backup_data/$(basename "$source_generated_artifact")"

# Restore into a clean, separately addressed data directory while reusing the
# independently provisioned key/secret files above.
cp -R "$backup_data/." "$restore_data/"
test ! -e "$restore_generated_artifact"
if [ "$expiry_profile" = 1 ]; then
	# A reset-TTL bug must start late enough to miss the original upper bound,
	# yet still before the source export's earliest possible expiry.
	restore_not_before=$((expiry_ready_at + 20))
	while [ "$(date +%s)" -lt "$restore_not_before" ]; do sleep 1; done
	[ "$(date +%s)" -lt $((expiry_started_at + generated_ttl)) ] || { echo 'restore did not begin before the original generated export deadline' >&2; exit 1; }
fi
start "$restore_data" "$restore_port" "$restore_generated_artifact"
issue_token "$restore_base" "$temp_dir/restore-oidc-token"
assert_active "$restore_base" "$temp_dir/source-oidc-token"
restore_kid=$(jwks_kid "$restore_base")
[ "$restore_kid" = "$source_kid" ] || {
	echo "restored JWKS kid $restore_kid differs from source $source_kid" >&2
	exit 1
}
test -s "$restore_generated_artifact"
retrieve_generated "$restore_generated_artifact" "$temp_dir/restore-generated.json"
cmp "$temp_dir/source-generated.json" "$temp_dir/restore-generated.json"
assert_generated_api "$restore_base" "$temp_dir/restore-generated.json" restored

# A post-restore mutation plus read proves the restored process is writable,
# not merely serving the copied static files.
assert_active "$restore_base" "$temp_dir/restore-oidc-token"
stop_graceful
assert_generated_log_redacted "$full_pattern" "$bare_pattern"
if [ "$expiry_profile" = 1 ]; then
	# Both local exports were created from the same committed winner. Their
	# ciphertext differs by nonce, so the original deadline is evidenced by the
	# same bounded authenticated-expiry observation instead of byte equality.
	wait_original_deadline

	# The backup data contains no local export. Starting it after the original
	# deadline must tombstone the expired shared payload without creating a local
	# export, while retaining the original API key without a replacement.
	expired_restore_data=$temp_dir/expired-restore-data
	restore_generated_artifact=$temp_dir/expired-restore-generated.secrets
	mkdir -p "$expired_restore_data"
	cp -R "$backup_data/." "$expired_restore_data/"
	test ! -e "$restore_generated_artifact"
	start "$expired_restore_data" "$restore_port" "$restore_generated_artifact"
	wait_restore_export_absent
	assert_generated_api "$restore_base" "$temp_dir/restore-generated.json" expiry-restored
	stop_graceful
	assert_generated_log_redacted "$full_pattern" "$bare_pattern"
	# A second start from the same clean restored data proves the persisted
	# tombstone keeps the expired backup from ever generating a replacement.
	start "$expired_restore_data" "$restore_port" "$restore_generated_artifact"
	test ! -e "$restore_generated_artifact"
	assert_generated_api "$restore_base" "$temp_dir/restore-generated.json" expiry-restored-tombstone
	stop_graceful
	assert_generated_log_redacted "$full_pattern" "$bare_pattern"
fi
pid=
if [ "$expiry_profile" = 1 ]; then
	echo 'standalone expiring generated cold backup/restore E2E passed'
else
	echo 'standalone cold backup/restore E2E passed'
fi
