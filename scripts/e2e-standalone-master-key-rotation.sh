#!/bin/sh
set -eu

for command in basename cmp cp curl dirname go grep jq mkdir nc seq sleep; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_STANDALONE_MASTER_KEY_PORT:-18086}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_MASTER_KEY_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_STANDALONE_MASTER_KEY_PORT must be between 1024 and 65535' >&2
	exit 1
}
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone master-key port $port is already in use; choose GOAUTHY_STANDALONE_MASTER_KEY_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"

temp_dir=$(mktemp -d)
pid=
server_log=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$temp_dir"
	exit "$status"
}
trap cleanup 0 1 2 15

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
replacement_key_dir=$temp_dir/replacement-master-keys
old_key_dir=$temp_dir/old-master-keys
mkdir -p "$data_dir" "$master_key_dir" "$replacement_key_dir"
mkdir -p "$old_key_dir"

# Fixed keys make this gate reproducible. The first process creates the
# encrypted signing row with key-a; the second starts with key-a + key-b and
# active key-b so the runtime rewrap worker must converge the row.
key_a=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY
key_b=YWJjZGVmZ2hpamtsbW5vcEFCQ0RFRkdISUpLTE1OT1A
printf '%s\n' "$key_a" >"$master_key_dir/key-a"
printf '%s\n' "$key_a" >"$old_key_dir/key-a"
printf '%s\n' "$key_b" >"$replacement_key_dir/key-b"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
operator_secret=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01
printf '%s\n' '[{"name":"rotation-operator","secret":{"Plain":"'"$operator_secret"'"},"access":[{"group":"Secrets","access_rights":["read","create","update","delete"]}]}]' >"$temp_dir/operator-keys"

binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy
issuer=http://127.0.0.1:$port

start() {
	key_dir=$1
	active_key=$2
	server_log=$temp_dir/server-$active_key-$(basename "$key_dir").log
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-master-key-e2e \
	GOAUTHY_NODE_ID=standalone-master-key-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID="$active_key" \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_API_KEY_BOOTSTRAP_FILE="$temp_dir/operator-keys" \
	GOAUTHY_DCR_ANONYMOUS=true \
	GOAUTHY_DCR_RATE_LIMIT_SECONDS=3600 \
	"$binary" >"$server_log" 2>&1 &
	pid=$!
	# Readiness is the only process-start wait. The retry count and wall clock
	# bound make a stuck startup fail without an unbounded or arbitrary sleep.
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 \
		"$issuer/readyz" >/dev/null 2>&1 || {
		cat "$server_log" >&2
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
		cat "$server_log" >&2
		return 1
	}
}

run_status_test() {
	active_key=$1
	key_dir=$2
	GOAUTHY_E2E_MASTER_KEY_STATUS=1 \
	GOAUTHY_E2E_DATA_DIR="$data_dir" \
	GOAUTHY_E2E_MASTER_KEY_DIR="$key_dir" \
	GOAUTHY_E2E_ISSUER="$issuer" \
	GOAUTHY_E2E_ACTIVE_MASTER_KEY_ID="$active_key" \
	go test -count=1 ./test/e2e -run '^TestStandaloneMasterKeyStatus$'
}

jwks() {
	curl --fail --silent --show-error "$issuer/oidc/jwks.json"
}

operator_auth() {
	printf 'API-Key rotation-operator$%s' "$operator_secret"
}

retirement_get() {
	curl --fail --silent --show-error --max-time 5 \
		-H "Authorization: $(operator_auth)" \
		"$issuer/auth/v1/master_key_retirement"
}

retirement_post() {
	action=$1
	body=$2
	curl --fail --silent --show-error --max-time 5 \
		-H "Authorization: $(operator_auth)" \
		-H 'Content-Type: application/json' \
		--data "$body" \
		"$issuer/auth/v1/master_key_retirement/$action"
}

# Standalone persistent DB: A creates the encrypted signing/DCR data and a
# cold restart keeps it. The API below exercises the exact-one standalone
# barrier; exact-three membership remains a cluster-only contract.
start "$master_key_dir" key-a
first_jwks=$(jwks)
first_kid=$(printf '%s' "$first_jwks" | jq -er '.keys[0].kid')
first_count=$(printf '%s' "$first_jwks" | jq -er '.keys | length')
[ "$first_count" -gt 0 ]
curl --fail --silent --show-error \
	-H 'Content-Type: application/json' \
	-H 'Idempotency-Key: standalone-master-key-rotation' \
	--data '{"redirect_uris":["https://rotation.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"standalone master-key rotation"}' \
	"$issuer/oidc/register" | jq -e '.client_id != ""' >/dev/null
stop_graceful
test -s "$data_dir/sqlite.db"
test -d "$data_dir/qlog"
run_status_test key-a "$master_key_dir"

# Restart with both keys available and B active. The startup worker runs one
# bounded pass before serving; JWKS continuity plus the stopped-process status
# check below proves the A-created envelope was authenticated and rewrapped.
cp "$master_key_dir/key-a" "$temp_dir/key-a-before"
cp "$replacement_key_dir/key-b" "$master_key_dir/key-b"
start "$master_key_dir" key-b
second_jwks=$(jwks)
second_kid=$(printf '%s' "$second_jwks" | jq -er '.keys[0].kid')
second_count=$(printf '%s' "$second_jwks" | jq -er '.keys | length')
[ "$second_kid" = "$first_kid" ] || { echo 'master-key restart changed persisted signing kid' >&2; exit 1; }
[ "$second_count" = "$first_count" ] || { echo 'master-key restart changed persisted signing-key count' >&2; exit 1; }

# The operator API is authenticated by a key with only the Secrets rights
# needed for this lifecycle. Fence is the commit point: A writers are then
# rejected while B writers remain admitted.
prepared=$(retirement_post prepare '{"epoch":1,"old_key_id":"key-a","replacement_key_id":"key-b"}')
printf '%s' "$prepared" | jq -e '.state == "prepared" and (.membership | length) == 1 and .membership[0] == "standalone-master-key-0"' >/dev/null
fenced=$(retirement_post fence '{"epoch":1}')
printf '%s' "$fenced" | jq -e '.state == "fenced" and .replacement_key_id == "key-b"' >/dev/null

# The worker ticks once per minute. Poll the authenticated status until the
# one fresh post-fence attestation appears; every status field must be zero.
attestation=
for _ in $(seq 1 90); do
	snapshot=$(retirement_get)
	if printf '%s' "$snapshot" | jq -e '
		.state == "fenced" and (.attestations | length) == 1 and
		.attestations[0].node_id == "standalone-master-key-0" and
		.attestations[0].active_key_id == "key-b" and
		(.attestations[0].boot_id | length) > 0 and
		.attestations[0].attestation_sequence == 1 and
		([.attestations[0].status.old_references,
		  .attestations[0].status.non_active_references,
		  .attestations[0].status.legacy_references,
		  .attestations[0].status.tamper_references,
		  .attestations[0].status.oidc_references,
		  .attestations[0].status.dcr_references,
		  .attestations[0].status.upstream_references,
		  .attestations[0].status.passkey_references] | all(.[]; . == 0))' >/dev/null; then
		attestation=$snapshot
		break
	fi
	sleep 1
done
[ -n "$attestation" ] || { echo 'timed out waiting for a fresh key-retirement attestation' >&2; exit 1; }
first_boot=$(printf '%s' "$attestation" | jq -er '.attestations[0].boot_id')
first_sequence=$(printf '%s' "$attestation" | jq -er '.attestations[0].attestation_sequence')

# Restart while still fenced. The new boot must replace the prior attestation
# with a distinct boot ID and a higher sequence before ready is allowed.
stop_graceful
start "$master_key_dir" key-b
second_attestation=
for _ in $(seq 1 90); do
	snapshot=$(retirement_get)
	if printf '%s' "$snapshot" | jq -e --arg boot "$first_boot" --argjson sequence "$first_sequence" '
		.state == "fenced" and (.attestations | length) == 1 and
		.attestations[0].node_id == "standalone-master-key-0" and
		.attestations[0].active_key_id == "key-b" and
		(.attestations[0].boot_id | length) > 0 and
		.attestations[0].boot_id != $boot and
		.attestations[0].attestation_sequence > $sequence and
		([.attestations[0].status.old_references,
		  .attestations[0].status.non_active_references,
		  .attestations[0].status.legacy_references,
		  .attestations[0].status.tamper_references,
		  .attestations[0].status.oidc_references,
		  .attestations[0].status.dcr_references,
		  .attestations[0].status.upstream_references,
		  .attestations[0].status.passkey_references] | all(.[]; . == 0))' >/dev/null; then
		second_attestation=$snapshot
		break
	fi
	sleep 1
done
[ -n "$second_attestation" ] || { echo 'timed out waiting for fresh-boot re-attestation' >&2; exit 1; }
second_boot=$(printf '%s' "$second_attestation" | jq -er '.attestations[0].boot_id')
ready=$(retirement_post ready '{"epoch":1}')
printf '%s' "$ready" | jq -e '.state == "ready" and (.attestations | length) == 1' >/dev/null
ready_boot=$(printf '%s' "$ready" | jq -er '.attestations[0].boot_id')
[ "$ready_boot" = "$second_boot" ]

stop_graceful
run_status_test key-b "$master_key_dir"

# A ready barrier denies an old A process before it can serve or write.
old_server_log=$temp_dir/old-key-server.log
GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-master-key-e2e \
	GOAUTHY_NODE_ID=standalone-master-key-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$old_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=key-a \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_API_KEY_BOOTSTRAP_FILE="$temp_dir/operator-keys" \
	"$binary" >"$old_server_log" 2>&1 &
old_pid=$!
for _ in $(seq 1 100); do
	if ! kill -0 "$old_pid" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if kill -0 "$old_pid" 2>/dev/null; then
	kill -TERM "$old_pid" >/dev/null 2>&1 || true
	wait "$old_pid" 2>/dev/null || true
	echo 'old key process was admitted after retirement ready' >&2
	cat "$old_server_log" >&2
	exit 1
fi
grep -F 'master-key runtime admission denied' "$old_server_log" >/dev/null || {
	echo 'old key process did not report admission denial' >&2
	cat "$old_server_log" >&2
	exit 1
}

# Restart B after the terminal transition. A fresh boot preserves the ready
# barrier and does not replace its completed attestation with a new identity.
start "$master_key_dir" key-b
after_restart=$(retirement_get)
printf '%s' "$after_restart" | jq -e --arg boot "$ready_boot" '.state == "ready" and .attestations[0].boot_id == $boot' >/dev/null
stop_graceful

# A fresh process with only B is a cryptographic proof that no live envelope
# still needs A. It also emits the sanitized safe=true status evidence.
start "$replacement_key_dir" key-b
third_jwks=$(jwks)
third_kid=$(printf '%s' "$third_jwks" | jq -er '.keys[0].kid')
[ "$third_kid" = "$first_kid" ] || { echo 'B-only restart changed persisted signing kid' >&2; exit 1; }
grep -F 'master-key reference status active_master_key_id=key-b safe=true scan_error=false' "$server_log" >/dev/null || {
	echo 'B-only startup did not report safe master-key status' >&2
	cat "$server_log" >&2
	exit 1
}
stop_graceful

# Retirement never removes key material automatically. A remains provisioned,
# unchanged, and the A-created signing row remains readable after B-only boot.
test -f "$master_key_dir/key-a"
test -f "$master_key_dir/key-b"
cmp "$temp_dir/key-a-before" "$master_key_dir/key-a"
run_status_test key-b "$replacement_key_dir"
echo 'standalone master-key rotation, rewrap, status, and no-deletion E2E passed'
