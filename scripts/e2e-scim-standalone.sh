#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

for command in curl go jq nc openssl; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done

port=${GOAUTHY_STANDALONE_PORT:-18081}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65531 ] || { echo 'GOAUTHY_STANDALONE_PORT must leave room for four fixture ports (1024..65531)' >&2; exit 1; }
scim_failure_events=${GOAUTHY_SCIM_FAILURE_EVENTS:-0}
case "$scim_failure_events" in
	0|1)
		failure_test=TestSCIMFailureEvents
		persistence_test=TestSCIMFailureEventPersisted
		failure_flag=GOAUTHY_E2E_SCIM_FAILURE_EVENTS
		persistence_flag=GOAUTHY_E2E_SCIM_FAILURE_EVENT_PERSISTENCE
		;;
	resources)
		failure_test=TestSCIMResourceFailureEvents
		persistence_test=TestSCIMResourceFailureEventsPersisted
		failure_flag=GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS
		persistence_flag=GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS_PERSISTENCE
		;;
	*) echo 'GOAUTHY_SCIM_FAILURE_EVENTS must be 0, 1 or resources' >&2; exit 1;;
esac
scim_port=$((port + 1))
scim_admin_port=$((port + 2))
smtp_port=$((port + 3))
smtp_http_port=$((port + 4))
e2e_port_lock_acquire
for candidate in "$port" "$scim_port" "$scim_admin_port" "$smtp_port" "$smtp_http_port"; do
	nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1 && { echo "standalone SCIM E2E port $candidate is already in use; choose GOAUTHY_STANDALONE_PORT" >&2; e2e_port_lock_release; exit 1; }
done

umask 077
temp_dir=$(mktemp -d)
goauthy_pid=
scim_pid=
smtp_pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$status" -ne 0 ]; then
		curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" 2>/dev/null | jq -c '{mode,users,calls}' >&2 || true
		for log in "$temp_dir/goauthy.log" "$temp_dir/scim.log" "$temp_dir/smtp.log"; do test ! -s "$log" || tail -n 80 "$log" | sed 's/^/[e2e] /' >&2; done
	fi
	for pid in "$goauthy_pid" "$scim_pid" "$smtp_pid"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
interrupted() { exit 130; }
terminated() { exit 143; }
trap cleanup 0
trap interrupted 1 2
trap terminated 15

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/password-reset-key"
printf '%s\n' 'correct-horse-browser-staple' | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-phc"
printf '%s\n' scim-e2e-token >"$temp_dir/scim-token"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp_dir/ca.key" -out "$temp_dir/ca.pem" -subj '/CN=GoAuthy SCIM E2E CA' -days 1 >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/scim.key" -out "$temp_dir/scim.csr" -subj '/CN=localhost' >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' >"$temp_dir/scim.ext"
openssl x509 -req -in "$temp_dir/scim.csr" -CA "$temp_dir/ca.pem" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/scim.pem" -days 1 -extfile "$temp_dir/scim.ext" >/dev/null 2>&1
printf '{"providers":[{"id":"fixture","base_url":"https://127.0.0.1:%s/scim/v2","token_file":"%s","ca_file":"%s","sync_delete_users":true}]}' "$scim_port" "$temp_dir/scim-token" "$temp_dir/ca.pem" >"$temp_dir/scim-providers.json"

go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
go build -trimpath -o "$temp_dir/scim-fixture" ./cmd/goauthy-scim-fixture
go build -trimpath -o "$temp_dir/smtp-sink" ./cmd/goauthy-smtp-sink

start_fixture() {
	SCIM_FIXTURE_ADDR="127.0.0.1:$scim_port" SCIM_FIXTURE_ADMIN_ADDR="127.0.0.1:$scim_admin_port" SCIM_FIXTURE_TLS_CERT_FILE="$temp_dir/scim.pem" SCIM_FIXTURE_TLS_KEY_FILE="$temp_dir/scim.key" SCIM_FIXTURE_BEARER_TOKEN=scim-e2e-token "$temp_dir/scim-fixture" >"$temp_dir/scim.log" 2>&1 &
	scim_pid=$!
	"$temp_dir/smtp-sink" -smtp-addr "127.0.0.1:$smtp_port" -http-addr "127.0.0.1:$smtp_http_port" >"$temp_dir/smtp.log" 2>&1 &
	smtp_pid=$!
	for _ in $(seq 1 300); do
		kill -0 "$scim_pid" 2>/dev/null && kill -0 "$smtp_pid" 2>/dev/null || { cat "$temp_dir/scim.log" "$temp_dir/smtp.log" >&2; return 1; }
		curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" >/dev/null 2>&1 && curl --fail --silent "http://127.0.0.1:$smtp_http_port/livez" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	cat "$temp_dir/scim.log" "$temp_dir/smtp.log" >&2
	return 1
}

start_goauthy() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="http://127.0.0.1:$port" GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=standalone-scim-e2e GOAUTHY_NODE_ID=standalone-scim-0 GOAUTHY_DATA_DIR="$data_dir" GOAUTHY_MASTER_KEY_DIR="$master_key_dir" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-phc" GOAUTHY_BOOTSTRAP_USER_EMAIL=admin@goauthy.e2e GOAUTHY_PASSWORD_RECOVERY_ENABLED=true GOAUTHY_PASSWORD_RESET_KEY_FILE="$temp_dir/password-reset-key" GOAUTHY_OPEN_USER_REG=true GOAUTHY_USER_REG_DOMAIN_RESTRICTION=goauthy.e2e GOAUTHY_POW_DIFFICULTY=10 GOAUTHY_SMTP_HOST=127.0.0.1 GOAUTHY_SMTP_PORT="$smtp_port" GOAUTHY_SMTP_FROM=support@goauthy.e2e GOAUTHY_SMTP_ALLOW_INSECURE=true GOAUTHY_SCIM_PROVIDERS_FILE="$temp_dir/scim-providers.json" "$temp_dir/goauthy" >"$temp_dir/goauthy.log" 2>&1 &
	goauthy_pid=$!
	for _ in $(seq 1 300); do
		kill -0 "$goauthy_pid" 2>/dev/null || { cat "$temp_dir/goauthy.log" >&2; return 1; }
		curl --fail --silent "http://127.0.0.1:$port/livez" >/dev/null 2>&1 && curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	cat "$temp_dir/goauthy.log" >&2
	return 1
}

restart_goauthy() {
	kill "$goauthy_pid" >/dev/null 2>&1 || true
	wait "$goauthy_pid" 2>/dev/null || true
	goauthy_pid=
	start_goauthy
}

fixture_state() { curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state"; }
wait_for_created() {
	subject=$1
	for _ in $(seq 1 300); do
		fixture_state | jq -e --arg subject "$subject" '[.users[] | select(.externalId == $subject)] | length == 1' >/dev/null && return 0
		sleep 0.1
	done
	echo 'timed out waiting for remote SCIM user creation' >&2
	fixture_state >&2 || true
	cat "$temp_dir/goauthy.log" >&2
	return 1
}
wait_for_deleted() {
	subject=$1
	path=$2
	for _ in $(seq 1 300); do
		fixture_state | jq -e --arg subject "$subject" --arg path "$path" '([.users[] | select(.externalId == $subject)] | length == 0) and any(.calls[]; .method == "DELETE" and .path == $path)' >/dev/null && return 0
		sleep 0.1
	done
	echo 'timed out waiting for remote SCIM delete' >&2
	fixture_state >&2 || true
	cat "$temp_dir/goauthy.log" >&2
	return 1
}

start_fixture
start_goauthy
run_failure_events() {
	env "$failure_flag=1" GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE="$temp_dir/scim-failure-event.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$scim_admin_port" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -timeout=28m -v -count=1 ./test/e2e/browser -run "^$failure_test\$"
	restart_goauthy
	env "$persistence_flag=1" GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE="$temp_dir/scim-failure-event.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$scim_admin_port" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -timeout=2m -v -count=1 ./test/e2e/browser -run "^$persistence_test\$"
}
if [ "$scim_failure_events" != 0 ]; then
	run_failure_events
	echo 'standalone SCIM failure event and persistence E2E passed'
	exit 0
fi
run_phase() {
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$scim_admin_port" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_SCIM_STATE_FILE="$temp_dir/scim-subject" GOAUTHY_E2E_SCIM_GROUP_STATE_FILE="$temp_dir/scim-group" GOAUTHY_E2E_SCIM_PHASE=$1 go test -count=1 ./test/e2e/browser -run '^TestSCIMUserDeletionAcrossPods$'
}
run_create_wake() {
GOAUTHY_E2E_SCIM_CREATE_WAKE=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$scim_admin_port" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -v -count=1 ./test/e2e/browser -run '^TestSCIMAdminCreateWake$'
}
run_create_wake
run_phase create
subject=$(cat "$temp_dir/scim-subject")
group_id=$(cat "$temp_dir/scim-group")
restart_goauthy
# The first restart can terminate an in-flight initial reconciliation after
# users have been mapped but before the dependent group is enqueued. A second
# bounded restart is the deterministic retry exercised by this E2E.
restart_goauthy
wait_for_created "$subject"
wait_for_group() {
	want=$1
	for _ in $(seq 1 300); do
		state=$(fixture_state)
		if [ "$want" = created ]; then
			expected=$(printf '%s' "$state" | jq -c --arg subject "$subject" '[.users[] | select(.externalId == "bootstrap-admin" or .externalId == $subject) | .id] | sort')
		else
			expected=$(printf '%s' "$state" | jq -c '[.users[] | select(.externalId == "bootstrap-admin") | .id] | sort')
		fi
		printf '%s' "$state" | jq -e --arg group_id "$group_id" --argjson expected "$expected" '([.groups[] | select(.externalId == ("group:" + $group_id))] | length == 1) and (([.groups[] | select(.externalId == ("group:" + $group_id))][0].members | map(.value) | sort) == $expected)' >/dev/null && return 0
		sleep 0.1
	done
	echo "timed out waiting for remote SCIM group $want" >&2
	fixture_state >&2 || true
	cat "$temp_dir/goauthy.log" >&2
	return 1
}
wait_for_group created
remote_id=$(fixture_state | jq -er --arg subject "$subject" '.users[] | select(.externalId == $subject) | .id')
run_phase delete
restart_goauthy
wait_for_deleted "$subject" "/scim/v2/Users/$remote_id"
wait_for_group empty
run_phase verify-deleted
echo 'standalone SCIM E2E passed'
