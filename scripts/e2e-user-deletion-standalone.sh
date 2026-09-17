#!/bin/sh
# Runs deterministic browser and API-key user deletion against one standalone
# process. The SMTP and SCIM fixtures are disposable local services: deleted
# identities must disappear remotely, and a cold restart must not revive their
# credentials or bypass final-admin protection.
set -eu

for command in cat curl dirname go jq nc openssl seq sleep tail sed; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_STANDALONE_USER_DELETE_PORT:-18089}
case "$port" in
	''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_USER_DELETE_PORT must be a decimal TCP port' >&2; exit 1 ;;
esac
[ "$port" -ge 1024 ] && [ "$port" -le 65531 ] || {
	echo 'GOAUTHY_STANDALONE_USER_DELETE_PORT must leave room for four fixture ports' >&2
	exit 1
}
scim_port=$((port + 1))
scim_admin_port=$((port + 2))
smtp_port=$((port + 3))
smtp_http_port=$((port + 4))

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
e2e_port_lock_acquire
for candidate in "$port" "$scim_port" "$scim_admin_port" "$smtp_port" "$smtp_http_port"; do
	if nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
		echo "standalone user-deletion port $candidate is already in use" >&2
		e2e_port_lock_release
		exit 1
	fi
	done

umask 077
temp_dir=$(mktemp -d)
goauthy_pid=
scim_pid=
smtp_pid=
base=http://127.0.0.1:$port

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$status" -ne 0 ]; then
		curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" 2>/dev/null | jq -c '{mode,users,calls}' >&2 || true
		for log in "$temp_dir/goauthy.log" "$temp_dir/scim.log" "$temp_dir/smtp.log"; do
			test ! -s "$log" || tail -n 80 "$log" | sed 's/^/[e2e] /' >&2
		done
	fi
	for process in "$goauthy_pid" "$scim_pid" "$smtp_pid"; do
		if [ -n "$process" ]; then
			kill "$process" >/dev/null 2>&1 || true
			wait "$process" 2>/dev/null || true
		fi
	done
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/password-reset-key"
printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-phc"
printf '%s\n' scim-user-delete-token >"$temp_dir/scim-token"

api_key_secret=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01
printf '%s\n' '[{"name":"standalone-users","secret":{"Plain":"'"$api_key_secret"'"},"access":[{"group":"Users","access_rights":["delete"]}]}]' >"$temp_dir/api-keys.json"
printf '%s\n' 'subject-placeholder' >"$temp_dir/deleted-subject"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp_dir/ca.key" -out "$temp_dir/ca.pem" -subj '/CN=GoAuthy user-delete E2E CA' -days 1 >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/scim.key" -out "$temp_dir/scim.csr" -subj '/CN=localhost' >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' >"$temp_dir/scim.ext"
openssl x509 -req -in "$temp_dir/scim.csr" -CA "$temp_dir/ca.pem" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/scim.pem" -days 1 -extfile "$temp_dir/scim.ext" >/dev/null 2>&1
printf '{"providers":[{"id":"fixture","base_url":"https://127.0.0.1:%s/scim/v2","token_file":"%s","ca_file":"%s","sync_delete_users":true}]}\n' "$scim_port" "$temp_dir/scim-token" "$temp_dir/ca.pem" >"$temp_dir/scim-providers.json"

cd "$(CDPATH='' cd -- "$script_dir/.." && pwd)"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
go build -trimpath -o "$temp_dir/scim-fixture" ./cmd/goauthy-scim-fixture
go build -trimpath -o "$temp_dir/smtp-sink" ./cmd/goauthy-smtp-sink

start_fixtures() {
	SCIM_FIXTURE_ADDR="127.0.0.1:$scim_port" SCIM_FIXTURE_ADMIN_ADDR="127.0.0.1:$scim_admin_port" SCIM_FIXTURE_TLS_CERT_FILE="$temp_dir/scim.pem" SCIM_FIXTURE_TLS_KEY_FILE="$temp_dir/scim.key" SCIM_FIXTURE_BEARER_TOKEN=scim-user-delete-token "$temp_dir/scim-fixture" >"$temp_dir/scim.log" 2>&1 &
	scim_pid=$!
	"$temp_dir/smtp-sink" -smtp-addr "127.0.0.1:$smtp_port" -http-addr "127.0.0.1:$smtp_http_port" >"$temp_dir/smtp.log" 2>&1 &
	smtp_pid=$!
	for _ in $(seq 1 300); do
		if ! kill -0 "$scim_pid" 2>/dev/null || ! kill -0 "$smtp_pid" 2>/dev/null; then
			cat "$temp_dir/scim.log" "$temp_dir/smtp.log" >&2
			return 1
		fi
		if curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" >/dev/null 2>&1 && curl --fail --silent "http://127.0.0.1:$smtp_http_port/livez" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

start_goauthy() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-user-delete-e2e \
	GOAUTHY_NODE_ID=standalone-user-delete-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_SUBJECT=bootstrap-admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-phc" \
	GOAUTHY_BOOTSTRAP_USER_EMAIL=admin@goauthy.e2e \
	GOAUTHY_PASSWORD_RECOVERY_ENABLED=true \
	GOAUTHY_PASSWORD_RESET_KEY_FILE="$temp_dir/password-reset-key" \
	GOAUTHY_OPEN_USER_REG=true \
	GOAUTHY_USER_REG_DOMAIN_RESTRICTION=goauthy.e2e \
	GOAUTHY_POW_DIFFICULTY=10 \
	GOAUTHY_SMTP_HOST=127.0.0.1 \
	GOAUTHY_SMTP_PORT="$smtp_port" \
	GOAUTHY_SMTP_FROM=support@goauthy.e2e \
	GOAUTHY_SMTP_ALLOW_INSECURE=true \
	GOAUTHY_SCIM_PROVIDERS_FILE="$temp_dir/scim-providers.json" \
	GOAUTHY_API_KEY_BOOTSTRAP_FILE="$temp_dir/api-keys.json" \
	GOAUTHY_ENABLE_SELF_DELETE=true \
	"$temp_dir/goauthy" >"$temp_dir/goauthy.log" 2>&1 &
	goauthy_pid=$!
	for _ in $(seq 1 300); do
		if ! kill -0 "$goauthy_pid" 2>/dev/null; then
			cat "$temp_dir/goauthy.log" >&2
			return 1
		fi
		if curl --fail --silent "$base/livez" >/dev/null 2>&1 && curl --fail --silent "$base/readyz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	cat "$temp_dir/goauthy.log" >&2
	return 1
}

stop_goauthy() {
	target=$goauthy_pid
	kill -TERM "$target"
	for _ in $(seq 1 300); do
		if ! kill -0 "$target" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done
	if kill -0 "$target" 2>/dev/null; then
		echo 'standalone user-delete process did not exit after bounded SIGTERM wait' >&2
		return 1
	fi
	wait "$target" 2>/dev/null || true
	goauthy_pid=
}

run_browser_phase() {
	phase=$1
	GOAUTHY_E2E_USER_DELETE_PHASE="$phase" \
	GOAUTHY_E2E_URL="$base" \
	GOAUTHY_E2E_SECONDARY_URL="$base" \
	GOAUTHY_E2E_TERTIARY_URL="$base" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" \
	go test -count=1 ./test/e2e/browser -run '^TestUserDeletionAcrossPods$'
}

run_api_phase() {
	mode=$1
	GOAUTHY_E2E_USER_DELETE_API_KEY='standalone-users$'"$api_key_secret" \
	GOAUTHY_E2E_USER_DELETE_API_KEY_MODE="$mode" \
	GOAUTHY_E2E_USER_DELETE_SUBJECT_FILE="$temp_dir/deleted-subject" \
	GOAUTHY_E2E_URL="$base" \
	GOAUTHY_E2E_SECONDARY_URL="$base" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$scim_admin_port" \
	GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$smtp_http_port" \
	go test -count=1 ./test/e2e/browser -run '^TestStandaloneUserDeletionAPIKey$'
}

run_after_restart() {
	GOAUTHY_E2E_USER_DELETE_AFTER_RESTART=1 \
	GOAUTHY_E2E_URL="$base" \
	GOAUTHY_E2E_SECONDARY_URL="$base" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	go test -count=1 ./test/e2e/browser -run '^TestStandaloneUserDeletionAfterRestart$'
}

wait_for_remote_clean() {
	for _ in $(seq 1 300); do
		if curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" | jq -e '[.users[] | select(.externalId != "bootstrap-admin")] | length == 0' >/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	echo 'timed out waiting for remote SCIM deletion of all non-admin users' >&2
	curl --fail --silent "http://127.0.0.1:$scim_admin_port/admin/state" >&2 || true
	return 1
}

start_fixtures
start_goauthy
run_browser_phase before-replacement
# The production SCIM worker runs an immediate pass on boot and then its
# five-minute interval. Keep the created user local through this first pass,
# reboot once to make the provider mapping observable, then delete via the
# public API and reboot again so the durable tombstone's DELETE is dispatched.
run_api_phase create
stop_goauthy
start_goauthy
run_api_phase delete
stop_goauthy
start_goauthy
run_after_restart
wait_for_remote_clean
stop_goauthy
echo 'standalone admin/self/API-key user deletion and SCIM tombstone E2E passed'
