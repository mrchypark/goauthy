#!/bin/sh
set -eu

# Re-exec without inherited deployment, OAuth, proxy, or cloud configuration.
if [ "${1:-}" != --isolated ]; then
	exec env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
		GOAUTHY_ELY_E2E_SLOT="${GOAUTHY_ELY_E2E_SLOT:-}" \
		GOAUTHY_ELY_E2E_PORT="${GOAUTHY_ELY_E2E_PORT:-18480}" \
		GOMAXPROCS=2 GOWORK=off /bin/sh "$0" --isolated "$@"
fi
shift
mode=${1:---check}
case "$mode" in --check|--run|--run-extra|--run-boundary) ;; *) echo 'usage: e2e-ely-standalone.sh [--check|--run|--run-extra|--run-boundary]' >&2; exit 2;; esac
[ "$#" -le 1 ] || exit 2
port=$GOAUTHY_ELY_E2E_PORT
case "$port" in ''|*[!0-9]*|0*) echo 'fixture port must be a decimal integer without leading zeros' >&2; exit 2;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65531 ] || { echo 'fixture port must be 1024..65531' >&2; exit 2; }
for tool in go curl nc mktemp sed grep ps date tee git rg sort shasum cut openssl; do
	command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"
for source in cmd/goauthy/main.go cmd/goauthy-smtp-sink/main.go cmd/goauthy-demo/main.go test/e2e/browser/ely_ui_test.go; do
	[ -f "$source" ] || { echo "missing fixture source: $source" >&2; exit 1; }
done
if [ "$mode" = --check ]; then
	echo 'Fixture prerequisites found. No builds, listeners, browser tests, or deployment mutations performed.'
	echo 'Run after parent grants the serial slot: GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run'
	echo 'Boundary-only mode: GOAUTHY_ELY_E2E_SLOT=granted sh scripts/e2e-ely-standalone.sh --run-boundary'
	exit 0
fi
[ "$GOAUTHY_ELY_E2E_SLOT" = granted ] || { echo 'parent serial build/E2E slot required; set GOAUTHY_ELY_E2E_SLOT=granted only after allocation' >&2; exit 2; }
umask 077
. "$script_dir/e2e-port-lock.sh"
temp_dir=$(mktemp -d "${TMPDIR%/}/goauthy-ely-e2e.XXXXXX")
receipt=$temp_dir/receipt.txt
public_receipt=$root/test/e2e/ELY-RECEIPT.txt
report() { printf '%s\n' "$*" | tee -a "$receipt" "$public_receipt"; }
server_pid= smtp_pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for child in "$server_pid" "$smtp_pid"; do
		if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
	done
	e2e_port_lock_release
	if [ "$status" -eq 0 ]; then
		rm -rf "$temp_dir"
	else
		echo "Fixture failed; private diagnostics retained at $temp_dir (may contain synthetic tokens; do not publish raw logs)." >&2
	fi
	exit "$status"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 1 15
e2e_port_lock_acquire
report "ATTEMPT started UTC=$(date -u +%FT%TZ) mode=$mode candidate=$(git rev-parse HEAD)"
source_digest() {
	{ rg --files cmd internal test/e2e/browser; printf '%s\n' go.mod go.sum scripts/e2e-port-lock.sh scripts/e2e-ely-standalone.sh scripts/test-e2e-ely-standalone.sh; } |
		LC_ALL=C sort | while IFS= read -r source; do shasum -a 256 "$source"; done |
		shasum -a 256 | cut -d ' ' -f 1
}
initial_digest=$(source_digest)
report "SOURCE_SHA256 $initial_digest"
for reserved in "$port" "$((port + 1))" "$((port + 2))" "$((port + 3))" "$((port + 4))"; do
	if nc -z 127.0.0.1 "$reserved" >/dev/null 2>&1; then echo "fixture port $reserved is occupied" >&2; exit 1; fi
done
mkdir -p "$temp_dir/data" "$temp_dir/master-keys"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/master-keys/dev-1"
cp "$temp_dir/master-keys/dev-1" "$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/reset-key"
cp "$temp_dir/reset-key" "$temp_dir/passkey-key"
printf '{"providers":[{"id":"ely-catalog","kind":"oauth2","client_id":"synthetic-client","client_secret_file":"%s","callback_uri":"https://identity.example.test/callback","auth_endpoint":"https://provider.example.test/authorize","token_endpoint":"https://provider.example.test/token","scopes":["read"],"auth_style":"header"}]}\n' "$temp_dir/bootstrap-client" >"$temp_dir/providers.json"
sed -n '/^    /s/^    //p' deploy/k8s/password-reset/email-templates.yaml >"$temp_dir/email-templates.toml"
printf '%s\n' correct-horse-browser-staple | go run -mod=readonly -p=1 ./cmd/goauthy-password >"$temp_dir/password-phc" 2>"$temp_dir/password-build.log"
if [ "$mode" = --run-boundary ]; then
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp_dir/ca.key" -out "$temp_dir/ca.pem" -subj '/CN=GoAuthy Ely boundary E2E CA' -days 1 >/dev/null 2>&1
	openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/goauthy.key" -out "$temp_dir/goauthy.csr" -subj '/CN=localhost' >/dev/null 2>&1
	printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' >"$temp_dir/goauthy.ext"
	openssl x509 -req -in "$temp_dir/goauthy.csr" -CA "$temp_dir/ca.pem" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/goauthy.pem" -days 1 -extfile "$temp_dir/goauthy.ext" >/dev/null 2>&1
	tls_cert_file=$temp_dir/goauthy.pem
	tls_key_file=$temp_dir/goauthy.key
	base=https://localhost:$port
	export SSL_CERT_FILE="$temp_dir/ca.pem" CURL_CA_BUNDLE="$temp_dir/ca.pem"
else
	tls_cert_file=
	tls_key_file=
	base=http://localhost:$port
fi
report 'BUILD started: standalone server and boundary browser test; serial -p=1.'
go build -mod=readonly -p=1 -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy >"$temp_dir/server-build.log" 2>&1
go build -mod=readonly -p=1 -trimpath -o "$temp_dir/smtp-sink" ./cmd/goauthy-smtp-sink >"$temp_dir/smtp-build.log" 2>&1
go build -mod=readonly -p=1 -trimpath -o "$temp_dir/demo" ./cmd/goauthy-demo >"$temp_dir/demo-build.log" 2>&1
go test -mod=readonly -p=1 -c -o "$temp_dir/browser.test" ./test/e2e/browser >"$temp_dir/browser-build.log" 2>&1
report 'BUILD passed: current candidate compiled successfully.'
"$temp_dir/smtp-sink" -smtp-addr "127.0.0.1:$((port + 1))" -http-addr "127.0.0.1:$((port + 2))" >"$temp_dir/smtp.log" 2>&1 &
smtp_pid=$!
export GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="$base" GOAUTHY_TLS_CERT_FILE="$tls_cert_file" GOAUTHY_TLS_KEY_FILE="$tls_key_file" GOAUTHY_RHIZA_PROFILE=standalone
export GOAUTHY_CLUSTER_ID=ely-disposable GOAUTHY_NODE_ID=ely-disposable-0 GOAUTHY_DATA_DIR="$temp_dir/data"
export GOAUTHY_MASTER_KEY_DIR="$temp_dir/master-keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1
export GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client"
export GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/password-phc"
export GOAUTHY_BOOTSTRAP_FORCE_MFA=false GOAUTHY_PASSKEY_RP_ID=localhost GOAUTHY_PASSKEY_ORIGINS="$base" GOAUTHY_PASSKEY_KEY_FILE="$temp_dir/passkey-key" GOAUTHY_PASSKEY_FORCE_UV=true
export GOAUTHY_SAAS_PROVIDERS_FILE="$temp_dir/providers.json"
export GOAUTHY_BOOTSTRAP_USER_EMAIL=admin@goauthy.e2e GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]'
export GOAUTHY_PASSWORD_RECOVERY_ENABLED=true GOAUTHY_PASSWORD_RESET_KEY_FILE="$temp_dir/reset-key"
export GOAUTHY_POW_DIFFICULTY=10 GOAUTHY_POW_EXPIRY=30s
export GOAUTHY_SMTP_HOST=127.0.0.1 GOAUTHY_SMTP_PORT="$((port + 1))" GOAUTHY_SMTP_FROM=support@goauthy.e2e GOAUTHY_SMTP_ALLOW_INSECURE=true
export GOAUTHY_EMAIL_TEMPLATES_FILE="$temp_dir/email-templates.toml" GOAUTHY_EMAIL_TEMPLATE_LANG=ko
wait_ready() {
	ready_url=$1
	ready_pid=$2
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		kill -0 "$ready_pid" 2>/dev/null || return 1
		if curl --noproxy '*' --max-time 1 --fail --silent "$ready_url" >/dev/null 2>&1; then return 0; fi
		attempt=$((attempt + 1))
		sleep 1
	done
	echo 'fixture readiness timed out' >&2
	return 1
}
start_server() {
	"$temp_dir/goauthy" >>"$temp_dir/server.log" 2>&1 &
	server_pid=$!
	wait_ready "$base/livez" "$server_pid"
	wait_ready "$base/readyz" "$server_pid"
}
wait_ready "http://127.0.0.1:$((port + 2))/livez" "$smtp_pid"
start_server
report 'FIXTURE ready: fresh standalone data, loopback-only listeners, local synthetic SMTP; no production mutations.'
export GOAUTHY_E2E_URL="$base" GOAUTHY_E2E_SECONDARY_URL="$base" GOAUTHY_E2E_TERTIARY_URL="$base"
export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple
export GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_BROWSER_EMAIL=admin@goauthy.e2e
export GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((port + 2))"
export GOAUTHY_E2E_ELY_UI=1 GOAUTHY_E2E_ADMIN_UI_BROWSER=1 GOAUTHY_E2E_MANAGED_CLIENTS_UI=1 GOAUTHY_E2E_ADMIN_CATALOG_SESSIONS_UI=1 GOAUTHY_E2E_ADMIN_API_KEY_UI=1
export GOAUTHY_E2E_ACCOUNT_DASHBOARD=1 GOAUTHY_E2E_AUTH_COLLECTIONS_UI=1 GOAUTHY_E2E_THEME_UI=1 GOAUTHY_E2E_THEME=1 GOAUTHY_E2E_LOGO=1
export GOAUTHY_E2E_DEVICE_OIDC=1 GOAUTHY_E2E_DEVICE_OIDC_UI=1
export GOAUTHY_E2E_THEME_STATE_FILE="$temp_dir/theme.json" GOAUTHY_E2E_LOGO_STATE_FILE="$temp_dir/logo.json"
export GOAUTHY_E2E_DEMO_BINARY="$temp_dir/demo"
export GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1 GOAUTHY_E2E_PROVIDER_REGISTRATION=1 GOAUTHY_E2E_SAAS_PROVIDERS=1 GOAUTHY_E2E_SAAS_PROVIDER_ID=ely-catalog
run_test() {
	test_name=$1
	report "RUN $test_name"
	if ! "$temp_dir/browser.test" -test.v -test.parallel=1 -test.timeout=5m -test.run "^$test_name\$" >"$temp_dir/$test_name.log" 2>&1; then
		report "FAIL $test_name (private diagnostic only; no pass claimed)"
		return 1
	fi
	if ! grep -q "^--- PASS: $test_name " "$temp_dir/$test_name.log" || grep -q -- '--- SKIP:' "$temp_dir/$test_name.log"; then
		report "FAIL $test_name: missing pass or skipped coverage"
		return 1
	fi
	report "PASS $test_name"
}
failures=0
finish() {
	if [ "$(source_digest)" != "$initial_digest" ]; then report 'FAIL source drift: results cannot certify final working tree'; failures=$((failures + 1)); fi
	report "FINISHED mode=$mode: $failures failed gates; source=$initial_digest. See ELY-COVERAGE.md for untested scope; no HA or whole-product completion claim."
	[ "$failures" -eq 0 ]
}
base_tests='TestElyBrowserLoginLogout TestAdminUIBrowserAcrossPods TestManagedClientsUIAcrossPods TestAdminCatalogSessionsUIAcrossPods TestAdminAPIKeyUIAcrossPods TestAuthCollectionsUIAcrossPods TestAccountDashboardAcrossPods TestThemeLive TestClientLogoLive TestElyBrandUI TestElyDemoSSO TestDeviceOIDCLive TestThemeLoginUI TestThemePersistPrepare TestClientLogoPersistPrepare'
extra_tests='TestThemeLoginUI TestAccountPasskeyUIAcrossPods TestSaaSProvidersCatalog TestProviderRegistrationLive'
if [ "$mode" = --run-boundary ]; then
	if ! run_test TestConnectionOAuth2ProviderRegistrationBoundary; then failures=$((failures + 1)); fi
	finish
	exit 0
fi
if [ "$mode" = --run-extra ]; then
	for test_name in $extra_tests; do
		if ! run_test "$test_name"; then failures=$((failures + 1)); fi
	done
	finish
	exit 0
fi
for test_name in $base_tests TestAccountPasskeyUIAcrossPods TestSaaSProvidersCatalog TestProviderRegistrationLive; do
	if ! run_test "$test_name"; then failures=$((failures + 1)); fi
done
kill -TERM "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=
start_server
for test_name in TestThemePersistVerify TestClientLogoPersistVerify; do
	if ! run_test "$test_name"; then failures=$((failures + 1)); fi
done
# Recovery changes the disposable bootstrap password and revokes its sessions.
if ! run_test TestPasswordResetAcrossPods; then failures=$((failures + 1)); fi
finish
