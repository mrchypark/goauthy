#!/bin/sh
set -eu

if [ "${1:-}" != --isolated ]; then
	exec env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
		GOAUTHY_LOGIN_JOURNEY_SLOT="${GOAUTHY_LOGIN_JOURNEY_SLOT:-}" \
		GOAUTHY_LOGIN_JOURNEY_PORT="${GOAUTHY_LOGIN_JOURNEY_PORT:-19380}" \
		GOAUTHY_E2E_CHROME_BIN="${GOAUTHY_E2E_CHROME_BIN:-}" \
		GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
		RUNNER_TEMP="${RUNNER_TEMP:-}" GOMAXPROCS=2 GOWORK=off /bin/sh "$0" --isolated "$@"
fi
shift
mode=${1:---check}
case "$mode" in --check|--run|--manual) ;; *) echo 'usage: e2e-login-journey-standalone.sh [--check|--run|--manual]' >&2; exit 2;; esac
[ "$#" -le 1 ] || exit 2

port=$GOAUTHY_LOGIN_JOURNEY_PORT
case "$port" in ''|*[!0-9]*|0*) echo 'fixture port must be a decimal integer without leading zeros' >&2; exit 2;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65533 ] || { echo 'fixture port must be 1024..65533' >&2; exit 2; }
app_port=$((port + 1))
for tool in go curl nc mktemp ps sed grep sh; do
	command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

chrome_bin=$GOAUTHY_E2E_CHROME_BIN
if [ -z "$chrome_bin" ]; then
	for candidate in google-chrome google-chrome-stable; do
		if command -v "$candidate" >/dev/null 2>&1; then chrome_bin=$(command -v "$candidate"); break; fi
	done
	if [ -z "$chrome_bin" ] && [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then chrome_bin="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; fi
fi
[ -n "$chrome_bin" ] && [ -x "$chrome_bin" ] || { echo 'Chrome unavailable: install it on the runner or set GOAUTHY_E2E_CHROME_BIN' >&2; exit 1; }

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"
for source in cmd/goauthy/main.go cmd/goauthy-demo/main.go test/e2e/browser/login_journey_test.go test/e2e/browser/account_error_feedback_ui_test.go scripts/e2e-port-lock.sh; do
	[ -f "$source" ] || { echo "missing fixture source: $source" >&2; exit 1; }
done
if [ "$mode" = --check ]; then
	echo 'Login journey prerequisites found. No builds, listeners, or browser tests performed.'
	echo 'After the parent allocates the serial fixture slot, use --run for the journey or --manual for a temporary CUA fixture.'
	exit 0
fi
[ "$GOAUTHY_LOGIN_JOURNEY_SLOT" = granted ] || { echo 'parent serial build/E2E slot required before --run or --manual' >&2; exit 2; }

umask 077
. "$script_dir/e2e-port-lock.sh"
temp_dir=$(mktemp -d "${TMPDIR%/}/goauthy-login-journey.XXXXXX")
if [ -n "${GITHUB_RUN_ID:-}" ]; then run_suffix=$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT:-0}; else run_suffix=local-$$; fi
artifact_dir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/goauthy-login-journey-artifacts-$run_suffix
private_dir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/goauthy-login-journey-private-$run_suffix
[ ! -e "$artifact_dir" ] && [ ! -e "$private_dir" ] || { echo 'a previous login journey artifact directory already exists; refusing to overwrite it' >&2; exit 1; }
server_pid=
demo_pid=
fixture_stage=fixture-preflight
stop_owned_child() {
	child=$1
	[ -n "$child" ] || return 0
	if kill -0 "$child" 2>/dev/null; then
		kill -TERM "$child" 2>/dev/null || true
		attempt=0
		while [ "$attempt" -lt 5 ] && kill -0 "$child" 2>/dev/null; do sleep 1; attempt=$((attempt + 1)); done
		if kill -0 "$child" 2>/dev/null; then kill -KILL "$child" 2>/dev/null || true; fi
	fi
	wait "$child" 2>/dev/null || true
	kill -0 "$child" 2>/dev/null && return 1
	return 0
}
cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=0
	for child in "$server_pid" "$demo_pid"; do
		stop_owned_child "$child" || cleanup_failed=1
	done
	e2e_port_lock_release
	if { [ "$status" -ne 0 ] || [ "$cleanup_failed" -ne 0 ]; } && [ -d "$temp_dir/artifacts" ] && [ ! -f "$temp_dir/artifacts/stage.txt" ]; then
		printf '%s\n' "$fixture_stage" >"$temp_dir/artifacts/stage.txt"
		chmod 600 "$temp_dir/artifacts/stage.txt"
	fi
	if [ "$status" -ne 0 ] || [ "$cleanup_failed" -ne 0 ]; then
		if [ -d "$temp_dir/artifacts" ] && mkdir -m 700 "$artifact_dir" 2>/dev/null; then
			for artifact in stage.txt failure.png; do
				if [ -f "$temp_dir/artifacts/$artifact" ]; then cp "$temp_dir/artifacts/$artifact" "$artifact_dir/$artifact"; chmod 600 "$artifact_dir/$artifact"; fi
			done
		fi
		if [ ! -e "$private_dir" ]; then mv "$temp_dir" "$private_dir"; else cleanup_failed=1; rm -rf "$temp_dir"; fi
		if [ -d "$private_dir" ]; then echo "private fixture diagnostics retained for investigation: $private_dir" >&2; fi
	else
		rm -rf "$temp_dir"
	fi
	if [ "$status" -eq 0 ] && [ "$cleanup_failed" -eq 0 ]; then
		exit 0
	fi
	if [ "$cleanup_failed" -ne 0 ]; then echo 'fixture cleanup could not verify all owned child processes exited' >&2; status=1; fi
	if [ -d "$artifact_dir" ]; then echo "sanitized failure artifacts: $artifact_dir" >&2; fi
	[ "$status" -ne 0 ] || status=1
	exit "$status"
}
trap cleanup 0
trap 'if [ "$mode" = --manual ]; then exit 0; else exit 130; fi' 2
trap 'exit 143' 1 15

e2e_port_lock_acquire
for reserved in "$port" "$app_port"; do
	if nc -z 127.0.0.1 "$reserved" >/dev/null 2>&1 || nc -z localhost "$reserved" >/dev/null 2>&1; then echo "fixture port $reserved is occupied" >&2; exit 1; fi
done
mkdir -m 700 "$temp_dir/data" "$temp_dir/master-keys" "$temp_dir/artifacts"
fixture_stage=synthetic-fixture-material
# Public fixed test vectors are limited to this fresh-data, loopback-only fixture.
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/master-keys/journey-1"
printf '%s\n' ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
chmod 600 "$temp_dir/master-keys/journey-1" "$temp_dir/oauth-hmac" "$temp_dir/bootstrap-client"
printf '%s\n' correct-horse-browser-staple >"$temp_dir/browser-password"
chmod 600 "$temp_dir/browser-password"
if ! printf '%s\n' correct-horse-browser-staple | go run -mod=readonly -p=1 ./cmd/goauthy-password >"$temp_dir/password-phc" 2>"$temp_dir/password-build.log"; then
	echo 'synthetic bootstrap credential generation failed' >&2
	exit 1
fi
chmod 600 "$temp_dir/password-phc"
fixture_stage=build-fixture-binaries
if ! go build -mod=readonly -p=1 -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy >"$temp_dir/server-build.log" 2>&1 ||
	! go build -mod=readonly -p=1 -trimpath -o "$temp_dir/demo" ./cmd/goauthy-demo >"$temp_dir/demo-build.log" 2>&1; then
	echo 'isolated fixture build failed' >&2
	exit 1
fi

issuer="http://localhost:$port"
app="http://localhost:$app_port"
GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
GOAUTHY_ISSUER="$issuer" \
GOAUTHY_RHIZA_PROFILE=standalone \
GOAUTHY_CLUSTER_ID=login-journey-disposable \
GOAUTHY_NODE_ID=login-journey-disposable-0 \
GOAUTHY_DATA_DIR="$temp_dir/data" \
GOAUTHY_MASTER_KEY_DIR="$temp_dir/master-keys" \
GOAUTHY_ACTIVE_MASTER_KEY_ID=journey-1 \
GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
GOAUTHY_BOOTSTRAP_CLIENT_ID=login-journey-demo \
GOAUTHY_BOOTSTRAP_REDIRECT_URI="$app/callback" \
GOAUTHY_BOOTSTRAP_USER=admin \
GOAUTHY_BOOTSTRAP_USER_SUBJECT=login-journey-admin \
GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/password-phc" \
GOAUTHY_BOOTSTRAP_USER_EMAIL=admin@login-journey.example.test \
GOAUTHY_BOOTSTRAP_USER_ROLES='["goauthy_admin"]' \
GOAUTHY_BOOTSTRAP_FORCE_MFA=false \
"$temp_dir/goauthy" >"$temp_dir/server.log" 2>&1 &
server_pid=$!

wait_ready() {
	ready_url=$1
	ready_pid=$2
	limit=$3
	attempt=0
	while [ "$attempt" -lt "$limit" ]; do
		kill -0 "$ready_pid" 2>/dev/null || return 1
		if curl --noproxy '*' --max-time 1 --fail --silent "$ready_url" >/dev/null 2>&1; then return 0; fi
		attempt=$((attempt + 1))
		sleep 1
	done
	return 1
}
fixture_stage=goauthy-readiness
if ! wait_ready "$issuer/livez" "$server_pid" 60 || ! wait_ready "$issuer/readyz" "$server_pid" 60; then
	echo 'GoAuthy fixture readiness failed' >&2
	exit 1
fi
"$temp_dir/demo" -name 'Login Journey Demo' -listen "127.0.0.1:$app_port" -issuer "$issuer" -client-id login-journey-demo -client-secret-file "$temp_dir/bootstrap-client" -force-login >"$temp_dir/demo.log" 2>&1 &
demo_pid=$!
fixture_stage=demo-readiness
if ! wait_ready "$app/healthz" "$demo_pid" 30; then
	echo 'demo fixture readiness failed' >&2
	exit 1
fi

if [ "$mode" = --manual ]; then
	echo "Temporary CUA fixture ready: issuer=$issuer app=$app goauthy_pid=$server_pid demo_pid=$demo_pid"
	echo 'Synthetic account: username=admin email=admin@login-journey.example.test role=goauthy_admin'
	echo 'Bootstrap OAuth client: login-journey-demo; callback: http://localhost:'"$app_port"'/callback; theme: default global fallback, no theme API writes.'
	echo 'Press Ctrl-C to stop only these two processes, verify cleanup, and remove the private fixture directory.'
	while kill -0 "$server_pid" 2>/dev/null && kill -0 "$demo_pid" 2>/dev/null; do sleep 1; done
	echo 'a fixture process exited unexpectedly' >&2
	exit 1
fi

fixture_stage=browser-test
set +e
GOAUTHY_E2E_LOGIN_JOURNEY=1 \
GOAUTHY_E2E_ACCOUNT_ERROR_UI=1 \
GOAUTHY_E2E_URL="$issuer" \
GOAUTHY_E2E_APP_URL="$app" \
GOAUTHY_E2E_BROWSER_USERNAME=admin \
GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
GOAUTHY_E2E_BROWSER_SUBJECT=login-journey-admin \
GOAUTHY_E2E_BROWSER_EMAIL=admin@login-journey.example.test \
GOAUTHY_E2E_CHROME_BIN="$chrome_bin" \
GOAUTHY_E2E_ARTIFACT_DIR="$temp_dir/artifacts" \
go test -mod=readonly -p=1 -count=1 -v -timeout=4m ./test/e2e/browser -run '^Test(LoginFailureRetryAppReturnAndLogout|AccountErrorFeedbackUI)$' >"$temp_dir/test.log" 2>&1
test_status=$?
set -e
if [ "$test_status" -ne 0 ] || \
	! grep -q '^--- PASS: TestLoginFailureRetryAppReturnAndLogout ' "$temp_dir/test.log" || \
	! grep -q '^--- PASS: TestAccountErrorFeedbackUI ' "$temp_dir/test.log" || \
	grep -Eq '^--- SKIP: Test(LoginFailureRetryAppReturnAndLogout|AccountErrorFeedbackUI)( |$)' "$temp_dir/test.log"; then
	echo 'both browser tests must produce actual PASS results (no retry was attempted)' >&2
	exit 1
fi
echo 'PASS TestLoginFailureRetryAppReturnAndLogout (count=1; no retry).'
echo 'PASS TestAccountErrorFeedbackUI (count=1; no retry).'
