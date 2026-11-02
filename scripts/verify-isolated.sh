#!/bin/sh
set -eu

usage() {
	echo 'usage: sh scripts/verify-isolated.sh [--check|--run]' >&2
	echo 'run requires GOAUTHY_ISOLATED_E2E_SLOT=granted' >&2
}

mode=${1:---check}
case "$mode" in --check|--run) ;; *) usage; exit 2;; esac

if [ "$#" -eq 2 ] && [ "${2:-}" = "--isolated-$$" ]; then
	clean_env=true
else
	[ "$#" -le 1 ] || { usage; exit 2; }
	clean_env=false
fi

# Re-exec with only the local toolchain and artifact paths. No app URLs,
# consumer profiles, cloud credentials, or cluster settings cross this edge.
if [ "$clean_env" != true ]; then
	exec env -i \
		PATH="${PATH:-/usr/bin:/bin}" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" \
		GOENV=off GOWORK=off GOMAXPROCS=2 CI="${CI:-}" \
		GOAUTHY_ISOLATED_E2E_SLOT="${GOAUTHY_ISOLATED_E2E_SLOT:-}" \
		GOAUTHY_E2E_CHROME_BIN="${GOAUTHY_E2E_CHROME_BIN:-}" \
		GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
		RUNNER_TEMP="${RUNNER_TEMP:-}" \
		/bin/sh "$0" "$mode" "--isolated-$$"
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"

for tool in env go curl nc mktemp grep rm ps sleep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
for source in \
	go.mod \
	scripts/e2e-login-journey-standalone.sh \
	scripts/e2e-open-registration-standalone.sh \
	scripts/e2e-admin-standalone.sh \
	scripts/e2e-port-lock.sh \
	scripts/e2e-stage-supervisor.sh \
	scripts/e2e-stage-supervisor-src/go.mod \
	scripts/e2e-stage-supervisor-src/main.go \
	test/e2e/browser/login_journey_test.go \
	test/e2e/browser/open_registration_test.go \
	test/e2e/browser/password_reset_test.go \
	test/e2e/browser/events_stream_test.go \
	test/e2e/browser/event_test_endpoint_test.go \
	test/e2e/browser/events_persistence_test.go \
	test/e2e/browser/password_reset_event_persistence_test.go; do
	[ -f "$source" ] || { echo "missing isolated E2E source: $source" >&2; exit 1; }
done
for shell_script in scripts/verify-isolated.sh scripts/e2e-stage-supervisor.sh scripts/e2e-login-journey-standalone.sh scripts/e2e-open-registration-standalone.sh scripts/e2e-admin-standalone.sh; do
	sh -n "$shell_script"
done
go version >/dev/null

chrome_bin=${GOAUTHY_E2E_CHROME_BIN:-}
if [ -z "$chrome_bin" ]; then
	for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
		if command -v "$candidate" >/dev/null 2>&1; then chrome_bin=$(command -v "$candidate"); break; fi
	done
	if [ -z "$chrome_bin" ] && [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
		chrome_bin="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	fi
fi
[ -n "$chrome_bin" ] && [ -x "$chrome_bin" ] || { echo 'Chrome/Chromium unavailable for the browser journey' >&2; exit 1; }

if [ "$mode" = --check ]; then
	echo 'Isolated E2E prerequisites found. No build, listeners, browser, SMTP sink, or test process started.'
	exit 0
fi
[ "${GOAUTHY_ISOLATED_E2E_SLOT:-}" = granted ] || { echo 'parent serial E2E slot required; set GOAUTHY_ISOLATED_E2E_SLOT=granted' >&2; exit 2; }

umask 077
run_dir=$(mktemp -d "${TMPDIR%/}/goauthy-isolated-e2e.XXXXXX")
stage_pid=
stage_active() {
	state=$(ps -o stat= -p "$1" 2>/dev/null || true)
	case "$state" in ''|Z*) return 1;; *) return 0;; esac
}
stop_owned_stage() {
	child=$1
	[ -n "$child" ] || return 0
	if stage_active "$child"; then
		kill -TERM "$child" 2>/dev/null || true
		attempt=0
		# The controller owns escalation; allow its 75s grace and 5s check.
		while [ "$attempt" -lt 900 ] && stage_active "$child"; do
			sleep 0.1
			attempt=$((attempt + 1))
		done
	fi
	stage_active "$child" && return 1
	wait "$child" 2>/dev/null || true
	return 0
}
handle_signal() {
	signal_status=$1
	signal_name=$2
	trap - 1 2 15
	if [ -n "$stage_pid" ]; then
		if stop_owned_stage "$stage_pid"; then
			stage_pid=
		else
			echo "could not verify owned stage exit after $signal_name; PID retained: $stage_pid" >&2
		fi
	fi
	exit "$signal_status"
}
cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=0
	if [ "$status" -ne 0 ] && [ -d "$run_dir" ]; then
		chmod 700 "$run_dir" || cleanup_failed=1
		for log in "$run_dir"/*.log; do
			[ -f "$log" ] || continue
			chmod 600 "$log" || cleanup_failed=1
		done
		if [ "$cleanup_failed" -eq 0 ]; then
			echo "private synthetic-fixture stage logs retained for investigation (not a CI artifact): $run_dir" >&2
		else
			echo "could not protect failure logs; private directory remains at: $run_dir" >&2
			status=1
		fi
	else
		rm -rf "$run_dir" || cleanup_failed=1
		[ ! -e "$run_dir" ] || cleanup_failed=1
	fi
	if [ "$cleanup_failed" -ne 0 ]; then
		echo "isolated runner could not remove captured fixture logs: $run_dir" >&2
		status=1
	fi
	exit "$status"
}
trap cleanup 0
trap 'handle_signal 129 HUP' 1
trap 'handle_signal 130 INT' 2
trap 'handle_signal 143 TERM' 15

run_stage() {
	label=$1
	shift
	log=$run_dir/$label.log
	if [ "$label" = supervisor-build ]; then
		"$@" >"$log" 2>&1 &
	else
		/bin/sh "$script_dir/e2e-stage-supervisor.sh" "$@" >"$log" 2>&1 &
	fi
	stage_pid=$!
	if wait "$stage_pid"; then
		stage_status=0
	else
		stage_status=$?
	fi
	stage_pid=
	if [ "$stage_status" -eq 0 ]; then
		return 0
	fi
	echo "isolated E2E stage failed: $label (raw fixture logs suppressed)" >&2
	grep -E '^fixture cleanup incomplete; temporary directory retained: [A-Za-z0-9._/ -]+$' "$log" >&2 || true
	if [ "$label" = registration ]; then
		for test_name in \
			TestOpenRegistrationAcrossPods TestAdminUserCreateLifecycle TestAdminUserUpdateAcrossPods \
			TestCreationEventsStream TestEventTestEndpoint TestEventTestPersisted \
			TestCreationEventsPersisted TestAdminUserUpdatePersisted \
			TestPasswordResetAcrossPods TestPasswordResetEventPersisted; do
			grep -E "^--- (PASS|FAIL|SKIP): $test_name \\([0-9]+([.][0-9]+)?s\\)$" "$log" >&2 || true
		done
	fi
	return 1
}

run_stage supervisor-build /bin/sh "$script_dir/e2e-stage-supervisor.sh" --prepare

run_stage login \
	env -i PATH="$PATH" HOME="$HOME" TMPDIR="$TMPDIR" GOENV=off GOWORK=off GOMAXPROCS=2 \
		GOAUTHY_LOGIN_JOURNEY_SLOT=granted GOAUTHY_LOGIN_JOURNEY_PORT=19380 \
		GOAUTHY_E2E_CHROME_BIN="$chrome_bin" CI="$CI" \
		GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" RUNNER_TEMP="$RUNNER_TEMP" \
		/bin/sh scripts/e2e-login-journey-standalone.sh --run
grep -q '^PASS TestLoginFailureRetryAppReturnAndLogout ' "$run_dir/login.log"
grep -q '^PASS TestAccountErrorFeedbackUI ' "$run_dir/login.log"
echo 'PASS isolated browser login journey.'

run_stage registration \
	env -i PATH="$PATH" HOME="$HOME" TMPDIR="$TMPDIR" GOENV=off GOWORK=off GOMAXPROCS=2 \
		GOAUTHY_STANDALONE_OPEN_REG_PORT=19400 CI="$CI" \
		/bin/sh scripts/e2e-open-registration-standalone.sh
for test_name in \
	TestOpenRegistrationAcrossPods TestAdminUserCreateLifecycle TestAdminUserUpdateAcrossPods \
	TestCreationEventsStream TestEventTestEndpoint TestEventTestPersisted \
	TestCreationEventsPersisted TestAdminUserUpdatePersisted \
	TestPasswordResetAcrossPods TestPasswordResetEventPersisted; do
	grep -q "^--- PASS: $test_name " "$run_dir/registration.log" || {
		echo "registration stage did not report PASS for $test_name" >&2
		exit 1
	}
done
if grep -q '^--- SKIP:' "$run_dir/registration.log"; then
	echo 'registration stage reported a skipped test' >&2
	exit 1
fi
grep -q '^standalone open-registration and password-reset E2E passed$' "$run_dir/registration.log"
echo 'PASS isolated registration, SMTP, event, and password-reset journey.'

run_stage admin \
	env -i PATH="$PATH" HOME="$HOME" TMPDIR="$TMPDIR" GOENV=off GOWORK=off GOMAXPROCS=2 \
		GOAUTHY_STANDALONE_ADMIN_PORT=19410 CI="$CI" \
		/bin/sh scripts/e2e-admin-standalone.sh
grep -q '^standalone browser-admin index E2E passed$' "$run_dir/admin.log"
echo 'PASS isolated browser-admin journey.'

echo 'All isolated GoAuthy E2E stages passed; each harness cleaned its own disposable resources.'
