#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$root/scripts/verify-isolated.sh
sh -n "$runner"
# Prepare the tiny stdlib helper with the real toolchain before installing mocks.
sh "$root/scripts/e2e-stage-supervisor.sh" --prepare
# The helper is a separate module and is excluded from the root ./... tests.
GOENV=off GOWORK=off GOMAXPROCS=2 go test -C "$root/scripts/e2e-stage-supervisor-src" -mod=readonly -p=1 -count=1 -timeout=30s
GOENV=off GOWORK=off GOMAXPROCS=2 go test -C "$root/scripts/e2e-stage-supervisor-src" -mod=readonly -p=1 -race -count=1 -timeout=30s

tmp=$(mktemp -d "${TMPDIR:-/tmp}/verify-isolated-test.XXXXXX")
term_root_pid=
term_stage_pid=
term_child_pid=
pid_active() {
	state=$(ps -o stat= -p "$1" 2>/dev/null || true)
	case "$state" in ''|Z*) return 1;; *) return 0;; esac
}
wait_pid_inactive() {
	pid=$1
	limit=$2
	attempt=0
	while [ "$attempt" -lt "$limit" ] && pid_active "$pid"; do
		sleep 0.1
		attempt=$((attempt + 1))
	done
	! pid_active "$pid"
}
stop_test_pid() {
	pid=$1
	[ -n "$pid" ] || return 0
	if pid_active "$pid"; then
		kill -TERM "$pid" 2>/dev/null || true
		wait_pid_inactive "$pid" 20 || {
			kill -KILL "$pid" 2>/dev/null || true
			wait_pid_inactive "$pid" 20 || return 1
		}
	fi
	return 0
}
cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=0
	stop_test_pid "$term_stage_pid" || cleanup_failed=1
	stop_test_pid "$term_child_pid" || cleanup_failed=1
	if [ -n "$term_root_pid" ]; then
		if pid_active "$term_root_pid"; then
			kill -KILL "$term_root_pid" 2>/dev/null || true
			wait_pid_inactive "$term_root_pid" 20 || cleanup_failed=1
		fi
		if ! pid_active "$term_root_pid"; then wait "$term_root_pid" 2>/dev/null || true; fi
	fi
	if [ "$cleanup_failed" -eq 0 ]; then
		rm -rf "$tmp" || cleanup_failed=1
		[ ! -e "$tmp" ] || cleanup_failed=1
	else
		echo "fake-stage processes remain; test scratch retained: $tmp (root=$term_root_pid stage=$term_stage_pid child=$term_child_pid)" >&2
	fi
	[ "$cleanup_failed" -eq 0 ] || status=1
	exit "$status"
}
trap cleanup 0 1 2 15
mkdir -p "$tmp/bin" "$tmp/project/scripts" "$tmp/project/test/e2e/browser"
(cd "$root/scripts/e2e-stage-supervisor-src" && GOENV=off GOWORK=off go version) >"$tmp/toolchain-version"
(cd "$root/scripts/e2e-stage-supervisor-src" && GOENV=off GOWORK=off go env GOHOSTOS GOHOSTARCH) >"$tmp/host-target"
cat >"$tmp/bin/go" <<'EOF'
#!/bin/sh
/usr/bin/env | sort >"$TMPDIR/go-env"
printf '%s\n' "$*" >"$TMPDIR/go-args"
[ ! -f "$TMPDIR/fail-go" ] || exit 23
case "${1:-}" in
	env) cat "$TMPDIR/host-target" ;;
	*) cat "$TMPDIR/toolchain-version" ;;
esac
EOF
cat >"$tmp/bin/nc" <<'EOF'
#!/bin/sh
: >"$TMPDIR/resource-started"
exit 99
EOF
cp "$tmp/bin/nc" "$tmp/bin/curl"
cat >"$tmp/bin/chrome" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$tmp/bin/go" "$tmp/bin/nc" "$tmp/bin/curl" "$tmp/bin/chrome"

fake_path=$tmp/bin:$PATH
# Force the host target despite inherited cross-build settings, and reject a
# cache prepared by a different toolchain without starting a build.
PATH=$fake_path TMPDIR=$tmp GOOS=windows GOARCH=386 sh "$root/scripts/e2e-stage-supervisor.sh" /bin/sh -c 'exit 0'
cp "$tmp/toolchain-version" "$tmp/toolchain-version.saved"
printf '%s\n' 'go version go0.invalid cache-fixture' >"$tmp/toolchain-version"
if PATH=$fake_path TMPDIR=$tmp sh "$root/scripts/e2e-stage-supervisor.sh" /bin/sh -c 'exit 0' >"$tmp/cache.log" 2>&1; then
	echo 'supervisor reused a cache from another toolchain' >&2
	exit 1
fi
grep -q '^stage supervisor is not prepared$' "$tmp/cache.log"
mv "$tmp/toolchain-version.saved" "$tmp/toolchain-version"
if PATH=$fake_path HOME=$tmp/check-home TMPDIR=$tmp GOAUTHY_E2E_URL=https://prod.example GOAUTHY_ISSUER=https://prod.example \
	GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR=/foreign GOAUTHY_E2E_TERNAL_DEVICE=1 AWS_PROFILE=production KUBECONFIG=/foreign/config \
	GOAUTHY_ISOLATED_CLEAN_ENV=1 GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" sh "$runner" --check >"$tmp/check.log" 2>&1; then
	:
else
	cat "$tmp/check.log" >&2
	echo 'isolated --check failed with available fake prerequisites' >&2
	exit 1
fi
[ ! -e "$tmp/resource-started" ] || { echo '--check invoked a listener or HTTP client' >&2; exit 1; }
[ ! -e "$tmp/check-home" ] || { echo '--check prepared a supervisor cache' >&2; exit 1; }
[ ! -e "$tmp/project/scripts/login-ran" ] || { echo '--check invoked a journey harness' >&2; exit 1; }
for forbidden in GOAUTHY_E2E_URL GOAUTHY_ISSUER GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR GOAUTHY_E2E_TERNAL_DEVICE AWS_PROFILE KUBECONFIG; do
	if grep -q "^$forbidden=" "$tmp/go-env"; then
		echo "hostile environment reached go child: $forbidden" >&2
		exit 1
	fi
done
grep -q '^GOENV=off$' "$tmp/go-env"
grep -q '^GOWORK=off$' "$tmp/go-env"
[ "$(cat "$tmp/go-args")" = version ]

touch "$tmp/fail-go"
if PATH=$fake_path TMPDIR=$tmp GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" sh "$runner" --check >/dev/null 2>&1; then
	echo '--check swallowed a failed toolchain child' >&2
	exit 1
fi
rm "$tmp/fail-go"

if PATH=$fake_path TMPDIR=$tmp GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" sh "$runner" --run https://prod.example >/dev/null 2>&1; then
	echo 'runner accepted a URL argument' >&2
	exit 1
fi
if PATH=$fake_path TMPDIR=$tmp GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" sh "$runner" --run >/dev/null 2>&1; then
	echo 'runner accepted --run without the parent serial slot' >&2
	exit 1
fi
[ ! -e "$tmp/resource-started" ] || { echo 'preflight rejection started a resource' >&2; exit 1; }

# Build a disposable copy with fake child harnesses to exercise allowlisting,
# fixed local endpoints, serial stage order, and child-failure propagation.
cp "$runner" "$tmp/project/scripts/verify-isolated.sh"
cp "$root/scripts/e2e-stage-supervisor.sh" "$tmp/project/scripts/"
mkdir -p "$tmp/project/scripts/e2e-stage-supervisor-src"
cp "$root/scripts/e2e-stage-supervisor-src/go.mod" "$root/scripts/e2e-stage-supervisor-src/main.go" "$tmp/project/scripts/e2e-stage-supervisor-src/"
for source in \
	cmd/goauthy/main.go \
	scripts/e2e-port-lock.sh \
	test/e2e/browser/login_journey_test.go \
	test/e2e/browser/open_registration_test.go \
	test/e2e/browser/password_reset_test.go \
	test/e2e/browser/events_stream_test.go \
	test/e2e/browser/event_test_endpoint_test.go \
	test/e2e/browser/events_persistence_test.go \
	test/e2e/browser/password_reset_event_persistence_test.go; do
	mkdir -p "$tmp/project/$(dirname "$source")"
	: >"$tmp/project/$source"
done
cat >"$tmp/project/go.mod" <<'EOF'
module isolated-guard-fixture
go 1.23
EOF
for harness in e2e-login-journey-standalone.sh e2e-open-registration-standalone.sh e2e-admin-standalone.sh; do
	cat >"$tmp/project/scripts/$harness" <<'EOF'
#!/bin/sh
set -eu
stage=${0##*/}
case "$stage" in
	e2e-login-journey-standalone.sh) name=login ;;
	e2e-open-registration-standalone.sh) name=registration ;;
	e2e-admin-standalone.sh) name=admin ;;
esac
/usr/bin/env | sort >"$TMPDIR/$name.env"
printf '%s\n' "$name" >>"$TMPDIR/stage-order"
if [ "$name" = login ] && [ -f "$TMPDIR/term-child-mode" ]; then
	sleep 60 &
	child=$!
	cleanup_stage() {
		trap - 0 1 2 15
		kill -TERM "$child" 2>/dev/null || true
		attempt=0
		while [ "$attempt" -lt 50 ] && kill -0 "$child" 2>/dev/null; do sleep 0.1; attempt=$((attempt + 1)); done
		if kill -0 "$child" 2>/dev/null; then kill -KILL "$child" 2>/dev/null || true; fi
		wait "$child" 2>/dev/null || true
		# Exercise the real harness budget: cleanup may exceed five seconds.
		sleep 6
		rm -f "$TMPDIR/fake-stage-resource" "$TMPDIR/stage-child.pid" "$TMPDIR/stage-harness.pid"
		exit 0
	}
	trap cleanup_stage 0 1 2 15
	printf '%s\n' "$$" >"$TMPDIR/stage-harness.pid"
	printf '%s\n' "$child" >"$TMPDIR/stage-child.pid"
	: >"$TMPDIR/fake-stage-resource"
	wait "$child"
	exit 0
fi
if [ -f "$TMPDIR/fail-$name" ]; then
	echo '--- FAIL: TestOpenRegistrationAcrossPods (0.01s)'
	echo 'raw-secret-marker-do-not-display'
	exit 37
fi
case "$name" in
	login)
		[ "${GOAUTHY_LOGIN_JOURNEY_PORT:-}" = 19380 ]
		[ "${GOAUTHY_LOGIN_JOURNEY_SLOT:-}" = granted ]
		printf '%s\n' 'PASS TestLoginFailureRetryAppReturnAndLogout (test)' 'PASS TestAccountErrorFeedbackUI (test)'
		;;
	registration)
		[ "${GOAUTHY_STANDALONE_OPEN_REG_PORT:-}" = 19400 ]
		for test_name in TestOpenRegistrationAcrossPods TestAdminUserCreateLifecycle TestAdminUserUpdateAcrossPods TestCreationEventsStream TestEventTestEndpoint TestEventTestPersisted TestCreationEventsPersisted TestAdminUserUpdatePersisted TestPasswordResetAcrossPods TestPasswordResetEventPersisted; do
			echo "--- PASS: $test_name (test)"
		done
		echo 'standalone open-registration and password-reset E2E passed'
		;;
	admin)
		[ "${GOAUTHY_STANDALONE_ADMIN_PORT:-}" = 19410 ]
		echo 'standalone browser-admin index E2E passed'
		;;
esac
EOF
done

if PATH=$fake_path TMPDIR=$tmp GOAUTHY_E2E_URL=https://prod.example GOAUTHY_ISSUER=https://prod.example \
	GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR=/foreign GOAUTHY_E2E_TERNAL_DEVICE=1 AWS_PROFILE=production KUBECONFIG=/foreign/config \
	GOAUTHY_ISOLATED_E2E_SLOT=granted GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" \
	sh "$tmp/project/scripts/verify-isolated.sh" --run >"$tmp/run.log" 2>&1; then
	:
else
	cat "$tmp/run.log" >&2
	echo 'isolated fake journey did not pass' >&2
	exit 1
fi
[ "$(cat "$tmp/stage-order")" = "login
registration
admin" ] || { echo 'journey stages were not serial' >&2; exit 1; }
for environment in "$tmp/login.env" "$tmp/registration.env" "$tmp/admin.env"; do
	for forbidden in GOAUTHY_E2E_URL GOAUTHY_ISSUER GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR GOAUTHY_E2E_TERNAL_DEVICE AWS_PROFILE KUBECONFIG; do
		if grep -q "^$forbidden=" "$environment"; then
			echo "hostile environment reached journey child: $forbidden" >&2
			exit 1
		fi
	done
done

rm -f "$tmp/stage-order" "$tmp/login.env" "$tmp/registration.env" "$tmp/admin.env"
touch "$tmp/fail-registration"
if PATH=$fake_path TMPDIR=$tmp GOAUTHY_ISOLATED_E2E_SLOT=granted GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" \
	sh "$tmp/project/scripts/verify-isolated.sh" --run >"$tmp/failure.log" 2>&1; then
	echo 'runner swallowed a failing child harness' >&2
	exit 1
fi
[ "$(cat "$tmp/stage-order")" = "login
registration" ] || { echo 'runner continued after failed registration stage' >&2; exit 1; }
if grep -q 'raw-secret-marker-do-not-display' "$tmp/failure.log"; then
	echo 'runner exposed raw child failure output' >&2
	exit 1
fi
grep -q '^--- FAIL: TestOpenRegistrationAcrossPods (0.01s)$' "$tmp/failure.log"
set -- "$tmp"/goauthy-isolated-e2e.*
failure_dir=$1
if [ ! -d "$failure_dir" ] || ! grep -q 'raw-secret-marker-do-not-display' "$failure_dir/registration.log"; then
	echo 'runner did not retain protected failure details for investigation' >&2
	exit 1
fi

# Terminate only the runner PID while its fake login harness owns a child.
# The harness trap must get TERM and remove its own child/resource before the
# runner exits 143 and removes no live fixture resources.
touch "$tmp/term-child-mode"
PATH=$fake_path TMPDIR=$tmp GOAUTHY_ISOLATED_E2E_SLOT=granted GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" \
	sh "$tmp/project/scripts/verify-isolated.sh" --run >"$tmp/term.log" 2>&1 &
term_root_pid=$!
attempt=0
while [ "$attempt" -lt 50 ] && [ ! -f "$tmp/stage-child.pid" ]; do sleep 0.1; attempt=$((attempt + 1)); done
[ -f "$tmp/stage-child.pid" ] || { echo 'TERM regression fake stage did not start' >&2; exit 1; }
term_stage_pid=$(cat "$tmp/stage-harness.pid")
term_child_pid=$(cat "$tmp/stage-child.pid")
kill -TERM "$term_root_pid"
if ! wait_pid_inactive "$term_root_pid" 150; then
	echo 'TERM regression: runner remained blocked instead of forwarding TERM to its owned stage' >&2
	exit 1
fi
if wait "$term_root_pid"; then term_status=0; else term_status=$?; fi
term_root_pid=
[ "$term_status" -eq 143 ] || { echo "TERM regression: runner exit=$term_status want 143" >&2; exit 1; }
if pid_active "$term_child_pid"; then
	echo 'TERM regression: fake stage child survived the runner signal' >&2
	exit 1
fi
[ ! -e "$tmp/fake-stage-resource" ] || { echo 'TERM regression: fake stage resource remained after child exit' >&2; exit 1; }
[ ! -e "$tmp/stage-child.pid" ] && [ ! -e "$tmp/stage-harness.pid" ] || {
	echo 'TERM regression: fake stage cleanup did not remove its markers' >&2
	exit 1
}
term_stage_pid=
term_child_pid=

echo 'Isolated runner guards passed: clean environment, no-resource check, serial stages, and failure propagation.'
