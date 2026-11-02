#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$root/scripts/verify-isolated.sh
sh -n "$runner"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/verify-isolated-test.XXXXXX")
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir -p "$tmp/bin" "$tmp/project/scripts" "$tmp/project/test/e2e/browser"
cat >"$tmp/bin/go" <<'EOF'
#!/bin/sh
/usr/bin/env | sort >"$TMPDIR/go-env"
printf '%s\n' "$*" >"$TMPDIR/go-args"
[ ! -f "$TMPDIR/fail-go" ] || exit 23
echo 'go version go1.test'
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
if PATH=$fake_path TMPDIR=$tmp GOAUTHY_E2E_URL=https://prod.example GOAUTHY_ISSUER=https://prod.example \
	GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR=/foreign GOAUTHY_E2E_TERNAL_DEVICE=1 AWS_PROFILE=production KUBECONFIG=/foreign/config \
	GOAUTHY_ISOLATED_CLEAN_ENV=1 GOAUTHY_E2E_CHROME_BIN="$tmp/bin/chrome" sh "$runner" --check >"$tmp/check.log" 2>&1; then
	:
else
	cat "$tmp/check.log" >&2
	echo 'isolated --check failed with available fake prerequisites' >&2
	exit 1
fi
[ ! -e "$tmp/resource-started" ] || { echo '--check invoked a listener or HTTP client' >&2; exit 1; }
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

echo 'Isolated runner guards passed: clean environment, no-resource check, serial stages, and failure propagation.'
