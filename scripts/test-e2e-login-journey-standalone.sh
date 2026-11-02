#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$root/scripts/e2e-login-journey-standalone.sh
sh -n "$runner"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/login-journey-guard.XXXXXX")
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir "$tmp/bin" "$tmp/runner-temp" "$tmp/caller-runner-temp"
caller_run_id=ci-call-$$
caller_run_attempt=8
caller_artifact="$tmp/caller-runner-temp/goauthy-login-journey-artifacts-$caller_run_id-$caller_run_attempt"
mkdir "$caller_artifact"
printf '%s\n' preserve >"$caller_artifact/marker"
RUNNER_TEMP="$tmp/caller-runner-temp"
GITHUB_RUN_ID=$caller_run_id
GITHUB_RUN_ATTEMPT=$caller_run_attempt
export RUNNER_TEMP GITHUB_RUN_ID GITHUB_RUN_ATTEMPT
for tool in go nc; do
	cat >"$tmp/bin/$tool" <<'EOF'
#!/bin/sh
: >"${0%/*}/../started"
if [ "${0##*/}" = go ]; then
	printf '%s\n' "${GOENV-unset}" >"$TMPDIR/nested-goenv"
	printf '%s\n' "$*" >"$TMPDIR/nested-go-args"
	exit 77
fi
exit 99
EOF
	chmod +x "$tmp/bin/$tool"
done

guard_path=$tmp/bin:$PATH
assert_not_started() {
	[ ! -e "$tmp/started" ] || { echo 'runner reached build or listener setup during preflight' >&2; exit 1; }
}
if ! PATH=$guard_path GOAUTHY_E2E_CHROME_BIN=/usr/bin/true sh "$runner" --check >/dev/null; then
	echo 'runner --check failed with an executable fake Chrome' >&2
	exit 1
fi
assert_not_started

for port in 0 019380 1023 65534 65535 bad '19380;exit 0'; do
	if PATH=$guard_path GOAUTHY_E2E_CHROME_BIN=/usr/bin/true GOAUTHY_LOGIN_JOURNEY_PORT="$port" sh "$runner" --check >/dev/null 2>&1; then
		echo "runner accepted invalid port: $port" >&2
		exit 1
	fi
	assert_not_started
done
if PATH=$guard_path GOAUTHY_E2E_CHROME_BIN=/usr/bin/true sh "$runner" --unknown >/dev/null 2>&1; then
	echo 'runner accepted an unknown mode' >&2
	exit 1
fi
assert_not_started
if PATH=$guard_path GOAUTHY_E2E_CHROME_BIN="$tmp/missing-chrome" sh "$runner" --check >/dev/null 2>&1; then
	echo 'runner accepted a missing Chrome executable' >&2
	exit 1
fi
assert_not_started
if PATH=$guard_path GOAUTHY_E2E_CHROME_BIN=/usr/bin/true GOAUTHY_LOGIN_JOURNEY_SLOT= sh "$runner" --run >/dev/null 2>&1; then
	echo 'runner accepted --run without the parent slot' >&2
	exit 1
fi
assert_not_started

# Force the real login harness through its nested env-i boundary, then stop at
# its first Go command with the fake executable. This proves the Go child sees
# GOENV=off even when the caller supplies a hostile Go environment setting.
# Use a private CI-style run namespace so its expected failure artifact cannot
# collide with this workflow's RUNNER_TEMP/GITHUB_RUN_ID artifact path.
guard_run_id=login-guard-$$
if PATH=$guard_path TMPDIR="$tmp" GOENV="$tmp/hostile-goenv" \
	RUNNER_TEMP="$tmp/runner-temp" GITHUB_RUN_ID="$guard_run_id" GITHUB_RUN_ATTEMPT=1 \
	GOAUTHY_E2E_CHROME_BIN=/usr/bin/true GOAUTHY_LOGIN_JOURNEY_SLOT=granted \
	sh "$runner" --run >"$tmp/nested-run.log" 2>&1; then
	echo 'nested Go capture unexpectedly completed the full login journey' >&2
	exit 1
fi
[ "$(cat "$tmp/nested-goenv")" = off ] || {
	echo "nested Go process did not receive GOENV=off: $(cat "$tmp/nested-goenv" 2>/dev/null || echo missing)" >&2
	exit 1
}
grep -q '^run -mod=readonly -p=1 ./cmd/goauthy-password$' "$tmp/nested-go-args"
[ -f "$tmp/runner-temp/goauthy-login-journey-artifacts-$guard_run_id-1/stage.txt" ] || {
	echo 'nested login guard did not use its isolated CI artifact namespace' >&2
	exit 1
}
[ ! -d "$tmp/goauthy-e2e-port.lock" ] || { echo 'login preflight left its port lock behind' >&2; exit 1; }
set -- "$tmp"/goauthy-login-journey.??????
[ ! -e "$1" ] || { echo 'login preflight left its credential directory behind' >&2; exit 1; }
[ "$(cat "$caller_artifact/marker")" = preserve ] || { echo 'nested fake-Go failure modified the caller CI artifact' >&2; exit 1; }
set -- "$tmp/caller-runner-temp"/*
[ "$#" -eq 1 ] && [ "$1" = "$caller_artifact" ] || { echo 'login guard leaked an artifact into caller RUNNER_TEMP' >&2; exit 1; }

echo 'Login journey syntax and offline preflight guards passed; no build, listener, or browser started.'
