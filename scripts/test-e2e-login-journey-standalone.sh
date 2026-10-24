#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$root/scripts/e2e-login-journey-standalone.sh
sh -n "$runner"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/login-journey-guard.XXXXXX")
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir "$tmp/bin"
for tool in go nc; do
	cat >"$tmp/bin/$tool" <<'EOF'
#!/bin/sh
: >"${0%/*}/../started"
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

echo 'Login journey syntax and offline preflight guards passed; no build, listener, or browser started.'
