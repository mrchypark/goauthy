#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/oauth112-mock.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
mkdir "$root/bin" "$root/state"
cat >"$root/bin/tcpdump" <<'MOCK'
#!/bin/sh
if [ "${1-}" = -r ]; then
	printf 'IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 100) 127.0.0.1.1 > 127.0.0.1.2: UDP, length 72\n'
	[ "${MOCK_DECODE_FAIL-}" != 1 ] || exit 23
	exit 0
fi
while [ "$#" -gt 0 ]; do
	if [ "$1" = -w ]; then shift; : >"$1"; fi
	shift
done
trap 'sleep 1; touch "$MOCK_STATE/stopped"; exit 0' INT TERM
touch "$MOCK_STATE/started"
while :; do sleep 1; done
MOCK
chmod +x "$root/bin/tcpdump"
export MOCK_STATE="$root/state"
export PATH="$root/bin:$PATH"
export TMPDIR="$root"

"$script_dir/capture-ip-traffic.sh" lo0 127.0.0.1 65000 300 >"$root/signal.out" 2>"$root/signal.err" &
capture_pid=$!
attempt=0
while [ ! -f "$MOCK_STATE/started" ] && [ "$attempt" -lt 10 ]; do
	sleep 1
	attempt=$((attempt + 1))
done
[ -f "$MOCK_STATE/started" ] || { printf 'mock capture did not start\n' >&2; exit 1; }
kill -TERM "$capture_pid"
if wait "$capture_pid"; then
	printf 'signal did not fail the capture command\n' >&2
	exit 1
else
	result=$?
fi
[ "$result" -eq 143 ] || { printf 'unexpected signal exit: %s\n' "$result" >&2; exit 1; }
[ -f "$MOCK_STATE/stopped" ] || { printf 'tcpdump was not stopped and waited\n' >&2; exit 1; }
if find "$root" -type d -name 'oauth112-wire.*' | grep . >/dev/null; then
	printf 'signal left a capture directory behind\n' >&2
	exit 1
fi

export MOCK_DECODE_FAIL=1
if "$script_dir/capture-ip-traffic.sh" lo0 127.0.0.1 65000 1 >"$root/decode.out" 2>"$root/decode.err"; then
	printf 'decoder failure was masked\n' >&2
	exit 1
fi
grep -q 'capture decode failed' "$root/decode.err" || {
	printf 'decoder failure was not reported\n' >&2
	exit 1
}
[ ! -s "$root/decode.out" ] || { printf 'decoder failure emitted a summary\n' >&2; exit 1; }
printf 'capture signal and decoder failure checks passed\n'
