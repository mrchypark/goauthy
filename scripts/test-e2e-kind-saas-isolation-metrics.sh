#!/bin/sh
# Exercise the runner's real metrics-forward loop against TCP peers that never
# complete TLS. This checks curl's deadline and per-forward cleanup only.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
cleanup() {
	if [ -n "${fifo_writer_pid:-}" ]; then kill "$fifo_writer_pid" 2>/dev/null || :; wait "$fifo_writer_pid" 2>/dev/null || :; fi
	for port in 18443 18444 18445; do
		if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
			pids=$(cat "$tmp/listener-pids" 2>/dev/null || :)
			for pid in $pids; do kill "$pid" 2>/dev/null || :; done
		fi
	done
	rm -rf "$tmp"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
mkdir "$tmp/bin" "$tmp/evidence"

for tool in awk curl date jq mkfifo nc openssl sh sleep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 1; }
done
for port in 18443 18444 18445; do
	if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then echo "test port already in use: $port" >&2; exit 1; fi
done

# Extract the live collection and aggregate predicates from the production runner.
awk '
	/^for index in 0 1 2; do$/ { copy=1 }
	copy && /^echo "candidate_source=/ { exit }
	copy { print }
' "$root/scripts/e2e-kind-saas-isolation-113.sh" >"$tmp/collection.sh"
[ -s "$tmp/collection.sh" ] || { echo 'could not extract runner metrics collection block' >&2; exit 1; }
grep -F -- '--connect-timeout 1 --max-time 2' "$tmp/collection.sh" >/dev/null || { echo 'runner metrics curl lost its bounded connect/total timeout' >&2; exit 1; }
printf '\n[ "$job_status" -eq 0 ] || exit "$job_status"\n' >>"$tmp/collection.sh"
sh -n "$tmp/collection.sh"

# Keep nc's stdin open without sending bytes so TCP connects but TLS gets no reply.
mkfifo "$tmp/quiet"
sleep 600 >"$tmp/quiet" &
fifo_writer_pid=$!
cat >"$tmp/bin/kubectl" <<'MOCK'
#!/bin/sh
set -eu
last=
for arg do last=$arg; done
port=${last%%:*}
nc -lk 127.0.0.1 "$port" <"$MOCK_QUIET_FIFO" >/dev/null 2>&1 &
listener_pid=$!
printf '%s\n' "$listener_pid" >>"$MOCK_LISTENER_PIDS"
trap 'kill "$listener_pid" 2>/dev/null || :; wait "$listener_pid" 2>/dev/null || :; exit 0' HUP INT TERM
wait "$listener_pid"
MOCK
cat >"$tmp/bin/curl" <<'MOCK'
#!/bin/sh
port=
for arg do
	case $arg in fixture.local:*:127.0.0.1) value=${arg#fixture.local:}; port=${value%%:*};; esac
done
tries=0
until nc -z 127.0.0.1 "$port" >/dev/null 2>&1; do
	tries=$((tries + 1))
	[ "$tries" -lt 50 ] || exit 88
	sleep 0.02
done
touch "$MOCK_LISTENER_READY-$port"
exec "$REAL_CURL" "$@"
MOCK
cat >"$tmp/bin/seq" <<'MOCK'
#!/bin/sh
# One real timed curl per node is enough to cover this boundary and cleanup.
printf '1\n'
MOCK
chmod +x "$tmp/bin/curl" "$tmp/bin/kubectl" "$tmp/bin/seq"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=fixture.local \
	-keyout "$tmp/key.pem" -out "$tmp/ca.crt" >/dev/null 2>&1
: >"$tmp/listener-pids"
REAL_CURL=$(command -v curl)
export REAL_CURL
export MOCK_LISTENER_READY=$tmp/ready MOCK_LISTENER_PIDS=$tmp/listener-pids MOCK_QUIET_FIFO=$tmp/quiet
PATH="$tmp/bin:$PATH"
export PATH

context=kind-test
namespace=goauthy
fixture_host=fixture.local
temp_dir=$tmp
ISOLATION113_EVIDENCE_DIR=$tmp/evidence
job_status=0
export context namespace fixture_host temp_dir ISOLATION113_EVIDENCE_DIR job_status

started=$(date +%s)
set +e
sh "$tmp/collection.sh" >"$tmp/collection.log" 2>&1
status=$?
set -e
elapsed=$(( $(date +%s) - started ))

[ "$status" -ne 0 ] || { echo 'runner collection unexpectedly accepted stalled TLS peers' >&2; exit 1; }
[ "$elapsed" -le 12 ] || { echo "runner collection exceeded 12s bound: ${elapsed}s" >&2; cat "$tmp/collection.log" >&2; exit 1; }
for index in 0 1 2; do
	file=$ISOLATION113_EVIDENCE_DIR/fixture-metrics-$index.json
	[ -f "$file" ] && [ ! -s "$file" ] || { echo "incomplete metrics evidence was not retained for node $index" >&2; exit 1; }
done
for port in 18443 18444 18445; do
	[ -f "$MOCK_LISTENER_READY-$port" ] || { echo "TCP peer did not become ready on $port" >&2; exit 1; }
	if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then echo "forward listener survived cleanup on $port" >&2; exit 1; fi
done
grep -q 'fixture metrics are missing or invalid' "$tmp/collection.log" || { echo 'runner did not report missing metrics evidence' >&2; exit 1; }
grep -q 'natural drain did not meet expectations' "$tmp/collection.log" || { echo 'runner did not reject an unobserved drain' >&2; exit 1; }
printf 'PASS: runner collection status=%s elapsed=%ss; incomplete metrics retained; no owned listeners remain\n' "$status" "$elapsed"
