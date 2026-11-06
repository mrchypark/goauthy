#!/bin/sh
# Synthetic Local archive compatibility; never accepts an existing data path.
set -eu
umask 077
race=
case "$#:${1:-}" in
  0:) ;;
  1:--race) race=-race ;;
  *) echo 'usage: test-rhiza-local-upgrade.sh [--race]' >&2; exit 2 ;;
esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
export GOENV=off GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE= GONOSUMDB= GONOPROXY=
work=$(mktemp -d "${TMPDIR:-/tmp}/goauthy-local-upgrade.XXXXXX")
child=
cleanup() {
  code=$?
  trap - 0 1 2 15
  if [ -n "$child" ]; then
    kill -INT "$child" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 75 ] && kill -0 "$child" 2>/dev/null; do sleep 1; attempt=$((attempt + 1)); done
    if kill -0 "$child" 2>/dev/null; then
      echo "owned child still active: PID=$child; retained work=$work" >&2
      exit 1
    fi
    wait "$child" 2>/dev/null || true
  fi
  rm -rf "$work"
  [ ! -e "$work" ] || exit 1
  echo 'cleanup=PASS temporary test binaries/data absent'
  exit "$code"
}
run() {
  "$@" &
  child=$!
  echo "owned child PID=$child" >&2
  if wait "$child"; then status=0; else status=$?; fi
  child=
  return "$status"
}
run_phase() {
  phase_label=$1
  phase_test=$2
  phase_binary=$3
  shift 3
  phase_status=0
  run "$phase_binary" "-test.run=^$phase_test$" -test.v "$@" > "$work/$phase_label.log" 2>&1 || phase_status=$?
  cat "$work/$phase_label.log"
  [ "$phase_status" -eq 0 ] || return "$phase_status"
  grep -Fxq "=== RUN   $phase_test" "$work/$phase_label.log" || return 1
  if grep -Eq '^[[:space:]]*--- SKIP:' "$work/$phase_label.log"; then return 1; fi
  if [ "$phase_label" = write ]; then
    # Deliberate process exit without Close cannot emit testing's final PASS.
    grep -Fxq 'COMPAT-WRITER-ACK-COMPLETE' "$work/$phase_label.log" || return 1
  else
    grep -Fq -- "--- PASS: $phase_test (" "$work/$phase_label.log" || return 1
  fi
  echo "phase=$phase_label exact-test=$phase_test completed; no skips"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 1 15
cd "$root"
printf '%s\n' 'fixture source SHA256 (working tree, not a release artifact):'
shasum -a 256 scripts/test-rhiza-local-upgrade.sh cmd/goauthy-rhiza-init/compatibility_test.go go.mod go.sum
cp go.mod "$work/producer.mod"
cp go.sum "$work/producer.sum"
go mod edit -modfile="$work/producer.mod" -require=github.com/mrchypark/rhiza@v0.21.2
# Build only GoAuthy's own existing init tests against each published SDK.
run go test ${race:+"$race"} -mod=mod -modfile="$work/producer.mod" -p 1 -c -o "$work/producer" ./cmd/goauthy-rhiza-init
run go test ${race:+"$race"} -mod=readonly -p 1 -c -o "$work/consumer" ./cmd/goauthy-rhiza-init
go version -m "$work/producer" | sed -n '/github.com\/mrchypark\/rhiza/p'
go version -m "$work/consumer" | sed -n '/github.com\/mrchypark\/rhiza/p'
mkdir "$work/live"
export GOAUTHY_INIT_LIFECYCLE_TEST_ROOT="$work/live"
for phase in seed write; do
  GOAUTHY_LOCAL_COMPAT_VERSION=v0.21.2 GOAUTHY_LOCAL_COMPAT_PHASE=$phase run_phase "$phase" TestLocalArchiveVersionCompatibilityPhases "$work/producer" -test.timeout=2m
done
# Producer exits without Close after its BeforeAck receipt; keep an unopened copy.
cp -Rp "$work/live" "$work/original"
digest() { (cd "$1" && find . -type f -exec shasum -a 256 {} + | LC_ALL=C sort); }
digest "$work/original" > "$work/original.before"
printf '%s\n' 'original tree manifest / binding / ACK receipt SHA256:'
shasum -a 256 "$work/original.before" "$work/original/data/local-backup.json" "$work/original/compat-receipt.json"
printf '%s\n' 'original synthetic mutation ACK receipt:'
cat "$work/original/compat-receipt.json"
printf '\n'
# Negative identity cases must refuse even a retained producer DataDir.
# qlog/lock.qlog is process-lock PID metadata, not recovered WAL content.
# Rhiza's own unchanged-tree tests exclude this exact file too.
digest "$work/live" | sed '\|  ./data/qlog/lock.qlog$|d' > "$work/live.before"
for negative in changed-node wrong-target; do
  GOAUTHY_INIT_REFUSAL_TEST_ROOT="$work/live" GOAUTHY_INIT_REFUSAL_TEST_CASE=$negative \
    run_phase "$negative" TestRestoreInitRefusesChangedBoundHistory "$work/consumer" -test.timeout=30s
done
digest "$work/live" | sed '\|  ./data/qlog/lock.qlog$|d' > "$work/live.after"
diff -u "$work/live.before" "$work/live.after"
printf '%s\n' 'negative before/after manifest SHA256 (must match):'
shasum -a 256 "$work/live.before" "$work/live.after"
GOAUTHY_LOCAL_COMPAT_VERSION=v0.23.0 GOAUTHY_LOCAL_COMPAT_PHASE=retained run_phase retained TestLocalArchiveVersionCompatibilityPhases "$work/consumer" -test.timeout=2m
cmp "$work/original/data/local-backup.json" "$work/live/data/local-backup.json"
# Restore an untouched producer archive at its original location, not a new
# namespace. Cold recovery must derive its binding from the archive itself.
rm -rf "$work/live/data"
rm -rf "$work/live/objects"
cp -Rp "$work/original/objects" "$work/live/objects"
[ ! -e "$work/live/data" ]
for phase in cold second; do
  GOAUTHY_LOCAL_COMPAT_VERSION=v0.23.0 GOAUTHY_LOCAL_COMPAT_PHASE=$phase run_phase "$phase" TestLocalArchiveVersionCompatibilityPhases "$work/consumer" -test.timeout=2m
  cmp "$work/original/data/local-backup.json" "$work/live/data/local-backup.json"
  if [ "$phase" = cold ]; then
    rm -rf "$work/live/data"
    [ ! -e "$work/live/data" ]
  fi
done
digest "$work/original" > "$work/original.after"
cmp "$work/original.before" "$work/original.after"
printf '%s\n' 'final original tree manifest SHA256 (must match original):'
shasum -a 256 "$work/original.after"
printf '%s\n' 'PASS: v0.21.2 -> v0.23.0; retained upgrade, nonempty snapshot+abrupt ACK tail, cold+second init/main restore, exact receipt replay, no duplicates, new write, binding refusal, original copy unchanged'
