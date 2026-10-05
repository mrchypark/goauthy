#!/bin/sh
# Focused offline controls for summarize-isolation113-native-timings.sh. No
# cluster, network, Go, Docker or Kubernetes; jq is the only dependency.
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sum="$root/scripts/summarize-isolation113-native-timings.sh"
[ -x "$sum" ] || { echo "missing $sum" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo 'jq required' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' 0 1 2 3 15
checks=0
fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { checks=$((checks + 1)); }

ack() {
  printf 'DIAGNOSTIC113_ACK wal_called=%s wal_ns=%s archive_called=%s archive_ns=%s\n' "$1" "$2" "$3" "$4"
}
prop() {
  printf 'DIAGNOSTIC113_PROPOSAL propose_called=%s propose_ns=%s apply_called=%s apply_ns=%s durability_called=%s durability_ns=%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6"
}
canary() { printf 'PRIVATE url=https://secret.example token=abc sql=SELECT-1\n'; }

case_dir() { d="$work/$1"; mkdir -p "$d"; printf '%s' "$d"; }
assert() { jq -e "$1" "$2" >/dev/null || fail "aggregate does not satisfy: $1"; }
run() {
  [ ! -e "$2" ] || rm "$2"
  set +e
  "$sum" "$1" "$2" >/dev/null 2>&1
  s=$?
  set -e
  printf '%s' "$s"
}

# 1. Valid three-file capture: observed, exact counts and maxima, and no private
#    line, canary or input file name in the aggregate.
d=$(case_dir valid)
: >"$d/native-log-0.private.log"
canary >>"$d/native-log-0.private.log"
printf '2026/10/05 06:00:00 ' >>"$d/native-log-0.private.log"
ack 1 1000000 1 2000000 >>"$d/native-log-0.private.log"
prop 1 3000000 1 4000000 1 5000000 >>"$d/native-log-0.private.log"
printf 'other private line\n' >>"$d/native-log-1.private.log"
ack 1 0 1 0 >>"$d/native-log-1.private.log"
ack 1 7000000 0 0 >>"$d/native-log-2.private.log"
rc=$(run "$d" "$d/out.json")
[ "$rc" = 0 ] || fail "valid capture must be observed, rc=$rc"
assert '.status == "observed" and .incomplete_reason == "none"' "$d/out.json"
assert '.diagnostic_only == true and .qualification_claim == false' "$d/out.json"
assert '.stages.propose.count == 1 and .stages.propose.max_ms == 3' "$d/out.json"
assert '.stages.apply.count == 1 and .stages.apply.max_ms == 4' "$d/out.json"
assert '.stages.durability.count == 1 and .stages.durability.max_ms == 5' "$d/out.json"
assert '.stages.wal.count == 3 and .stages.wal.max_ms == 7' "$d/out.json"
assert '.stages.archive.count == 2 and .stages.archive.max_ms == 2' "$d/out.json"
assert '.collection.log_files_expected == 3 and .collection.log_files_present == 3' "$d/out.json"
if grep -Eq 'canary|secret\.example|SELECT-1|native-log' "$d/out.json"; then
  fail 'aggregate leaked private log content or an input file name'
fi
ok

# 2. Missing input file fails closed.
d=$(case_dir missing)
: >"$d/native-log-0.private.log"
ack 1 1 1 1 >>"$d/native-log-0.private.log"
cp "$d/native-log-0.private.log" "$d/native-log-1.private.log"
rc=$(run "$d" "$d/out.json")
[ "$rc" = 3 ] || fail "missing log file must be nonzero, rc=$rc"
assert '.status == "incomplete" and .incomplete_reason == "missing_log_file"' "$d/out.json"
ok

# 3. An unexpected fourth capture fails closed.
d=$(case_dir extra)
for n in 0 1 2; do
  : >"$d/native-log-$n.private.log"
  ack 1 1 1 1 >>"$d/native-log-$n.private.log"
done
: >"$d/native-log-3.private.log"
rc=$(run "$d" "$d/out.json")
[ "$rc" = 3 ] || fail "unexpected log file must be nonzero, rc=$rc"
assert '.incomplete_reason == "unexpected_log_file"' "$d/out.json"
ok

# 4. An empty capture file fails closed.
d=$(case_dir empty)
for n in 0 1 2; do
  : >"$d/native-log-$n.private.log"
  ack 1 1 1 1 >>"$d/native-log-$n.private.log"
done
: >"$d/native-log-2.private.log"
rc=$(run "$d" "$d/out.json")
[ "$rc" = 3 ] || fail "empty log must be nonzero, rc=$rc"
assert '.incomplete_reason == "empty_log_file"' "$d/out.json"
ok

# 5. Out-of-schema markers: bad numerals, non-bit called flags, uncalled with a
#    nonzero duration, apply0 with durability1, missing and repeated fields.
k=0
for bad in \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=-1 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=0x10 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=1.5 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=10000000000000000 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=0 wal_ns=5 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=0 archive_called=2 archive_ns=0' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=0 archive_called=0 archive_ns=1' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=0 archive_called=1' \
  'DIAGNOSTIC113_ACK wal_called=1 wal_ns=0 wal_ns=0 archive_called=1 archive_ns=0' \
  'DIAGNOSTIC113_PROPOSAL propose_called=1 propose_ns=0 apply_called=0 apply_ns=0 durability_called=1 durability_ns=0' \
  'DIAGNOSTIC113_PROPOSAL propose_called=0 propose_ns=0 apply_called=0 apply_ns=0 durability_called=0 durability_ns=0' \
  'DIAGNOSTIC113_PROPOSAL propose_called=1 propose_ns=0 apply_called=0 apply_ns=1 durability_called=0 durability_ns=0' \
  'DIAGNOSTIC113_PROPOSAL propose_called=1 propose_ns=0 apply_called=1 apply_ns=0 durability_called=0 durability_ns=1'
do
  k=$((k + 1))
  d=$(case_dir "bad-$k")
  for n in 0 1 2; do
    : >"$d/native-log-$n.private.log"
    ack 1 1 1 1 >>"$d/native-log-$n.private.log"
    prop 1 1 1 1 1 1 >>"$d/native-log-$n.private.log"
  done
  printf '%s\n' "$bad" >>"$d/native-log-0.private.log"
  rc=$(run "$d" "$d/out.json")
  [ "$rc" = 3 ] || fail "out-of-schema marker must be nonzero: $bad (rc=$rc)"
  assert '.incomplete_reason == "invalid_marker_line"' "$d/out.json"
done
ok

# 6. Zero elapsed is valid when called, and a 2^53-safe duration is accepted.
d=$(case_dir large)
for n in 0 1 2; do : >"$d/native-log-$n.private.log"; done
ack 1 9007199254740991 1 0 >>"$d/native-log-0.private.log"
prop 1 0 1 0 1 0 >>"$d/native-log-1.private.log"
ack 1 0 0 0 >>"$d/native-log-2.private.log"
rc=$(run "$d" "$d/out.json")
[ "$rc" = 0 ] || fail "zero elapsed when called must be observed, rc=$rc"
assert '.stages.propose.count == 1 and .stages.propose.max_ms == 0' "$d/out.json"
assert '.stages.durability.count == 1 and .stages.durability.max_ms == 0' "$d/out.json"
assert '.stages.wal.max_ms > 9007199000 and .stages.wal.max_ms < 9007200000' "$d/out.json"
ok

# 7. An existing output file is refused and left byte-for-byte unchanged.
d=$(case_dir exists)
for n in 0 1 2; do
  : >"$d/native-log-$n.private.log"
  ack 1 1 1 1 >>"$d/native-log-$n.private.log"
  prop 1 1 1 1 1 1 >>"$d/native-log-$n.private.log"
done
printf 'PRIOR\n' >"$d/out.json"
set +e
"$sum" "$d" "$d/out.json" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" = 2 ] || fail "an existing output must be refused, rc=$rc"
[ "$(cat "$d/out.json")" = PRIOR ] || fail 'an existing output was modified'
ok

echo "test-isolation113-native-timings: $checks checks passed"
