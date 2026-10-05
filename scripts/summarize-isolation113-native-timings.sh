#!/bin/sh
# DIAGNOSTIC ONLY bounded aggregate for #113 native propose/apply/durability and
# WAL/ACK recording. Reads ONLY this run's three private native log files and
# emits fixed per-name counts and maxima plus collection completeness. It never
# emits log lines, file names, identifiers, SQL, URLs or error strings, and it
# performs no arithmetic across concurrent, possibly overlapping calls.
#
# Exit status: 0 observed, 2 usage/unreadable, 3 incomplete.
# Usage: summarize-isolation113-native-timings.sh INPUT_DIR OUTPUT_JSON
set -eu
umask 077

[ "$#" -eq 2 ] || {
  echo 'usage: summarize-isolation113-native-timings.sh INPUT_DIR OUTPUT_JSON' >&2
  exit 2
}
dir=$1
out=$2
[ -d "$dir" ] || { echo 'summarize: input dir must exist' >&2; exit 2; }
[ ! -e "$out" ] || { echo 'summarize: refusing to overwrite output' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo 'summarize: jq is required' >&2; exit 2; }

work=$(mktemp)
trap '[ ! -e "$work" ] || rm "$work"' 0 1 2 3 15

extra=0
for f in "$dir"/native-log-*.private.log; do
  [ -e "$f" ] || continue
  case ${f##*/} in
  native-log-0.private.log | native-log-1.private.log | native-log-2.private.log) ;;
  *) extra=$((extra + 1)) ;;
  esac
done

missing=0
empty=0
have=0
set --
n=0
while [ "$n" -lt 3 ]; do
  f="$dir/native-log-$n.private.log"
  if [ -f "$f" ]; then
    set -- "$@" "$f"
    have=$((have + 1))
    [ -s "$f" ] || empty=$((empty + 1))
  else
    missing=$((missing + 1))
  fi
  n=$((n + 1))
done

[ "$have" -gt 0 ] || set -- /dev/null

awk -v missing="$missing" -v empty="$empty" -v extra="$extra" -v have="$have" \
  -v e0="$dir/native-log-0.private.log" -v e1="$dir/native-log-1.private.log" \
  -v e2="$dir/native-log-2.private.log" '
function isdig(s) { return s ~ /^[0-9]+$/ }
function numok(s) { return isdig(s) && length(s) <= 16 && (s + 0) <= 9007199254740991 }
function isbit(s) { return s == "0" || s == "1" }
function need(p) { if (!((p in recs) && recs[p] > 0)) zero = 1 }
{ if (match($0, /DIAGNOSTIC113_(ACK|PROPOSAL)/)) $0 = substr($0, RSTART) }
$1 == "DIAGNOSTIC113_ACK" {
  walc = 0; waln = 0; arcc = 0; arcn = 0; bad = 0
  if (NF != 5) bad = 1
  else {
    if (split($2, a, "=") != 2 || a[1] != "wal_called" || !isbit(a[2])) bad = 1; walc = a[2] + 0
    if (split($3, a, "=") != 2 || a[1] != "wal_ns" || !numok(a[2])) bad = 1; waln = a[2] + 0
    if (split($4, a, "=") != 2 || a[1] != "archive_called" || !isbit(a[2])) bad = 1; arcc = a[2] + 0
    if (split($5, a, "=") != 2 || a[1] != "archive_ns" || !numok(a[2])) bad = 1; arcn = a[2] + 0
    if (walc != 1) bad = 1
    if (arcc == 0 && arcn != 0) bad = 1
  }
  if (bad) { inv = 1; next }
  recs[FILENAME]++
  if (walc == 1) { walq++; if (waln > walmax) walmax = waln }
  if (arcc == 1) { arcq++; if (arcn > arcmax) arcmax = arcn }
  if (walc == 1 && arcc == 1) ackfull++
  next
}
$1 == "DIAGNOSTIC113_PROPOSAL" {
  prc = 0; prn = 0; apc = 0; apn = 0; duc = 0; dun = 0; bad = 0
  if (NF != 7) bad = 1
  else {
    if (split($2, a, "=") != 2 || a[1] != "propose_called" || !isbit(a[2])) bad = 1; prc = a[2] + 0
    if (split($3, a, "=") != 2 || a[1] != "propose_ns" || !numok(a[2])) bad = 1; prn = a[2] + 0
    if (split($4, a, "=") != 2 || a[1] != "apply_called" || !isbit(a[2])) bad = 1; apc = a[2] + 0
    if (split($5, a, "=") != 2 || a[1] != "apply_ns" || !numok(a[2])) bad = 1; apn = a[2] + 0
    if (split($6, a, "=") != 2 || a[1] != "durability_called" || !isbit(a[2])) bad = 1; duc = a[2] + 0
    if (split($7, a, "=") != 2 || a[1] != "durability_ns" || !numok(a[2])) bad = 1; dun = a[2] + 0
    if (prc != 1) bad = 1
    if (apc == 0 && apn != 0) bad = 1
    if (duc == 0 && dun != 0) bad = 1
    if (apc == 0 && duc == 1) bad = 1
  }
  if (bad) { inv = 1; next }
  recs[FILENAME]++
  if (prc == 1) { prq++; if (prn > prmax) prmax = prn }
  if (apc == 1) { apq++; if (apn > apmax) apmax = apn }
  if (duc == 1) { duq++; if (dun > dumax) dumax = dun }
  if (prc == 1 && apc == 1 && duc == 1) propfull++
  next
}
index($0, "DIAGNOSTIC113_") { inv = 1; next }
END {
  need(e0); need(e1); need(e2)
  reason = ""
  if (missing > 0) reason = "missing_log_file"
  else if (extra > 0) reason = "unexpected_log_file"
  else if (empty > 0) reason = "empty_log_file"
  else if (inv) reason = "invalid_marker_line"
  else if (zero) reason = "zero_record_file"
  else if (ackfull == 0) reason = "missing_acked_pair"
  else if (propfull == 0) reason = "missing_full_proposal"
  status = (reason == "") ? "observed" : "incomplete"
  if (reason == "") reason = "none"
  printf "{\"status\":\"%s\",\"reason\":\"%s\",\"stages\":{", status, reason
  printf "\"propose\":{\"count\":%d,\"max_ms\":%.6f},", prq, prmax / 1e6
  printf "\"apply\":{\"count\":%d,\"max_ms\":%.6f},", apq, apmax / 1e6
  printf "\"durability\":{\"count\":%d,\"max_ms\":%.6f},", duq, dumax / 1e6
  printf "\"wal\":{\"count\":%d,\"max_ms\":%.6f},", walq, walmax / 1e6
  printf "\"archive\":{\"count\":%d,\"max_ms\":%.6f}}}\n", arcq, arcmax / 1e6
}
' "$@" >"$work"

status=$(jq -r '.status' "$work")
reason=$(jq -r '.reason' "$work")

jq -n --argjson agg "$(cat "$work")" --argjson have "$have" '{
  schema: "isolation113-native-timings/v1",
  diagnostic_only: true,
  qualification_claim: false,
  status: $agg.status,
  incomplete_reason: $agg.reason,
  collection: {
    log_files_expected: 3,
    log_files_present: $have,
    coverage_note: "nonzero per-name counts are observation evidence for this run only, not proof of universal export coverage"
  },
  stages: $agg.stages,
  limitations: [
    "ACK and proposal record counts are independent; no marker is matched against another",
    "timings from concurrent calls may overlap; each per-name maximum stands alone and is never summed, differenced or made exclusive",
    "no proposal, apply or durability duration is derived from any other",
    "a zero count for a stage does not disprove a code path when collection is incomplete",
    "no driver, pod, phase or CPU attribution is present or implied",
    "native captures are bounded to the last 20000 lines and 8MiB per member; truncated or absent calls are not disproven",
    "diagnostic only: not a qualification, performance, SLO or production claim",
    "private native log content, file names and log lines are never published"
  ]
}' >"$out"
chmod 600 "$out"
rm "$work"
trap - 0 1 2 3 15

if [ "$status" != observed ]; then
  echo "summarize: native timing diagnostic INCOMPLETE ($reason); evidence must be read as unresolved" >&2
  exit 3
fi
exit 0
