#!/bin/sh
# Focused offline controls for scripts/summarize-isolation113-stage-aggregate.sh.
#
# Runs the real summarizer against synthetic raw recordings in a temporary
# directory. No cluster, no network, no Go, no Docker, no Kubernetes. jq is the
# only dependency; the script is POSIX sh and is expected to be exercised under
# more than one jq version by the caller.
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
summarizer="$root/scripts/summarize-isolation113-stage-aggregate.sh"
[ -x "$summarizer" ] || { echo "missing summarizer: $summarizer" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

checks=0
fail() {
  echo "FAIL: $1" >&2
  exit 1
}
ok() {
  checks=$((checks + 1))
}

# Real epoch nanoseconds, far beyond the 2^53 safe-integer range. A timestamp
# bound that used2^53 would reject every real record.
ns_base=1791176000000000000
ns_step=1000000

# record NAME START DELTA_MS [EXTRA] -> one NDJSON line with exactly seven keys
record() {
  jq -cn \
    --arg trace 'abababababababababababababababab' \
    --arg span 'cdcdcdcdcdcdcdcd' \
    --arg parent 'efefefefefefefef' \
    --arg name "$1" \
    --argjson start "$2" \
    --argjson dur "$3" \
    --argjson end "$(awk -v s="$2" -v d="$3" 'BEGIN { printf "%.0f", s + d * 1000000 }')" \
    '{trace_id:$trace, span_id:$span, parent_span_id:$parent, start_ns:$start, end_ns:$end, duration_ms:$dur, name:$name}'
}

# aggregate_stages -> prints the 18 stage names, one per line
stage_names() {
  printf '%s\n' \
    credential_lookup password_verify subject_revalidate interaction_consume \
    session_rotate oauth_issue authorize_validate authorize_session policy_check \
    policy_allow policy_account_lock policy_success session_load request_resolve \
    storage_execute storage_submit storage_status storage_replay
}

run_summarizer() {
  # run_summarizer RAW WRAPPER_RC [CRITERION] -> writes $work/out.json
  raw=$1
  wrapper_rc=$2
  criterion=${3:-}
  if [ -e "$work/out.json" ]; then rm "$work/out.json"; fi
  if [ -e "$work/out.json.stats" ]; then rm "$work/out.json.stats"; fi
  if [ -n "$criterion" ]; then
    set +e
    "$summarizer" "$raw" "$work/out.json" "$wrapper_rc" "$criterion" >/dev/null 2>&1
    printf '%s' "$?"
    set -e
  else
    set +e
    "$summarizer" "$raw" "$work/out.json" "$wrapper_rc" >/dev/null 2>&1
    printf '%s' "$?"
    set -e
  fi
}

assert_json() {
  jq -e "$1" "$work/out.json" >/dev/null || fail "aggregate does not satisfy: $1"
}

stage_count() {
  jq -r --arg n "$1" '.stages[$n].count' "$work/out.json"
}

# --------------------------------------------------------------- positive case
# One empty-name HTTP span plus one span for each of the 18 stage names. The
# empty name is a valid HTTP server span projection and must not be rejected.
positive="$work/positive.ndjson"
: >"$positive"
record "" "$ns_base" 1.5 >>"$positive"
stage_names | while read -r name; do
  record "$name" "$ns_base" 2 >>"$positive"
done
# A second storage_replay and a larger storage_submit so maxima and increments
# are distinguishable from counts.
record storage_replay "$ns_base" 9 >>"$positive"
record storage_submit "$ns_base" 7 >>"$positive"

rc=$(run_summarizer "$positive" 0)
[ "$rc" = 0 ] || fail "positive case must be observed, got rc=$rc"
assert_json '.diagnostic_status == "observed"'
assert_json '.incomplete_reason == "none"'
assert_json '.diagnostic_only == true and .qualification_claim == false'
assert_json '.campaign_exit_code == 0'
# 21 records: 18 stage names, one HTTP span and two repeated storage stages.
assert_json '.collection.raw_records == 21'
assert_json '.stages.storage_replay.count == 2'
assert_json '.stages.storage_submit.count == 2'
assert_json '.stages.storage_execute.count == 1'
assert_json '.stages.storage_submit.max_ms == 7'
assert_json '.stages.storage_replay.max_ms == 9'
assert_json '.stages.password_verify.max_ms == 2'
# Every one of the 18 names is present, with no extra key.
assert_json '(.stages | keys | length) == 18'
assert_json '([.stages | keys[]] - ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session","policy_check","policy_allow","policy_account_lock","policy_success","session_load","request_resolve","storage_execute","storage_submit","storage_status","storage_replay"]) | length == 0'
# Privacy: no identifiers, no raw strings, no per-request correlation keys.
assert_json '[paths(scalars) | last | tostring] | all(.[]; test("^(trace_id|span_id|parent_span_id|url|sql|token|password|secret)$"; "i") | not)'
assert_json 'has("records") | not'
assert_json 'has("raw") | not'
# No arithmetic across enclosing and nested stages, and no driver/pod/phase keys.
assert_json '[(.stages | keys[]) as $k | (.stages[$k] | keys_unsorted | sort)] | all(. == ["count","max_ms"])'
assert_json 'has("drivers") | not'
assert_json 'has("pods") | not'
assert_json 'has("phases") | not'
assert_json '[paths | last | tostring] | all(.[]; test("^(total|sum|residual)$"; "i") | not)'
assert_json '(.limitations | length) >= 5'
ok

# ------------------------------------------------- raw_records binds input list
# The recorded length is the raw record list, not the 18-entry stage map.
assert_json '.collection.raw_records != 18'
assert_json '.collection.raw_records == 21'
ok

# --------------------------------------------------------- criteria happy path
criterion_ok="$work/criterion.json"
cat >"$criterion_ok" <<'JSON'
{
  "performance": {
    "comparisons": [
      {"driver_index": 0, "pass": true},
      {"driver_index": 0, "pass": false},
      {"driver_index": 1, "pass": false},
      {"driver_index": 1, "pass": false},
      {"driver_index": 2, "pass": true},
      {"driver_index": 2, "pass": false}
    ]
  },
  "protected": {"errors": 1}
}
JSON
raw_observed="$work/observed.ndjson"
: >"$raw_observed"
record storage_execute "$ns_base" 1 >>"$raw_observed"
record storage_submit "$ns_base" 1 >>"$raw_observed"
rc=$(run_summarizer "$raw_observed" 1 "$criterion_ok")
# A failing campaign with a valid recording keeps its own non-zero code, while
# the diagnostic itself is observed and therefore not reported as incomplete.
[ "$rc" = 0 ] || fail "failing campaign with observed recording must not force incomplete, got rc=$rc"
assert_json '.campaign_exit_code == 1'
assert_json '.diagnostic_status == "observed"'
assert_json '.criteria.failed_relative_comparisons == 4'
assert_json '.criteria.failed_comparisons_complete == true'
assert_json '.criteria.expected_comparisons == 6'
assert_json '.criteria.protected_errors == 1'
ok

# Incomplete comparison set must stay null, never 0, and must not be reported as
# a complete zero-failure extraction.
criterion_short="$work/criterion-short.json"
cat >"$criterion_short" <<'JSON'
{"performance": {"comparisons": [{"pass": true}, {"pass": false}]}, "protected": {"errors": 0}}
JSON
rc=$(run_summarizer "$raw_observed" 0 "$criterion_short")
[ "$rc" = 0 ] || fail "observed recording with a short comparison set must still be observed"
assert_json '.criteria.failed_relative_comparisons == null'
assert_json '.criteria.failed_comparisons_complete == false'
assert_json '.criteria.protected_errors == 0'
ok

# Missing criterion entirely stays null.
rc=$(run_summarizer "$raw_observed" 0)
[ "$rc" = 0 ] || fail "observed recording without criterion must be observed"
assert_json '.criteria.failed_relative_comparisons == null'
assert_json '.criteria.failed_comparisons_complete == false'
assert_json '.criteria.protected_errors == null'
ok

# Malformed criterion stays null on both fields.
criterion_bad="$work/criterion-bad.json"
printf '%s\n' '{ this is not json' >"$criterion_bad"
rc=$(run_summarizer "$raw_observed" 0 "$criterion_bad")
[ "$rc" = 0 ] || fail "observed recording with a malformed criterion must be observed"
assert_json '.criteria.failed_relative_comparisons == null'
assert_json '.criteria.protected_errors == null'
ok

# Non-integer protected errors stays null rather than collapsing to zero.
criterion_protected_bad="$work/criterion-protected-bad.json"
cat >"$criterion_protected_bad" <<'JSON'
{"performance": {"comparisons": [{"pass": true},{"pass": true},{"pass": true},{"pass": true},{"pass": true},{"pass": true}]}, "protected": {"errors": "one"}}
JSON
rc=$(run_summarizer "$raw_observed" 0 "$criterion_protected_bad")
[ "$rc" = 0 ] || fail "observed recording must stay observed"
assert_json '.criteria.protected_errors == null'
assert_json '.criteria.failed_relative_comparisons == 0'
ok

# --------------------------------------------------------------- wrapper rc
rc=$(run_summarizer "$raw_observed" 0)
[ "$rc" = 0 ] || fail "campaign pass with an observed recording must succeed"
rc=$(run_summarizer "$raw_observed" 255)
[ "$rc" = 0 ] || fail "campaign 255 with an observed recording must keep the diagnostic observed"
assert_json '.campaign_exit_code == 255'
for bad_rc in '' abc 256 999 -1 1.5; do
  [ ! -e "$work/out.json" ] || rm "$work/out.json"
  set +e
  "$summarizer" "$raw_observed" "$work/out.json" "$bad_rc" >/dev/null 2>&1
  bad_status=$?
  set -e
  [ "$bad_status" = 2 ] || fail "wrapper rc '$bad_rc' must be rejected with status 2, got $bad_status"
  [ -e "$work/out.json" ] && fail "wrapper rc '$bad_rc' must not produce an aggregate"
done
# A leading zero is normalized rather than treated as octal or rejected.
rc=$(run_summarizer "$raw_observed" 007)
[ "$rc" = 0 ] || fail "zero-padded wrapper rc must be accepted"
assert_json '.campaign_exit_code == 7'
ok

# ------------------------------------------------------- incomplete conditions
# Missing recording: safe incomplete aggregate and non-zero, even for campaign 0.
missing="$work/absent.ndjson"
[ -e "$missing" ] || : >"$missing"
rc=$(run_summarizer "$missing" 0)
[ "$rc" != 0 ] || fail "missing recording must be non-zero"
assert_json '.diagnostic_status == "incomplete"'
assert_json '.incomplete_reason == "raw_capture_missing"'
assert_json '.collection.raw_records == 0'
assert_json '(.stages | length) == 0'
assert_json '.criteria.failed_relative_comparisons == null'
ok

absent="$work/absent-path.ndjson"
rc=$(run_summarizer "$absent" 0)
[ "$rc" != 0 ] || fail "absent recording path must be non-zero"
assert_json '.incomplete_reason == "raw_capture_missing"'
ok

# Malformed raw.
malformed="$work/malformed.ndjson"
printf '%s\n' '{"trace_id":"zz"' >"$malformed"
rc=$(run_summarizer "$malformed" 0)
[ "$rc" != 0 ] || fail "malformed recording must be non-zero"
assert_json '.incomplete_reason == "raw_parse_failed"'
ok

# Unexpected eighth field.
extra_field="$work/extra-field.ndjson"
jq -cn '{trace_id:"abababababababababababababababab", span_id:"cdcdcdcdcdcdcdcd", parent_span_id:"efefefefefefefef", start_ns:1, end_ns:2, duration_ms:0.001, name:"storage_execute", extra:"leak"}' >"$extra_field"
rc=$(run_summarizer "$extra_field" 0)
[ "$rc" != 0 ] || fail "an eighth field must be rejected"
assert_json '.incomplete_reason == "raw_parse_failed"'
ok

# Unknown stage name, including a near miss next to the new stages.
for bad_name in storage storage_submit_v2 storage_status_extra storage_replay_attempt; do
  bad_name_raw="$work/bad-name.ndjson"
  jq -cn --arg n "$bad_name" '{trace_id:"abababababababababababababababab", span_id:"cdcdcdcdcdcdcdcd", parent_span_id:"", start_ns:1, end_ns:2, duration_ms:0.001, name:$n}' >"$bad_name_raw"
  rc=$(run_summarizer "$bad_name_raw" 0)
  [ "$rc" != 0 ] || fail "unknown stage name '$bad_name' must be rejected"
  assert_json '.incomplete_reason == "raw_parse_failed"'
done
ok

# Negative, non-integer, reversed and non-finite field values.
for bad_json in \
  '{"trace_id":"abababababababababababababababab","span_id":"cdcdcdcdcdcdcdcd","parent_span_id":"","start_ns":-1,"end_ns":2,"duration_ms":0.001,"name":"storage_execute"}' \
  '{"trace_id":"abababababababababababababababab","span_id":"cdcdcdcdcdcdcdcd","parent_span_id":"","start_ns":1.5,"end_ns":2,"duration_ms":0.001,"name":"storage_execute"}' \
  '{"trace_id":"abababababababababababababababab","span_id":"cdcdcdcdcdcdcdcd","parent_span_id":"","start_ns":9,"end_ns":2,"duration_ms":0.001,"name":"storage_execute"}' \
  '{"trace_id":"abababababababababababababababab","span_id":"cdcdcdcdcdcdcdcd","parent_span_id":"","start_ns":1,"end_ns":2,"duration_ms":-0.5,"name":"storage_execute"}' \
  '{"trace_id":"abababababababababababababababab","span_id":"cdcdcdcdcdcdcdcd","parent_span_id":"","start_ns":1,"end_ns":2,"duration_ms":1e400,"name":"storage_execute"}'
do
  bad_value_raw="$work/bad-value.ndjson"
  printf '%s\n' "$bad_json" >"$bad_value_raw"
  rc=$(run_summarizer "$bad_value_raw" 0)
  [ "$rc" != 0 ] || fail "invalid field value must be rejected: $bad_json"
  assert_json '.incomplete_reason == "raw_parse_failed"'
done
# A non-finite literal is not valid JSON at all, so it is malformed input rather
# than a shape failure; both must be non-zero and safe.
nonfinite="$work/nonfinite.ndjson"
printf '%s\n' '{"start_ns":NaN,"end_ns":1,"duration_ms":0,"name":"storage_execute","trace_id":"","span_id":"","parent_span_id":""}' >"$nonfinite"
rc=$(run_summarizer "$nonfinite" 0)
[ "$rc" != 0 ] || fail 'a non-finite literal must be rejected'
assert_json '.incomplete_reason == "raw_parse_failed"'
ok

# Missing outer stage or missing submit stage.
no_outer="$work/no-outer.ndjson"
: >"$no_outer"
record storage_submit "$ns_base" 1 >>"$no_outer"
rc=$(run_summarizer "$no_outer" 0)
[ "$rc" != 0 ] || fail "a recording without storage_execute must be incomplete"
assert_json '.incomplete_reason == "no_outer_or_submit_spans_observed"'
assert_json '.collection.raw_records == 1'
assert_json '.stages.storage_submit.count == 1'
assert_json '.stages.storage_execute.count == 0'
ok

no_submit="$work/no-submit.ndjson"
: >"$no_submit"
record storage_execute "$ns_base" 1 >>"$no_submit"
rc=$(run_summarizer "$no_submit" 0)
[ "$rc" != 0 ] || fail "a recording without storage_submit must be incomplete"
assert_json '.incomplete_reason == "no_outer_or_submit_spans_observed"'
assert_json '.stages.storage_execute.count == 1'
assert_json '.stages.storage_submit.count == 0'
ok

# An empty-but-valid capture that only carries HTTP spans.
http_only="$work/http-only.ndjson"
: >"$http_only"
record "" "$ns_base" 1 >>"$http_only"
record "" "$ns_base" 1 >>"$http_only"
rc=$(run_summarizer "$http_only" 0)
[ "$rc" != 0 ] || fail "an HTTP-only capture must be incomplete"
assert_json '.incomplete_reason == "no_outer_or_submit_spans_observed"'
assert_json '.collection.raw_records == 2'
assert_json '(.stages | length) == 18'
ok

# ---------------------------------------------- >2^53 timestamps are accepted
# The positive case already uses real epoch nanoseconds; assert explicitly that
# they exceed the 2^53 safe-integer range and were still counted.
if [ "$(awk -v n="$ns_base" 'BEGIN { print (n > 9007199254740991) ? 1 : 0 }')" = 1 ]; then
  ok
else
  fail "the epoch nanosecond fixture must exceed 2^53"
fi
rc=$(run_summarizer "$positive" 0)
[ "$rc" = 0 ] || fail 'positive timestamps must remain accepted'
assert_json '.stages.storage_execute.count == 1'
ok

# --------------------------------------------------------------- output hygiene
# Nothing but the aggregate is left behind next to the output, and no raw
# identifier ever appears in the aggregate file itself.
[ -e "$work/out.json.stats" ] && fail 'the work file must be removed'
if grep -Eq '"(trace_id|span_id|parent_span_id)"' "$work/out.json"; then
  fail 'the aggregate must not contain identifier fields'
fi
if grep -Fq 'abababababababababababababababab' "$work/out.json"; then
  fail 'the aggregate must not contain raw identifiers'
fi
[ -s "$work/out.json" ] || fail 'the aggregate must be non-empty'
ok

echo "test-isolation113-stage-aggregate: $checks checks passed (jq $(jq --version))"
