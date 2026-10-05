#!/bin/sh
# Diagnostic-only bounded aggregate for the #113 storage-stage recording.
#
# Reads ONLY this run's private raw NDJSON and emits fixed stage names, counts,
# maxima and collection completeness. It never emits raw traces, span or trace
# identifiers, attributes, events, errors, URLs, SQL or tokens. It performs no
# arithmetic across enclosing and nested stages.
#
# Exit status precedence (most severe first, in this fixed order):
#   2  usage or unreadable input (no aggregate is produced)
#   3  diagnostic incomplete (missing, unparsable, or no outer/submit spans),
#      or the campaign passed while the diagnostic is incomplete
#   0  diagnostic observed
# A non-zero campaign exit code is the expected source performance failure. It
# is recorded verbatim and never converted into a pass, but on its own it does
# not make the diagnostic incomplete.
#
# Usage:
#   summarize-isolation113-stage-aggregate.sh RAW_NDJSON OUT_JSON WRAPPER_RC [CRITERION_JSON]
set -eu
umask 077

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || {
  echo 'usage: summarize-isolation113-stage-aggregate.sh RAW_NDJSON OUT_JSON WRAPPER_RC [CRITERION_JSON]' >&2
  exit 2
}
raw=$1
out=$2
wrapper_rc=$3
criterion=${4:-}

# Wrapper exit status is a byte value. Validate the numeral and the range
# without arithmetic overflow, then normalize a leading zero away.
case "$wrapper_rc" in
'' | *[!0-9]*)
  echo 'summarize: WRAPPER_RC must be a decimal numeral' >&2
  exit 2
  ;;
esac
wrapper_len=${#wrapper_rc}
if [ "$wrapper_len" -gt 3 ] || { [ "$wrapper_len" -eq 3 ] && [ "$wrapper_rc" \> 255 ]; }; then
  echo 'summarize: WRAPPER_RC must be 0..255' >&2
  exit 2
fi
while [ "${wrapper_rc#0}" != "$wrapper_rc" ] && [ "${#wrapper_rc}" -gt 1 ]; do
  wrapper_rc=${wrapper_rc#0}
done

command -v jq >/dev/null 2>&1 || { echo 'summarize: jq is required' >&2; exit 2; }

stages='credential_lookup password_verify subject_revalidate interaction_consume session_rotate oauth_issue authorize_validate authorize_session policy_check policy_allow policy_account_lock policy_success session_load request_resolve storage_execute storage_submit storage_status storage_replay'

status=observed
reason=none
stats=/dev/null

# Bounded work file inside the caller-owned output directory: no mktemp and no
# trap cleanup, so nothing outside this run's own results path is ever removed.
stats="$out.stats"

if [ ! -s "$raw" ]; then
  status=incomplete
  reason=raw_capture_missing
  stats=/dev/null
else
  # Privacy and integrity gate for every record before any value is used:
  #   - exactly the seven projected record keys, nothing else
  #   - fixed hex identifier shapes
  #   - finite non-negative integer timestamps (nanosecond precision, so the
  #     2^53 safe-integer bound must NOT be applied to timestamps)
  #   - finite non-negative duration_ms, never recomputed or compared for exact
  #     equality against end_ns - start_ns
  #   - end_ns must not precede start_ns
  #   - name is either empty (HTTP server span) or an allowlisted stage
  #   - nothing but the object shape is read, so no free-form string can pass
  if jq -s -e --arg stages "$stages" '
    def ns: type == "number" and isfinite and . >= 0 and floor == .;
    def dur: type == "number" and isfinite and . >= 0;
    def hex32: test("^([0-9a-f]{32})?$");
    def hex16: test("^([0-9a-f]{16})?$");
    def exact7: (keys | sort) == ["duration_ms","end_ns","name","parent_span_id","span_id","start_ns","trace_id"];
    ($stages | split(" ")) as $names
    | . as $records
    | if ($records | type) != "array" then error("raw is not a record array")
      elif any($records[];
        (type != "object")
        or (exact7 | not)
        or (.trace_id | hex32 | not)
        or (.span_id | hex16 | not)
        or (.parent_span_id | hex16 | not)
        or (.start_ns | ns | not)
        or (.end_ns | ns | not)
        or (.duration_ms | dur | not)
        or (.end_ns < .start_ns)
        or (.name as $n | (($n == "") or (($names | index($n)) != null)) | not)
      ) then error("record failed the shape gate")
      else $records end
    | ($names | map({ key: ., value: { count: 0, max_ms: 0 } }) | from_entries) as $base
    | (length) as $records_n
    | reduce (.[] | select(.name != "")) as $r ($base;
        .[$r.name].count += 1
        | .[$r.name].max_ms = ([.[$r.name].max_ms, $r.duration_ms] | max))
    | { records: $records_n, stages: . }
  ' "$raw" >"$stats"; then
    :
  else
    status=incomplete
    reason=raw_parse_failed
    stats=/dev/null
  fi
fi

outer=0
submit=0
if [ "$stats" != /dev/null ]; then
  outer=$(jq -r '.stages.storage_execute.count // 0' "$stats")
  submit=$(jq -r '.stages.storage_submit.count // 0' "$stats")
  if [ "$outer" -eq 0 ] || [ "$submit" -eq 0 ]; then
    status=incomplete
    reason=no_outer_or_submit_spans_observed
  fi
fi

# Criterion cross-reference is strictly optional and never inferred. An absent,
# malformed or incomplete comparison set stays null; it is never reported as 0
# failures. A complete set is expected to yield six boolean pass comparisons.
expected_comparisons=6
failed_comparisons=null
failed_comparisons_complete=false
protected_error_n=null
if [ -n "$criterion" ] && [ -s "$criterion" ]; then
  criterion_failed=$(jq -r '
    if type == "object"
       and (.performance.comparisons | type) == "array"
       and all(.performance.comparisons[]; type == "object" and (.pass | type) == "boolean")
    then ([.performance.comparisons[] | select(.pass == false)] | length | tostring)
    else "null" end
  ' "$criterion" 2>/dev/null) || criterion_failed=null
  case "$criterion_failed" in
 null) : ;;
  '' | *[!0-9]*) criterion_failed=null ;;
  *) criterion_n=$(jq -r 'if (.performance.comparisons | type) == "array" then (.performance.comparisons | length | tostring) else "null" end' "$criterion" 2>/dev/null) || criterion_n=null
     case "$criterion_n" in
     '' | *[!0-9]*) criterion_n=null ;;
     *) if [ "$criterion_n" -eq "$expected_comparisons" ]; then
          failed_comparisons=$criterion_failed
          failed_comparisons_complete=true
        fi ;;
     esac ;;
  esac
  # Actual criterion field is .protected.errors, an integer count. An absent or
  # non-integer value stays null rather than collapsing to zero.
  criterion_protected=$(jq -r '
    if type == "object" and (.protected.errors | type) == "number"
       and (.protected.errors | isfinite) and .protected.errors >= 0
       and (.protected.errors | floor) == .protected.errors
    then (.protected.errors | tostring) else "null" end
  ' "$criterion" 2>/dev/null) || criterion_protected=null
  case "$criterion_protected" in
  null) : ;;
  '' | *[!0-9]*) : ;;
  *) protected_error_n=$criterion_protected ;;
  esac
fi

if [ "$stats" != /dev/null ]; then
  stages_json=$(jq -c '.stages' "$stats")
  records_json=$(jq -c '.records' "$stats")
else
  stages_json='{}'
  records_json='0'
fi
[ ! -e "$out.stats" ] || rm "$out.stats"

jq -n \
  --arg schema 'isolation113-stage-aggregate/v1' \
  --arg status "$status" \
  --arg reason "$reason" \
  --argjson wrapper_rc "$wrapper_rc" \
  --argjson failed "$failed_comparisons" \
  --argjson failed_complete "$failed_comparisons_complete" \
  --argjson protected "$protected_error_n" \
  --argjson expected "$expected_comparisons" \
  --argjson stages "$stages_json" \
  --argjson records "$records_json" \
  '{
    schema: $schema,
    diagnostic_only: true,
    qualification_claim: false,
    campaign_exit_code: $wrapper_rc,
    diagnostic_status: $status,
    incomplete_reason: $reason,
    collection: {
      raw_records: $records,
      coverage_note: "positive storage_execute and storage_submit counts are observation evidence for this run only, not proof of universal export coverage"
    },
    criteria: {
      failed_relative_comparisons: $failed,
      failed_comparisons_complete: $failed_complete,
      expected_comparisons: $expected,
      protected_errors: $protected,
      note: "criterion values can indicate that a failing campaign was observed; they are NOT correlated with any individual recorded span"
    },
    stages: $stages,
    limitations: [
      "whole-capture aggregate only: recorded spans carry no driver, pod or phase attribution",
      "no arithmetic across enclosing and nested stages: storage_execute overlaps storage_submit, storage_status and storage_replay; no sum, total or residual is computed",
      "maxima are per-name maxima over different records, so a larger enclosing maximum does not localize time to any request or phase",
      "a zero count for a stage does not disprove a code path when collection is incomplete",
      "an extra 100m CPU / 64Mi memory collector Pod shared the 4-CPU runner; no absolute latency conclusion is drawn",
      "diagnostic only: not a qualification, performance, SLO or production claim",
      "raw traces, span identifiers and logs stay private to the run and are never uploaded"
    ]
  }' >"$out"
chmod 600 "$out"

if [ "$status" != observed ]; then
  echo "summarize: diagnostic INCOMPLETE ($reason); evidence must be read as unresolved" >&2
  exit 3
fi
if [ "$wrapper_rc" -ne 0 ]; then
  echo "summarize: campaign exit $wrapper_rc preserved; diagnostic observed; this is not a qualification pass" >&2
  exit 0
fi
exit 0
