#!/bin/sh
# Offline privacy-safe summarizer for the native authentication-stage histogram
# captured by scripts/e2e-kind-saas-isolation-113.sh. Reads the pre/post per-pod
# bounded collector records from a diagnostic directory and emits safe JSON on
# stdout. It never reads raw exposition text, logs, credentials, or container
# identifiers. Every collector record must match the exact bounded schema and
# the fixed twelve-stage allowlist; otherwise the result is a fixed-reason
# unavailable marker. Only fixed reason enums are ever emitted.
set -eu
umask 077

usage() {
	echo "usage: $0 <diagnostic-directory>" >&2
	exit 2
}

[ "$#" -eq 1 ] || usage
dir=$1
case "$dir" in
	/*) ;;
	*) echo "diagnostic directory must be absolute: $dir" >&2; exit 1 ;;
esac
[ -d "$dir" ] || { echo "diagnostic directory not found: $dir" >&2; exit 1; }

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
analyzer_jq=$script_dir/summarize-saas-isolation-113-auth-stage.jq
[ -f "$analyzer_jq" ] || { echo "companion analyzer not found: $analyzer_jq" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: >"$tmp/pre.jsonl"
: >"$tmp/post.jsonl"

# Exact bounded schema for one collector record. Rejects extra keys at every
# level, a non-integer count, non-integer, duplicate, non-finite, or
# non-increasing bucket bounds, a +Inf bucket that does not equal the count, an
# unknown stage, and an unknown top-level field. An actually observed zero
# child (count 0, sum 0, every bucket 0) is valid: a histogram child can
# publish zero between label creation and the first observation. No free-form
# text is read from the record.
validator='
def is_int: type == "number" and isfinite and . >= 0 and (floor == .) and . <= 9007199254740991;
def is_num: type == "number" and isfinite and . >= 0 and . <= 9007199254740991;
def le_key: if . == "+Inf" then 1e300 else (. | tonumber) end;
def le_finite: . == "+Inf" or ((type == "string") and (test("^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$")) and ((. | tonumber) | isfinite) and ((. | tonumber) >= 0));
def stage_names: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session","policy_check","policy_allow","policy_account_lock","policy_success"];
def valid_canceled($values):
	($values | type) == "object"
	and ([$values | keys[] | select(. as $k | (stage_names | index($k)) == null)] | length) == 0
	and ([$values[] | is_int] | all);
def valid_stage_value($v):
	($v | keys | sort) == ["buckets","count","sum"]
	and ($v.count | is_int)
	and ($v.sum | is_num)
	and (($v.buckets | type) == "array") and (($v.buckets | length) > 0)
	and ([$v.buckets[] | ((. | keys | sort) == ["le","value"]) and ((.le | type) == "string") and (.le | le_finite) and (.value | is_int)] | all)
	and (([$v.buckets[] | select(.le == "+Inf")] | length) == 1)
	and ($v.buckets[-1].le == "+Inf")
	and (([$v.buckets[] | select(.le == "+Inf")][0].value) == $v.count)
	and ([range(0; (($v.buckets | length) - 1)) as $i | ($v.buckets[$i].value <= $v.buckets[$i + 1].value)] | all)
	and ([range(0; (($v.buckets | length) - 1)) as $i | (($v.buckets[$i].le | le_key) < ($v.buckets[$i + 1].le | le_key))] | all);
((.schema_version == 1 and (keys | sort) == ["captured_at_unix_ms","family","pod_index","schema_version","stages"])
	or (.schema_version == 2 and (keys | sort) == ["canceled_completions","captured_at_unix_ms","family","pod_index","schema_version","stages"] and (.canceled_completions | valid_canceled(.))))
and .family == "goauthy_auth_stage_duration_seconds"
and (.pod_index | is_int)
and (.captured_at_unix_ms | is_int)
and (.stages | type) == "object"
and ([.stages | keys[] | select(. as $k | (stage_names | index($k)) == null)] | length) == 0
and ([.stages | to_entries[] | valid_stage_value(.value)] | all)
and (.pod_index == $idx)
'

# Archive snapshots are optional diagnostic sidecars. Re-run the collector's
# fixed-schema validator so hand-edited, partial, or multi-document files can
# never be copied into the resource summary. Their absence does not invalidate
# the independent auth-stage capture.
archive_collector=$script_dir/collect-saas-isolation-113-auth-stage.sh
: >"$tmp/archive-pre.jsonl"
: >"$tmp/archive-post.jsonl"
archive_present=0
archive_invalid=false
for idx in 0 1 2; do
	for phase in pre post; do
		f=$dir/archive-duration-$phase-$idx.json
		if [ -f "$f" ]; then
			if "$archive_collector" --archive-json <"$f" >"$tmp/archive-record.json" 2>/dev/null; then
				cat "$tmp/archive-record.json" >>"$tmp/archive-$phase.jsonl"
				archive_present=$((archive_present + 1))
			else
				printf 'null\n' >>"$tmp/archive-$phase.jsonl"
				archive_invalid=true
			fi
		else
			printf 'null\n' >>"$tmp/archive-$phase.jsonl"
		fi
	done
done
jq -s '.' "$tmp/archive-pre.jsonl" >"$tmp/archive-pre.json"
jq -s '.' "$tmp/archive-post.jsonl" >"$tmp/archive-post.json"
if [ "$archive_invalid" = true ]; then
	archive_reason=capture-invalid
elif [ "$archive_present" -eq 0 ]; then
	archive_reason=capture-missing
elif [ "$archive_present" -ne 6 ]; then
	archive_reason=capture-incomplete
else
	archive_reason=
fi

cat >"$tmp/archive-summary.jq" <<'JQ'
def stage_names: ["publication_admission","archive_load","extent_build_upload","head_publish","publication_release"];
def stage_summary($name; $before_doc; $after_doc; $capture_reason):
	($before_doc.stages[$name] // null) as $before |
	($after_doc.stages[$name] // null) as $after |
	($before != null and $before.available == true and $after != null and $after.available == true) as $valid |
	($valid and ($after.count < $before.count or $after.duration_ns_sum < $before.duration_ns_sum)) as $reset |
	{
		stage: $name,
		available: ($valid and ($reset | not)),
		reason: (if $reset then "counter-reset" elif $valid then null elif $capture_reason != "" then $capture_reason else "source-unavailable" end),
		count_pre: (if $before != null and $before.available then $before.count else null end),
		count_post: (if $after != null and $after.available then $after.count else null end),
		count_delta: (if $valid and ($reset | not) then $after.count - $before.count else null end),
		duration_ns_sum_pre: (if $before != null and $before.available then $before.duration_ns_sum else null end),
		duration_ns_sum_post: (if $after != null and $after.available then $after.duration_ns_sum else null end),
		duration_ns_sum_delta: (if $valid and ($reset | not) then $after.duration_ns_sum - $before.duration_ns_sum else null end),
		reset: $reset
	};
($pre[0]) as $before_all |
($post[0]) as $after_all |
{
	schema_version: 1,
	available: ($capture_reason == ""),
	reason: (if $capture_reason == "" then null else $capture_reason end),
	pods: [range(0; 3) as $idx |
		($before_all[$idx] // null) as $before_doc |
		($after_all[$idx] // null) as $after_doc |
		{
			pod_index: $idx,
			stages: [stage_names[] as $name | stage_summary($name; $before_doc; $after_doc; $capture_reason)]
		}
	],
	notes: "Per-process cumulative durations between two captures; the runner must verify unchanged process identity. Stage intervals can nest and must not be summed. Deltas are not per-request attribution or proof of cause."
}
JQ
jq -n --slurpfile pre "$tmp/archive-pre.json" --slurpfile post "$tmp/archive-post.json" \
	--arg capture_reason "$archive_reason" -f "$tmp/archive-summary.jq" >"$tmp/archive-summary.json"

emit_unavailable() {
	jq -n --arg reason "$1" --slurpfile archive "$tmp/archive-summary.json" '{
		schema_version: 1,
		available: false,
		reason: $reason,
		archive_duration: $archive[0],
		family: "goauthy_auth_stage_duration_seconds",
		canceled_completions: {
			available: false,
			reason: $reason,
			source_continuity: "unknown",
			pods: []
		},
		known_stages: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session","policy_check","policy_allow","policy_account_lock","policy_success"],
		observed_stages: [],
		pods: [],
		totals: []
	}'
}

invalid=false
complete=true
for idx in 0 1 2; do
	for phase in pre post; do
		f=$dir/auth-stage-$phase-$idx.json
		if [ -f "$f" ]; then
			# Each capture file must hold exactly one JSON object that passes
			# the whole strict schema. This rejects a valid document hiding
			# behind an invalid one, a valid one followed by an invalid one,
			# two valid documents, and scalar or array documents, and it
			# appends only the single canonical validated object.
			if jq -s -c --argjson idx "$idx" 'if ((length == 1) and (.[0] | ('"$validator"'))) then .[0] else error("invalid auth stage capture") end' "$f" >"$tmp/canonical.json" 2>/dev/null; then
				cat "$tmp/canonical.json" >>"$tmp/$phase.jsonl"
			else
				invalid=true
			fi
		else
			complete=false
		fi
	done
done

if [ "$invalid" = true ]; then
	emit_unavailable capture-invalid
	exit 0
fi
if [ "$complete" != true ]; then
	if [ -s "$tmp/pre.jsonl" ] || [ -s "$tmp/post.jsonl" ]; then
		emit_unavailable capture-incomplete
	else
		emit_unavailable capture-missing
	fi
	exit 0
fi

jq -s '.' "$tmp/pre.jsonl" >"$tmp/pre.json"
jq -s '.' "$tmp/post.jsonl" >"$tmp/post.json"

# Reject identical pre/post capture timestamps: a zero-length interval cannot
# yield a meaningful capture-interval delta.
if ! jq -n --slurpfile pre "$tmp/pre.json" --slurpfile post "$tmp/post.json" -e '
	[ $post[0][] as $p | ($pre[0][] | select(.pod_index == $p.pod_index)) as $q |
		($p.captured_at_unix_ms != $q.captured_at_unix_ms) ] | all
' >/dev/null; then
	emit_unavailable capture-invalid
	exit 0
fi

# Fail closed on a pre-only stage (a stage present in pre but absent in post)
# and on incompatible bucket bounds between pre and post for a shared stage.
# Only a wholly absent pre stage is synthesized as zero; an actually observed
# zero child (count 0, sum 0, every bucket 0) is valid and is compared
# normally.
if ! jq -n --slurpfile pre "$tmp/pre.json" --slurpfile post "$tmp/post.json" -e '
	def le_set($s): ([$s.buckets[].le] | sort);
	[ $pre[0][] as $q | ($post[0][] | select(.pod_index == $q.pod_index)) as $p |
		([$q.stages | keys[] | select(. as $k | ($p.stages | has($k)) | not)] | length) == 0
		and
		([$p.stages | keys[] | select(. as $k | ($q.stages | has($k)) and
			(le_set($p.stages[$k]) != le_set($q.stages[$k])))] | length) == 0
	] | all
' >/dev/null; then
	emit_unavailable capture-invalid
	exit 0
fi

jq -n --slurpfile pre "$tmp/pre.json" --slurpfile post "$tmp/post.json" -f "$analyzer_jq" >"$tmp/auth-summary.json"
jq --slurpfile archive "$tmp/archive-summary.json" '. + {archive_duration:$archive[0]}' "$tmp/auth-summary.json"
