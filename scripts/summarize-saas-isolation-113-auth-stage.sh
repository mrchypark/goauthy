#!/bin/sh
# Offline privacy-safe summarizer for the native authentication-stage histogram
# captured by scripts/e2e-kind-saas-isolation-113.sh. Reads the pre/post per-pod
# bounded collector records from a diagnostic directory and emits safe JSON on
# stdout. It never reads raw exposition text, logs, credentials, or container
# identifiers. Every collector record must match the exact bounded schema and
# the fixed eight-stage allowlist; otherwise the result is a fixed-reason
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
# level, a non-integer count, non-integer or non-monotonic buckets, a +Inf
# bucket that does not equal the count, an unknown stage, and an unknown
# top-level field. No free-form text is read from the record.
validator='
def is_int: type == "number" and isfinite and . >= 0 and (floor == .) and . <= 9007199254740991;
def is_num: type == "number" and isfinite and . >= 0 and . <= 9007199254740991;
def le_ok: . == "+Inf" or (test("^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$"));
def stage_names: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session"];
def valid_stage_value($v):
	($v | keys | sort) == ["buckets","count","sum"]
	and ($v.count | is_int)
	and ($v.sum | is_num)
	and (($v.buckets | type) == "array") and (($v.buckets | length) > 0)
	and ([$v.buckets[] | ((. | keys | sort) == ["le","value"]) and ((.le | type) == "string") and (.le | le_ok) and (.value | is_int)] | all)
	and ([$v.buckets[].le] | index("+Inf") != null)
	and (([$v.buckets[] | select(.le == "+Inf")] | length) == 1)
	and (([$v.buckets[] | select(.le == "+Inf")][0].value) == $v.count)
	and ([range(0; (($v.buckets | length) - 1)) as $i | ($v.buckets[$i].value <= $v.buckets[$i + 1].value)] | all);
(keys | sort) == ["captured_at_unix_ms","family","pod_index","schema_version","stages"]
and .schema_version == 1
and .family == "goauthy_auth_stage_duration_seconds"
and (.pod_index | is_int)
and (.captured_at_unix_ms | is_int)
and (.stages | type) == "object"
and ([.stages | keys[] | select(. as $k | (stage_names | index($k)) == null)] | length) == 0
and ([.stages | to_entries[] | valid_stage_value(.value)] | all)
and (.pod_index == $idx)
'

emit_unavailable() {
	jq -n --arg reason "$1" '{
		schema_version: 1,
		available: false,
		reason: $reason,
		family: "goauthy_auth_stage_duration_seconds",
		known_stages: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session"],
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
			if jq -e --argjson idx "$idx" "$validator" "$f" >/dev/null 2>&1; then
				jq -c '.' "$f" >>"$tmp/$phase.jsonl"
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

jq -n --slurpfile pre "$tmp/pre.json" --slurpfile post "$tmp/post.json" -f "$analyzer_jq"
