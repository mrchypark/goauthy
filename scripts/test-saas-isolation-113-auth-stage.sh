#!/bin/sh
# Focused offline tests for issue #113's privacy-safe auth-stage and native
# object-store counter captures. Builds synthetic producer documents and
# bounded records, then exercises the existing --summarize path. It never runs
# a cluster, build, campaign, or dispatch.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
collector=$script_dir/collect-saas-isolation-113-auth-stage.sh
summarizer=$script_dir/summarize-saas-isolation-113-auth-stage.sh
wrapper=$script_dir/run-capacity-113-ci.sh
runner=$script_dir/e2e-kind-saas-isolation-113.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1" >&2; }
bad() { fail=$((fail + 1)); echo "not ok: $1" >&2; }

for tool in awk jq mktemp date cp grep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 1; }
done
[ -x "$collector" ] || { echo "collector not executable: $collector" >&2; exit 1; }
[ -x "$summarizer" ] || { echo "summarizer not executable: $summarizer" >&2; exit 1; }

stages="credential_lookup password_verify subject_revalidate interaction_consume session_rotate oauth_issue authorize_validate authorize_session policy_check policy_allow policy_account_lock policy_success"

# One complete histogram for a single stage with integer bucket/count values.
hist() {
	stage=$1; b1=$2; b2=$3; sum=$4; count=$5
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="%s",le="0.01"} %s\n' "$stage" "$b1"
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="%s",le="+Inf"} %s\n' "$stage" "$b2"
	printf 'goauthy_auth_stage_duration_seconds_sum{stage="%s"} %s\n' "$stage" "$sum"
	printf 'goauthy_auth_stage_duration_seconds_count{stage="%s"} %s\n' "$stage" "$count"
}

# Collect from a file (never a pipeline) so the collector exit status is exact.
collect() { "$collector" "$1" "$2" <"$3"; }

# ---------------------------------------------------------------------------
# Collector: exact family, all twelve fixed stages, privacy redaction.
# ---------------------------------------------------------------------------
all12_in=$tmp/all12.txt
: >"$all12_in"
n=1
for s in $stages; do
	hist "$s" "$n" "$((n + 1))" "0.0$n" "$((n + 1))" >>"$all12_in"
	n=$((n + 1))
done
printf '# HELP goauthy_http_requests_total nope\n' >>"$all12_in"
printf 'goauthy_http_requests_total{method="GET",route_class="authorize",status_class="2xx",tenant="SECRET_TENANT_CANARY"} 42\n' >>"$all12_in"
if out=$(collect 0 1700000000000 "$all12_in") &&
	printf '%s' "$out" | jq -e --argjson n 12 '
		.schema_version == 1
		and .family == "goauthy_auth_stage_duration_seconds"
		and .pod_index == 0
		and (.stages | length) == $n
		and .stages.credential_lookup.count == 2
		and .stages.authorize_validate.count == 8
		and .stages.authorize_session.count == 9
		and .stages.policy_check.count == 10
		and .stages.policy_allow.count == 11
		and .stages.policy_account_lock.count == 12
		and .stages.policy_success.count == 13
	' >/dev/null; then
	ok "collector extracts all twelve fixed stages"
else
	bad "collector extracts all twelve fixed stages"
fi

if ! printf '%s' "$out" | grep -q 'SECRET_TENANT_CANARY' &&
	! printf '%s' "$out" | grep -q 'goauthy_http_requests_total' &&
	! printf '%s' "$out" | grep -q 'tenant' &&
	! printf '%s' "$out" | grep -q 'route_class'; then
	ok "collector redacts foreign families and label values"
else
	bad "collector redacts foreign families and label values"
fi

# ---------------------------------------------------------------------------
# Collector fail-closed controls.
# ---------------------------------------------------------------------------
expect_collect_fail() {
	desc=$1; infile=$2
	if collect 0 1 "$infile" >/dev/null 2>&1; then
		bad "$desc"
	else
		ok "$desc"
	fi
}

printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} not-a-number\n' >"$tmp/bad-value.txt"
expect_collect_fail "collector rejects a non-numeric value" "$tmp/bad-value.txt"

printf 'goauthy_auth_stage_duration_seconds_total{stage="credential_lookup"} 1\n' >"$tmp/bad-suffix.txt"
expect_collect_fail "collector rejects an unexpected family suffix" "$tmp/bad-suffix.txt"

printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="soon"} 1\n' >"$tmp/bad-le.txt"
expect_collect_fail "collector rejects an invalid bucket bound" "$tmp/bad-le.txt"

printf 'goauthy_auth_stage_duration_seconds_count{stage="bogus"} 1\n' >"$tmp/unknown.txt"
expect_collect_fail "collector rejects an unknown stage label" "$tmp/unknown.txt"

printf 'goauthy_auth_stage_duration_seconds_count{stage="policy_check_PRIVATE_STAGE_CANARY"} 1\n' >"$tmp/unknown-canary.txt"
if out=$(collect 0 1 "$tmp/unknown-canary.txt" 2>&1); then
	bad "collector rejects an arbitrary policy-stage suffix without disclosure"
elif printf '%s' "$out" | grep -q 'PRIVATE_STAGE_CANARY'; then
	bad "collector rejects an arbitrary policy-stage suffix without disclosure"
else
	ok "collector rejects an arbitrary policy-stage suffix without disclosure"
fi

printf 'goauthy_auth_stage_duration_seconds_count{stage="consume_rotate_issue"} 1\n' >"$tmp/removed.txt"
expect_collect_fail "collector rejects the removed consume_rotate_issue label" "$tmp/removed.txt"

printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup",tenant="x"} 1\n' >"$tmp/extra-label.txt"
expect_collect_fail "collector rejects an arbitrary extra label" "$tmp/extra-label.txt"

{
	printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 1\n'
	printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 2\n'
} >"$tmp/dup.txt"
expect_collect_fail "collector rejects a duplicate series" "$tmp/dup.txt"

{
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="0.01"} 5\n'
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="+Inf"} 3\n'
	printf 'goauthy_auth_stage_duration_seconds_sum{stage="credential_lookup"} 0.1\n'
	printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 3\n'
} >"$tmp/nonmono.txt"
expect_collect_fail "collector rejects non-monotonic buckets" "$tmp/nonmono.txt"

{
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="0.01"} 1\n'
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="+Inf"} 2\n'
	printf 'goauthy_auth_stage_duration_seconds_sum{stage="credential_lookup"} 0.1\n'
	printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 2.5\n'
} >"$tmp/nonint.txt"
expect_collect_fail "collector rejects a non-integer count" "$tmp/nonint.txt"

: >"$tmp/empty.txt"
if out=$(collect 2 1 "$tmp/empty.txt") && printf '%s' "$out" | jq -e '.stages == {}' >/dev/null; then
	ok "collector accepts an absent family as an empty stage map"
else
	bad "collector accepts an absent family as an empty stage map"
fi

# An observed zero child is valid: a histogram child can publish zero between
# label creation and the first observation.
zero_in=$tmp/zero.txt
{
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="0.01"} 0\n'
	printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="+Inf"} 0\n'
	printf 'goauthy_auth_stage_duration_seconds_sum{stage="credential_lookup"} 0\n'
	printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 0\n'
} >"$zero_in"
if out=$(collect 0 1 "$zero_in") &&
	printf '%s' "$out" | jq -e '.stages.credential_lookup.count == 0 and .stages.credential_lookup.sum == 0 and ([.stages.credential_lookup.buckets[].value] | all(. == 0))' >/dev/null; then
	ok "collector accepts an observed zero histogram child"
else
	bad "collector accepts an observed zero histogram child"
fi

# ---------------------------------------------------------------------------
# Summarizer: capture-interval deltas over a realistic twelve-stage fixture.
# ---------------------------------------------------------------------------
build_pair() { # DIR PRE_BASE POST_BASE
	dir=$1; pre_base=$2; post_base=$3
	mkdir -p "$dir"
	: >"$tmp/pre-src.txt"; : >"$tmp/post-src.txt"
	n=1
	for s in $stages; do
		hist "$s" "$pre_base" "$((pre_base + 1))" "0.$n" "$((pre_base + 1))" >>"$tmp/pre-src.txt"
		hist "$s" "$post_base" "$((post_base + 5))" "1.$n" "$((post_base + 5))" >>"$tmp/post-src.txt"
		n=$((n + 1))
	done
	for idx in 0 1 2; do
		collect "$idx" 1000 "$tmp/pre-src.txt" >"$dir/auth-stage-pre-$idx.json"
		collect "$idx" 2000 "$tmp/post-src.txt" >"$dir/auth-stage-post-$idx.json"
	done
}

evidence=$tmp/evidence
build_pair "$evidence" 2 7
if out=$("$summarizer" "$evidence") &&
	printf '%s' "$out" | jq -e --argjson n 12 '
		.available == true and .captured == true
		and (.known_stages | length) == $n
		and (.observed_stages | length) == $n
		and ([.pods[].pod_index] | sort) == [0, 1, 2]
		and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .count_delta) == 9
		and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "authorize_session") | .count_delta) == 9
		and (([.pods[] | select(.pod_index == 0)][0].stages | map(select(.stage == "policy_check" or .stage == "policy_allow" or .stage == "policy_account_lock" or .stage == "policy_success"))) | (length == 4 and all(.[]; .count_delta == 9)))
		and ([.totals[] | select(.stage == "credential_lookup")][0].count_delta) == 27
		and ([.pods[] | select(.pod_index == 0)][0].span_ms) == 1000
	' >/dev/null; then
	ok "summarizer reports twelve-stage capture-interval deltas"
else
	bad "summarizer reports twelve-stage capture-interval deltas"
	printf '%s\n' "$out" >&2 || true
fi

# A valid pre-capture may have no histogram family before the first authorize
# request. It remains distinct from a failed scrape and yields the post-only
# stage delta from the same strict collector/summarizer path.
empty_pre=$tmp/empty-pre
mkdir -p "$empty_pre"
: >"$tmp/no-auth-stage-family.txt"
hist policy_check 0 1 0.1 1 >"$tmp/first-auth-stage-observation.txt"
for idx in 0 1 2; do
	collect "$idx" 1000 "$tmp/no-auth-stage-family.txt" >"$empty_pre/auth-stage-pre-$idx.json"
	collect "$idx" 2000 "$tmp/first-auth-stage-observation.txt" >"$empty_pre/auth-stage-post-$idx.json"
done
if empty_pre_out=$("$summarizer" "$empty_pre") && printf '%s' "$empty_pre_out" | jq -e '
	([.pods[].stages[] | select(.stage == "policy_check")]) as $policy |
	.available == true and .captured == true
	and ([.pods[].pod_index] | sort) == [0, 1, 2]
	and ($policy | length) == 3 and all($policy[]; .count_delta == 1 and .sum_delta == 0.1)
' >/dev/null; then
	ok "empty pre-capture and first post-capture observation produce a valid bounded delta"
else
	bad "empty pre-capture and first post-capture observation produce a valid bounded delta"
	printf '%s\n' "$empty_pre_out" >&2 || true
fi

if ! printf '%s' "$out" | jq -e '[paths | map(tostring) | join(".")] | any(test("percentile|p95|p99|average|mean|phase"))' >/dev/null; then
	ok "summarizer emits no percentile, average, or phase field"
else
	bad "summarizer emits no percentile, average, or phase field"
fi

# Count/sum reset.
reset=$tmp/reset
mkdir -p "$reset"
for idx in 0 1 2; do
	hist credential_lookup 5 9 0.9 9 >"$tmp/rpre.txt"
	hist credential_lookup 0 1 0.1 1 >"$tmp/rpost.txt"
	collect "$idx" 1000 "$tmp/rpre.txt" >"$reset/auth-stage-pre-$idx.json"
	collect "$idx" 2000 "$tmp/rpost.txt" >"$reset/auth-stage-post-$idx.json"
done
if out=$("$summarizer" "$reset") &&
	printf '%s' "$out" | jq -e '
		([.pods[].stages[] | .reset] | all(. == true))
		and ([.pods[].stages[] | .count_delta] | all(. == null))
		and ([.totals[] | .reset_any] | all(. == true))
	' >/dev/null; then
	ok "summarizer marks a count/sum reset and suppresses deltas"
else
	bad "summarizer marks a count/sum reset and suppresses deltas"
fi

# Bucket-only reset: count and sum rise but a bucket decreases; the bucket
# delta must be null, never a valid negative number.
breset=$tmp/breset
mkdir -p "$breset"
for idx in 0 1 2; do
	{
		printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="0.01"} 3\n'
		printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="+Inf"} 5\n'
		printf 'goauthy_auth_stage_duration_seconds_sum{stage="credential_lookup"} 0.5\n'
		printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 5\n'
	} >"$tmp/bpre.txt"
	{
		printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="0.01"} 1\n'
		printf 'goauthy_auth_stage_duration_seconds_bucket{stage="credential_lookup",le="+Inf"} 6\n'
		printf 'goauthy_auth_stage_duration_seconds_sum{stage="credential_lookup"} 0.6\n'
		printf 'goauthy_auth_stage_duration_seconds_count{stage="credential_lookup"} 6\n'
	} >"$tmp/bpost.txt"
	collect "$idx" 1000 "$tmp/bpre.txt" >"$breset/auth-stage-pre-$idx.json"
	collect "$idx" 2000 "$tmp/bpost.txt" >"$breset/auth-stage-post-$idx.json"
done
if out=$("$summarizer" "$breset") &&
	printf '%s' "$out" | jq -e '
		([.pods[].stages[] | select(.stage == "credential_lookup") | .reset] | all(. == true))
		and ([.pods[].stages[] | select(.stage == "credential_lookup") | .buckets[].delta] | all(. == null))
		and ([.pods[].stages[] | select(.stage == "credential_lookup") | .count_delta] | all(. == null))
	' >/dev/null; then
	ok "summarizer treats a bucket-only reset as a reset with no negative delta"
else
	bad "summarizer treats a bucket-only reset as a reset with no negative delta"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Strict schema controls on the safe summarizer input.
# ---------------------------------------------------------------------------
schema_case() { # DIR MUTATOR [SKIP_PHASE_IDX]
	dir=$1; mutator=$2; skip=${3:-}
	mkdir -p "$dir"
	for idx in 0 1 2; do
		for phase in pre post; do
			[ "$skip" = "$phase-$idx" ] && continue
			case "$phase" in
				pre) collect "$idx" 1000 "$tmp/pre-src.txt" >"$dir/auth-stage-pre-$idx.json" ;;
				post) collect "$idx" 2000 "$tmp/post-src.txt" >"$dir/auth-stage-post-$idx.json" ;;
			esac
		done
	done
	[ -n "$mutator" ] || return 0
	eval "$mutator"
}

expect_unavailable() {
	desc=$1; dir=$2; reason=$3
	if out=$("$summarizer" "$dir") && printf '%s' "$out" | jq -e --arg r "$reason" '.available == false and .reason == $r' >/dev/null; then
		ok "$desc"
	else
		bad "$desc"
		printf '%s\n' "$out" >&2 || true
	fi
}

schema_case "$tmp/schema-extra" 'jq ". + {extra: 1}" "$tmp/schema-extra/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/schema-extra/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects an extra top-level key" "$tmp/schema-extra" capture-invalid

schema_case "$tmp/schema-count" 'jq ".stages.credential_lookup.count = 2.5" "$tmp/schema-count/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/schema-count/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects a non-integer count" "$tmp/schema-count" capture-invalid

schema_case "$tmp/schema-bucket" 'jq ".stages.credential_lookup.buckets[0].value = 99" "$tmp/schema-bucket/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/schema-bucket/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects a decreasing bucket" "$tmp/schema-bucket" capture-invalid

schema_case "$tmp/schema-unknown" 'jq ".stages.bogus = .stages.credential_lookup" "$tmp/schema-unknown/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/schema-unknown/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects an unknown stage key" "$tmp/schema-unknown" capture-invalid

schema_case "$tmp/schema-ts" 'jq ".captured_at_unix_ms = 1000" "$tmp/schema-ts/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/schema-ts/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects an identical pre/post capture timestamp" "$tmp/schema-ts" capture-invalid

schema_case "$tmp/schema-missing" '' "post-2"
expect_unavailable "strict schema rejects a missing expected pod" "$tmp/schema-missing" capture-incomplete

schema_case "$tmp/schema-binding" 'cp "$tmp/schema-binding/auth-stage-post-1.json" "$tmp/schema-binding/auth-stage-post-2.json"'
expect_unavailable "strict schema rejects a mismatched native pod binding" "$tmp/schema-binding" capture-invalid

if out=$("$summarizer" "$tmp") && printf '%s' "$out" | jq -e '.available == false and .reason == "capture-missing"' >/dev/null; then
	ok "summarizer reports a missing capture as unavailable"
else
	bad "summarizer reports a missing capture as unavailable"
fi

# ---------------------------------------------------------------------------
# Bucket-bound and stage-set compatibility controls.
# ---------------------------------------------------------------------------
schema_case "$tmp/bounds-missing-pre" 'jq ".stages.credential_lookup.buckets = [.stages.credential_lookup.buckets[] | select(.le != \"0.01\")]" "$tmp/bounds-missing-pre/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-missing-pre/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects a missing pre bucket" "$tmp/bounds-missing-pre" capture-invalid

schema_case "$tmp/bounds-removed-post" 'jq ".stages.credential_lookup.buckets = [.stages.credential_lookup.buckets[] | select(.le != \"0.01\")]" "$tmp/bounds-removed-post/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-removed-post/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects a removed post bucket" "$tmp/bounds-removed-post" capture-invalid

schema_case "$tmp/bounds-duplicate" 'jq ".stages.credential_lookup.buckets += [.stages.credential_lookup.buckets[0]]" "$tmp/bounds-duplicate/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-duplicate/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects duplicate bucket bounds" "$tmp/bounds-duplicate" capture-invalid

schema_case "$tmp/bounds-alias" 'jq ".stages.credential_lookup.buckets[0].le = \"abc\"" "$tmp/bounds-alias/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-alias/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects a non-numeric bucket bound" "$tmp/bounds-alias" capture-invalid

schema_case "$tmp/bounds-equal-alias" 'jq ".stages.credential_lookup.buckets[0].le = \"1e-2\"" "$tmp/bounds-equal-alias/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-equal-alias/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects an aliased equal bucket bound" "$tmp/bounds-equal-alias" capture-invalid

schema_case "$tmp/bounds-unordered" 'jq ".stages.credential_lookup.buckets = [{le:\"0.05\",value:1},{le:\"0.01\",value:1},{le:\"+Inf\",value:2}]" "$tmp/bounds-unordered/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-unordered/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects numerically unordered bucket bounds" "$tmp/bounds-unordered" capture-invalid

schema_case "$tmp/bounds-count0" 'jq ".stages.credential_lookup.count = 0" "$tmp/bounds-count0/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/bounds-count0/auth-stage-pre-0.json"'
expect_unavailable "strict schema rejects an inconsistent zero count with nonzero buckets" "$tmp/bounds-count0" capture-invalid

# An actually observed zero child (count 0, sum 0, every bucket 0, compatible
# bounds) is valid and must compare to post normally, not be relabeled invalid.
schema_case "$tmp/zero-valid" 'jq ".stages.credential_lookup = {count:0,sum:0,buckets:[{le:\"0.01\",value:0},{le:\"+Inf\",value:0}]}" "$tmp/zero-valid/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/zero-valid/auth-stage-pre-0.json"'
if out=$("$summarizer" "$tmp/zero-valid") &&
	printf '%s' "$out" | jq -e '.available == true and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .count_pre) == 0 and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .reset) == false and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .count_delta) == ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .count_post)' >/dev/null; then
	ok "a valid zero pre stage yields a normal positive delta"
else
	bad "a valid zero pre stage yields a normal positive delta"
fi

schema_case "$tmp/stage-preonly" 'jq "del(.stages.oauth_issue)" "$tmp/stage-preonly/auth-stage-post-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/stage-preonly/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects a pre-only stage on one pod" "$tmp/stage-preonly" capture-invalid

# A wholly absent pre stage is the only legitimate zero (an unobserved child).
schema_case "$tmp/stage-postonly" 'jq "del(.stages.oauth_issue)" "$tmp/stage-postonly/auth-stage-pre-0.json" >"$tmp/e" && mv "$tmp/e" "$tmp/stage-postonly/auth-stage-pre-0.json"'
if out=$("$summarizer" "$tmp/stage-postonly") &&
	printf '%s' "$out" | jq -e '.available == true and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "oauth_issue") | .count_pre) == 0 and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "oauth_issue") | .count_delta) > 0 and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "oauth_issue") | .count_delta) == ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "oauth_issue") | .count_post)' >/dev/null; then
	ok "a wholly absent pre stage is permitted as an unobserved child"
else
	bad "a wholly absent pre stage is permitted as an unobserved child"
fi

# Multi-document and non-object capture files must be rejected whole, so a
# valid document can never smuggle an invalid document (or an unknown stage
# name) into the public safe JSON. Each pod is collected with its real pod
# index so a negative result can only come from the stream guard, never from a
# pod-binding mismatch.
valid_post=$tmp/valid-post.json
collect 0 2000 "$tmp/post-src.txt" >"$valid_post"
canary_doc=$tmp/canary.json
# A valid-shaped unknown stage inside .stages is the meaningful canary: it
# would survive if only .stages were copied and the unknown-stage check failed.
jq -c '.stages.CANARY_SECRET_STAGE = {count: 1, sum: 0.1, buckets: [{le: "0.01", value: 0}, {le: "+Inf", value: 1}]}' "$valid_post" >"$canary_doc"
multidoc_case() { # DIR BUILDER
	dir=$1; builder=$2
	mkdir -p "$dir"
	for idx in 0 1 2; do
		collect "$idx" 1000 "$tmp/pre-src.txt" >"$dir/auth-stage-pre-$idx.json"
		collect "$idx" 2000 "$tmp/post-src.txt" >"$dir/auth-stage-post-$idx.json"
	done
	eval "$builder"
}

multidoc_case "$tmp/md-base" ':'
if out=$("$summarizer" "$tmp/md-base") && printf '%s' "$out" | jq -e '.available == true and .captured == true and (.pods | length) == 3' >/dev/null; then
	ok "multi-document positive control is available"
else
	bad "multi-document positive control is available"
fi

multidoc_case "$tmp/md-invalid-first" '{ cat "$canary_doc"; cat "$valid_post"; } >"$tmp/md-invalid-first/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects an invalid document before a valid one" "$tmp/md-invalid-first" capture-invalid

multidoc_case "$tmp/md-invalid-last" '{ cat "$valid_post"; cat "$canary_doc"; } >"$tmp/md-invalid-last/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects a valid document before an invalid one" "$tmp/md-invalid-last" capture-invalid

multidoc_case "$tmp/md-two-valid" '{ cat "$valid_post"; cat "$valid_post"; } >"$tmp/md-two-valid/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects two valid documents" "$tmp/md-two-valid" capture-invalid

multidoc_case "$tmp/md-scalar" 'printf "5\n" >"$tmp/md-scalar/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects a scalar document" "$tmp/md-scalar" capture-invalid

multidoc_case "$tmp/md-array" 'printf "[1,2]\n" >"$tmp/md-array/auth-stage-post-0.json"'
expect_unavailable "strict schema rejects an array document" "$tmp/md-array" capture-invalid

if out=$("$summarizer" "$tmp/md-invalid-first") && ! printf '%s' "$out" | grep -q 'CANARY_SECRET_STAGE'; then
	ok "public safe output never carries an unknown stage name"
else
	bad "public safe output never carries an unknown stage name"
fi

# ---------------------------------------------------------------------------
# Mock integration: a pre-scrape failure must survive a passing driver wait.
# ---------------------------------------------------------------------------
harness=$tmp/harness
mkdir -p "$harness/bin" "$harness/evidence"
awk '/^collect_auth_stage_metrics\(\) \{/{f=1} f{print} f && /^\}$/{exit}' "$runner" >"$harness/collect-func.sh"
awk '/wait --for=condition=complete job\/isolation113-driver/{print; exit}' "$runner" >"$harness/wait-line.sh"
if [ -s "$harness/collect-func.sh" ] && [ -s "$harness/wait-line.sh" ]; then
	ok "sticky-failure harness extracts the real function and wait line"
else
	bad "sticky-failure harness extracts the real function and wait line"
fi
hist credential_lookup 1 2 0.02 2 >"$harness/metrics.txt"
cat >"$harness/bin/kubectl" <<'MOCK'
#!/bin/sh
for arg in "$@"; do
	if [ "$arg" = "wait" ]; then exit "${MOCK_WAIT_RC:-0}"; fi
done
exit "${MOCK_KUBECTL_RC:-1}"
MOCK
cat >"$harness/bin/curl" <<'MOCK'
#!/bin/sh
[ "${MOCK_CURL_OK:-0}" = 1 ] || exit 1
cat "$MOCK_METRICS_FILE"
MOCK
cat >"$harness/bin/seq" <<'MOCK'
#!/bin/sh
printf '1\n'
MOCK
cat >"$harness/bin/sleep" <<'MOCK'
#!/bin/sh
exit 0
MOCK
chmod +x "$harness/bin/kubectl" "$harness/bin/curl" "$harness/bin/seq" "$harness/bin/sleep"
cat >"$harness/run.sh" <<'RUN'
set -u
temp_dir=$HARNESS
ISOLATION113_EVIDENCE_DIR=$HARNESS/evidence
context=kind-test
namespace=goauthy
script_dir=$SCRIPT_DIR
metrics_token=dummy
job_status=0
. "$HARNESS/collect-func.sh"
collect_auth_stage_metrics pre
. "$HARNESS/wait-line.sh"
printf '%s\n' "$job_status"
RUN

run_harness() { # CURL_OK WAIT_RC
	if HARNESS=$harness SCRIPT_DIR=$script_dir MOCK_CURL_OK=$1 MOCK_WAIT_RC=$2 \
		MOCK_METRICS_FILE=$harness/metrics.txt PATH="$harness/bin:$PATH" \
		sh "$harness/run.sh" 2>/dev/null; then :; else :; fi
}

got=$(run_harness 0 0) || true
if [ "$got" = 1 ]; then
	ok "pre-scrape failure is not overwritten by a passing driver wait"
else
	bad "pre-scrape failure is not overwritten by a passing driver wait (got '$got')"
fi

got=$(run_harness 1 1) || true
if [ "$got" = 1 ]; then
	ok "a failing driver wait still records failure after a passing pre-scrape"
else
	bad "a failing driver wait still records failure after a passing pre-scrape (got '$got')"
fi

got=$(run_harness 1 0) || true
if [ "$got" = 0 ]; then
	ok "a passing pre-scrape and driver wait leave the run clean"
else
	bad "a passing pre-scrape and driver wait leave the run clean (got '$got')"
fi

# ---------------------------------------------------------------------------
# Execute the real pin/readiness/startup/configmap region with a mocked capture
# boundary. This checks delayed-pre slack, sticky failure, and each post path.
# ---------------------------------------------------------------------------
ready_line=$(grep -n '^kubectl --context .* wait --for=condition=Ready pod/goauthy-0' "$runner" | head -1 | cut -d: -f1)
pin_snapshot_line=$(grep -n '^node_image_pin_snapshot "\$GOAUTHY_IMAGE"' "$runner" | head -1 | cut -d: -f1)
pin_check_line=$(grep -n '^printf .*pod-image-pins.txt"$' "$runner" | head -1 | cut -d: -f1)
pre_line=$(grep -n '^collect_auth_stage_metrics pre$' "$runner" | head -1 | cut -d: -f1)
authorize_line=$(grep -n '^authorize_url=' "$runner" | head -1 | cut -d: -f1)
deadline_line=$(grep -n '^readiness_deadline=' "$runner" | head -1 | cut -d: -f1)
start_line=$(grep -n '^start_ms=' "$runner" | head -1 | cut -d: -f1)
cm_line=$(grep -n 'create configmap isolation113-run' "$runner" | head -1 | cut -d: -f1)
apply_line=$(grep -n '^[[:space:]]*kubectl --context .* apply -f deploy/kind-saas-isolation-113/driver-job.yaml$' "$runner" | head -1 | cut -d: -f1)
if [ -n "$ready_line" ] && [ -n "$pin_snapshot_line" ] && [ -n "$pin_check_line" ] && [ -n "$pre_line" ] &&
	[ -n "$authorize_line" ] && [ -n "$deadline_line" ] && [ -n "$start_line" ] && [ -n "$cm_line" ] && [ -n "$apply_line" ] &&
	[ "$ready_line" -lt "$pin_snapshot_line" ] && [ "$pin_snapshot_line" -lt "$pin_check_line" ] &&
	[ "$pin_check_line" -lt "$pre_line" ] && [ "$pre_line" -lt "$authorize_line" ] &&
	[ "$authorize_line" -lt "$deadline_line" ] && [ "$deadline_line" -lt "$start_line" ] &&
	[ "$start_line" -lt "$cm_line" ] && [ "$cm_line" -lt "$apply_line" ]; then
	ok "Ready and image pins precede pre-capture; authorize deadline and workload schedule follow it"
else
	bad "Ready and image pins precede pre-capture; authorize deadline and workload schedule follow it"
fi

gate=$tmp/gate
mkdir -p "$gate/bin" "$gate/tmp" "$gate/evidence"
awk '/^node_image_pin_snapshot "\$GOAUTHY_IMAGE"/{f=1} f && /create configmap isolation113-run/{print; exit} f{print}' "$runner" >"$gate/real-region.sh"
awk '/^collect_auth_stage_metrics post$/{print; exit}' "$runner" >"$gate/normal-post.sh"
if [ -s "$gate/real-region.sh" ] && [ "$(cat "$gate/normal-post.sh")" = 'collect_auth_stage_metrics post' ]; then
	ok "behavior harness extracts the real pin/readiness/configmap region and normal post call"
else
	bad "behavior harness extracts the real pin/readiness/configmap region and normal post call"
fi
cat >"$gate/bin/kubectl" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$MOCK_KUBECTL_LOG"
case " $* " in
	*" get pod goauthy-0 goauthy-1 goauthy-2 -o json "*) printf '{"items":[{"status":{"containerStatuses":[{"name":"goauthy","ready":true,"restartCount":0}]}},{"status":{"containerStatuses":[{"name":"goauthy","ready":true,"restartCount":0}]}},{"status":{"containerStatuses":[{"name":"goauthy","ready":true,"restartCount":0}]}}]}\n' ;;
	*" get pods -l app.kubernetes.io/name=goauthy "*) printf 'goauthy-0 Running true sha256:synthetic image\n' ;;
	*" port-forward "*) exit 0 ;;
	*" create configmap isolation113-run "*) printf 'configmap\n' ;;
	*" apply -f - "*) cat >/dev/null ;;
esac
exit 0
MOCK
cat >"$gate/bin/curl" <<'MOCK'
#!/bin/sh
n=$(cat "$MOCK_AUTH_COUNT"); n=$((n + 1)); printf '%s\n' "$n" >"$MOCK_AUTH_COUNT"
printf 'authorize:%s\n' "$n" >>"$MOCK_EVENTS"
if [ "$MOCK_AUTH_STATUS" != 200 ]; then touch "$MOCK_DEADLINE"; fi
printf '%s' "$MOCK_AUTH_STATUS"
MOCK
cat >"$gate/bin/date" <<'MOCK'
#!/bin/sh
if [ "${1:-}" = -u ]; then printf '2026-10-08T00:00:00Z\n'; exit 0; fi
if [ -f "$MOCK_DEADLINE" ]; then now=1700000060; else now=$(cat "$MOCK_NOW"); fi
printf '%s\n' "$now"
printf 'clock:%s\n' "$now" >>"$MOCK_EVENTS"
MOCK
cat >"$gate/bin/sleep" <<'MOCK'
#!/bin/sh
exit 0
MOCK
chmod +x "$gate/bin/kubectl" "$gate/bin/curl" "$gate/bin/date" "$gate/bin/sleep"
cat >"$gate/run.sh" <<'RUN'
set -eu
context=kind-test
namespace=goauthy
temp_dir=$HARNESS/tmp
job_status=0
baseline_iam_only=0
startup_only=$MOCK_STARTUP_ONLY
GOAUTHY_IMAGE=synthetic
candidate_config_digest=synthetic
candidate_manifest_digest=synthetic
prestart_spec=synthetic
ISOLATION113_EVIDENCE_DIR=$HARNESS/evidence
node_image_pin_snapshot() { printf '{"runtime_digests":["sha256:synthetic"]}\n' >"$3"; }
assert_candidate_pods() { :; }
collect_auth_stage_metrics() {
	printf 'capture:%s\n' "$1" >>"$MOCK_EVENTS"
	case "$1" in pre) printf 'pre\n' >>"$MOCK_CAPTURES" ;; post) printf 'post\n' >>"$MOCK_CAPTURES" ;; esac
	case "$1" in
		pre)
			if [ "$MOCK_PRE_DELAY" -eq 1 ]; then printf '1700000012\n' >"$MOCK_NOW"; fi
			[ "$MOCK_PRE_FAIL" -eq 0 ] || job_status=1
			;;
		post)
			if [ "$MOCK_POST_FAIL" -eq 1 ]; then job_status=1; return 1; fi
			;;
	esac
	return 0
}
capture_failure_state() { printf 'failure-state\n' >>"$MOCK_EVENTS"; }
. "$HARNESS/real-region.sh"
. "$HARNESS/normal-post.sh"
RUN

run_gate() {
	mode=$1; auth_status=$2; pre_fail=$3; fail_post=$4; delay_pre=$5
	printf '0\n' >"$gate/auth-count"
	: >"$gate/events"; : >"$gate/captures"; : >"$gate/kubectl.log"
	printf '1700000000\n' >"$gate/now"
	rm -f "$gate/deadline"
	set +e
	HARNESS=$gate MOCK_AUTH_COUNT=$gate/auth-count MOCK_EVENTS=$gate/events MOCK_CAPTURES=$gate/captures \
		MOCK_DEADLINE=$gate/deadline MOCK_KUBECTL_LOG=$gate/kubectl.log MOCK_NOW=$gate/now \
		MOCK_AUTH_STATUS=$auth_status MOCK_PRE_FAIL=$pre_fail MOCK_POST_FAIL=$fail_post MOCK_PRE_DELAY=$delay_pre \
		MOCK_STARTUP_ONLY=$mode PATH="$gate/bin:$PATH" sh "$gate/run.sh" >"$gate/stdout" 2>"$gate/stderr"
	rc=$?
	set -e
	return "$rc"
}

if run_gate 0 200 0 0 1; then
	if [ "$(cat "$gate/auth-count")" = 3 ] && [ "$(cat "$gate/captures")" = "$(printf 'pre\npost')" ]; then
		ok "normal gate captures pre/post once after three successful authorize probes"
	else
		bad "normal gate captures pre/post once after three successful authorize probes"
		cat "$gate/events" "$gate/captures" >&2
	fi
	if awk '/^capture:pre$/{p=NR} /^clock:/{if(p>0 && c==0)c=NR} /^authorize:1$/{a=NR} END{exit !(p>0 && c>p && a>c)}' "$gate/events"; then
		ok "pre-capture completes before the deadline clock and first authorize probe"
	else
		bad "pre-capture completes before the deadline clock and first authorize probe"
		cat "$gate/events" >&2
	fi
	if grep -F 'start-unix-ms=1700000042000' "$gate/kubectl.log" >/dev/null && grep -F 'apply -f -' "$gate/kubectl.log" >/dev/null; then
		ok "delayed pre preserves exactly 30 seconds of start/configmap slack"
	else
		bad "delayed pre preserves exactly 30 seconds of start/configmap slack"
		cat "$gate/kubectl.log" >&2
	fi
else
	bad "normal gate captures pre/post once after three successful authorize probes"
fi

if run_gate 1 200 1 0 0; then
	bad "pre-capture failure still runs authorize, remains sticky, and stops before startup/workload"
else
	gate_rc=$?
	if [ "$gate_rc" -eq 1 ] && [ "$(cat "$gate/auth-count")" = 3 ] && [ "$(cat "$gate/captures")" = pre ] &&
		grep -F 'failure-state' "$gate/events" >/dev/null &&
		! grep -F 'isolation113-run' "$gate/kubectl.log" >/dev/null; then
		ok "pre-capture failure still runs authorize, remains sticky, and stops before startup/workload"
	else
		bad "pre-capture failure still runs authorize, remains sticky, and stops before startup/workload"
	fi
fi

if run_gate 0 503 0 1 0; then
	bad "non-200 gate captures post once despite capture failure and preserves exit 1"
	else
	gate_rc=$?
	if [ "$gate_rc" -eq 1 ] && [ "$(cat "$gate/auth-count")" = 1 ] && [ "$(cat "$gate/captures")" = "$(printf 'pre\npost')" ] &&
		grep -F 'within the shared 60-second startup window' "$gate/stderr" >/dev/null; then
		ok "non-200 gate captures post once despite capture failure and preserves exit 1"
	else
		bad "non-200 gate captures post once despite capture failure and preserves exit 1"
	fi
fi

if run_gate 1 200 0 0 0; then
	if [ "$(cat "$gate/auth-count")" = 3 ] && [ "$(cat "$gate/captures")" = pre ] &&
		! grep -F 'isolation113-run' "$gate/kubectl.log" >/dev/null; then
		ok "startup-only still captures pre, passes functional readiness, and exits before workload scheduling"
	else
		bad "startup-only still captures pre, passes functional readiness, and exits before workload scheduling"
	fi
else
	bad "startup-only still captures pre, passes functional readiness, and exits before workload scheduling"
fi

# ---------------------------------------------------------------------------
# Direct integration: auth_stage must not remove the mandatory resource gates.
# ---------------------------------------------------------------------------
gen_evidence() { # DIR WITH_AUTH(0/1)
	dir=$1; with_auth=$2
	mkdir -p "$dir"
	stamp=0
	for idx in 0 1 2; do
		log=$dir/driver-isolation113-driver-$idx-abcde.log
		: >"$log"
		i=0; while [ $i -lt 6 ]; do stamp=$((stamp + 1)); printf 'connection_use_grant_test.go:1: isolation113 phase=baseline route=iam outcome=success scheduled_unix_ms=%s start_lag_ms=0.1 completion_latency_ms=100\n' "$stamp" >>"$log"; i=$((i + 1)); done
		i=0; while [ $i -lt 6 ]; do stamp=$((stamp + 1)); printf 'connection_use_grant_test.go:1: isolation113 phase=mixed route=iam outcome=success scheduled_unix_ms=%s start_lag_ms=0.1 completion_latency_ms=110\n' "$stamp" >>"$log"; i=$((i + 1)); done
		i=0; while [ $i -lt 4 ]; do stamp=$((stamp + 1)); printf 'connection_use_grant_test.go:1: isolation113 phase=recovery route=iam outcome=success scheduled_unix_ms=%s start_lag_ms=0.1 completion_latency_ms=90\n' "$stamp" >>"$log"; i=$((i + 1)); done
		printf 'connection_use_grant_test.go:1: isolation113 phase=mixed route=api-key operation=account outcome=success status=200 start_lag_ms=0.1 completion_latency_ms=110\n' >>"$log"
		i=0; while [ $i -lt 4 ]; do printf 'connection_use_grant_test.go:1: isolation113 phase=recovery route=api-key operation=account outcome=success status=200 start_lag_ms=0.1 completion_latency_ms=90\n' >>"$log"; i=$((i + 1)); done
		i=0; while [ $i -lt 2 ]; do printf 'connection_use_grant_test.go:1: isolation113 phase=mixed route=api-key operation=slow-headers outcome=http-error status=502 start_lag_ms=0.1 completion_latency_ms=5000\n' >>"$log"; i=$((i + 1)); done
		i=0; while [ $i -lt 2 ]; do printf 'connection_use_grant_test.go:1: isolation113 phase=mixed route=api-key operation=slow-body outcome=http-error status=502 start_lag_ms=0.1 completion_latency_ms=5000\n' >>"$log"; i=$((i + 1)); done
		printf 'connection_use_grant_test.go:1: isolation113 phase=mixed route=api-key operation=failure outcome=http-error status=502 start_lag_ms=0.1 completion_latency_ms=5000\n' >>"$log"
	done
	: >"$dir/container-samples.jsonl"
	for p in 0 1 2; do
		for c in goauthy sidecarfixture; do
			for t in 1 2; do
				jq -nc --arg ts "2026-01-01T00:00:0${t}Z" --argjson p "$p" --arg c "$c" '{hostTimestampUTC:$ts,pod:("goauthy-"+($p|tostring)),container:$c,cpuUsageCoreNanoSeconds:1000,memoryWorkingSetBytes:1000000,memoryRSSBytes:900000,unavailable:[]}' >>"$dir/container-samples.jsonl"
			done
		done
	done
	for i in 0 1 2; do
		jq -nc '{healthy:{started:5,completed:5,active:0},"slow-headers":{started:2,completed:2,active:0},"slow-body":{started:2,completed:2,active:0},fail:{started:1,completed:1,active:0}}' >"$dir/fixture-metrics-$i.json"
	done
	if [ "$with_auth" = 1 ]; then
		for idx in 0 1 2; do
			collect "$idx" 1000 "$tmp/pre-src.txt" >"$dir/auth-stage-pre-$idx.json"
			collect "$idx" 2000 "$tmp/post-src.txt" >"$dir/auth-stage-post-$idx.json"
		done
	fi
}

# Exercise the runner's actual fixed native-counter capture and wrapper
# projection with synthetic inputs. Identity values exist only in mock command
# output and shell comparisons; evidence contains only the fixed projection.
no_canary() {
	if grep -F "$1" "$2" >/dev/null; then
		return 1
	else
		grep_status=$?
	fi
	[ "$grep_status" -eq 1 ]
}
object_store_funcs=$tmp/object-store-functions.sh
awk '/^object_store_pod_identity\(\) \{/{copy=1} copy{print} copy && /^\}$/{functions++; if(functions==3) exit}' "$runner" >"$object_store_funcs"
if [ -s "$object_store_funcs" ]; then
	# shellcheck disable=SC1090
	. "$object_store_funcs"
	object_store_source_ready=true
else
	object_store_source_ready=false
	bad "runner exposes the source-executed native counter capture"
fi

write_native_stats() {
	value=$1 gauge=${2:-$1}
	jq -n --argjson n "$value" --argjson g "$gauge" '{
		replay_grouping_enabled:0, uploads:$n, gets:$n, lists:$n, heads:$n, deletes:$n, failures:$n,
		bytes_uploaded:$n, bytes_downloaded:$n, s3_http_requests:$n, s3_http_failures:$n,
		http_requests:$n, http_failures:$n, http_get_requests:$n, http_put_requests:$n,
		http_head_requests:$n, http_delete_requests:$n, http_other_requests:$n,
		condition_conflicts:$n, dedup_hits:$n, sdk_retries:$n, transport_failures:$n,
		http_4xx_unexpected:$n, http_5xx:$n, observed_request_identities:$n,
		observed_request_repeats:$n, request_grouping_unknown:$n,
		replay_tracker_capacity_misses:$n, replay_identity_capacity_misses:$n,
		replay_incomplete_operations:$n, replay_tracked_operations_active:$n, replay_open_readers:$g
	}' >"$tmp/native-stats.json"
}

mkdir -p "$tmp/native-bin" "$tmp/native-evidence"
cat >"$tmp/native-bin/kubectl" <<'MOCK'
#!/bin/sh
case " $* " in
	*" get pod/goauthy-"*)
		case " $* " in
			*" --request-timeout=5s "*) ;;
			*) printf 'missing bounded identity timeout\n' >"$MOCK_TIMEOUT_ASSERT"; exit 97 ;;
		esac
		;;
esac
pod_index=
for arg do
	case "$arg" in pod/goauthy-[012]) pod_index=${arg##*-} ;; esac
done
case " $* " in *" get pod/goauthy-"*) ;; *) exit 0 ;; esac
calls_file=$MOCK_ID_CALLS_DIR/$pod_index
count=0
if [ -r "$calls_file" ]; then count=$(cat "$calls_file"); fi
count=$((count + 1))
printf '%s\n' "$count" >"$calls_file"
case "$MOCK_ID_MODE" in
	unknown) exit 1 ;;
	timeout) exit 124 ;;
	within-change) uid=synthetic-uid-$count; restart=0 ;;
	replace) if [ "$count" -le 2 ]; then uid=synthetic-uid-a; else uid=synthetic-uid-b; fi; restart=0 ;;
	restart) uid=synthetic-uid-a; if [ "$count" -le 2 ]; then restart=0; else restart=1; fi ;;
	*) uid=synthetic-uid-a; restart=0 ;;
esac
jq -nc --arg uid "$uid" --argjson restart "$restart" '{metadata:{uid:$uid},status:{containerStatuses:[{name:"goauthy",restartCount:$restart}]}}'
MOCK
cat >"$tmp/native-bin/curl" <<'MOCK'
#!/bin/sh
route=auth
for arg do case "$arg" in */metrics/object-store) route=native ;; esac; done
if [ "$route" = native ]; then printf 'native\n' >>"$MOCK_NATIVE_CALLS"; fi
if [ "${MOCK_FETCH_FAIL:-0}" = 1 ]; then
	echo 'SYNTHETIC_RAW_ERROR_CANARY' >&2
	exit 22
fi
cat "$MOCK_STATS"
MOCK
chmod +x "$tmp/native-bin/kubectl" "$tmp/native-bin/curl"

native_capture() {
	phase=$1 index=$2 mode=$3 fetch_fail=$4 stats=$5
	MOCK_ID_CALLS_DIR=$tmp/native-id-calls MOCK_ID_MODE=$mode MOCK_FETCH_FAIL=$fetch_fail MOCK_STATS=$stats \
		MOCK_TIMEOUT_ASSERT=$tmp/missing-timeout-flag MOCK_NATIVE_CALLS=$tmp/native-curl-calls \
		PATH="$tmp/native-bin:$PATH" capture_object_store_snapshot "$phase" "$index" 19090
}

gen_native_snapshots() { # evidence pre-value post-value failure-mode
	dir=$1 pre_value=$2 post_value=$3 mode=$4
	ISOLATION113_EVIDENCE_DIR=$dir context=synthetic namespace=synthetic metrics_token=synthetic
	rm -f "$tmp/native-id-calls"/*
	for idx in 0 1 2; do
		write_native_stats "$pre_value" "$pre_value"
		native_capture pre "$idx" "$mode" 0 "$tmp/native-stats.json"
		write_native_stats "$post_value" 0
		native_capture post "$idx" "$mode" 0 "$tmp/native-stats.json"
	done
}

if [ "$object_store_source_ready" = true ]; then
	mkdir -p "$tmp/native-cases" "$tmp/native-id-calls" "$tmp/mock-auth-scripts"
	ISOLATION113_EVIDENCE_DIR=$tmp/native-cases context=synthetic namespace=synthetic metrics_token=synthetic
	: >"$tmp/native-curl-calls"
	: >"$tmp/mock-auth-scripts/collect-saas-isolation-113-auth-stage.sh"
	cat >"$tmp/mock-auth-scripts/collect-saas-isolation-113-auth-stage.sh" <<'MOCK'
#!/bin/sh
printf '{"stages":{"policy_check":{"count":1}}}\n'
MOCK
	chmod +x "$tmp/mock-auth-scripts/collect-saas-isolation-113-auth-stage.sh"
	rm -f "$tmp/native-id-calls"/*
	write_native_stats 0
	native_capture pre 0 stable 0 "$tmp/native-stats.json"
	if jq -e '.available == true and ([.counters[]] | all(. == 0))' "$tmp/native-cases/object-store-pre-0.json" >/dev/null; then
		if no_canary 'synthetic-uid-' "$tmp/native-cases/object-store-pre-0.json"; then
			ok "native capture accepts zero counters without persisting pod identity"
		else
			bad "native capture accepts zero counters without persisting pod identity"
		fi
	else
		bad "native capture accepts a valid all-zero 32-counter producer document"
	fi

	for invalid_case in missing extra bad-type overflow multiple; do
		rm -f "$tmp/native-id-calls"/*
		write_native_stats 1
		case "$invalid_case" in
			missing) jq 'del(.replay_open_readers)' "$tmp/native-stats.json" >"$tmp/native-invalid.json" ;;
			extra) jq '. + {unapproved_label:"SYNTHETIC_PRIVATE_CANARY"}' "$tmp/native-stats.json" >"$tmp/native-invalid.json" ;;
			bad-type) jq '.replay_open_readers="SYNTHETIC_PRIVATE_CANARY"' "$tmp/native-stats.json" >"$tmp/native-invalid.json" ;;
			overflow) jq '.http_requests=9007199254740992' "$tmp/native-stats.json" >"$tmp/native-invalid.json" ;;
			multiple) cat "$tmp/native-stats.json" "$tmp/native-stats.json" >"$tmp/native-invalid.json" ;;
		esac
		native_capture pre 0 stable 0 "$tmp/native-invalid.json"
		if jq -e '.available == false and .reason == "capture-invalid" and .counters == null' "$tmp/native-cases/object-store-pre-0.json" >/dev/null &&
			no_canary 'SYNTHETIC_PRIVATE_CANARY' "$tmp/native-cases/object-store-pre-0.json"; then
			ok "native capture rejects $invalid_case input without projecting raw fields"
		else
			bad "native capture rejects $invalid_case input without projecting raw fields"
		fi
	done

	write_native_stats 1
	native_capture pre 0 within-change 0 "$tmp/native-stats.json"
	if jq -e '.available == false and .reason == "identity-unstable" and .counters == null' "$tmp/native-cases/object-store-pre-0.json" >/dev/null; then
		ok "native capture rejects identity changes within one fetch"
	else
		bad "native capture rejects identity changes within one fetch"
	fi
	native_capture pre 0 unknown 0 "$tmp/native-stats.json"
	if jq -e '.available == false and .reason == "identity-unknown" and .counters == null' "$tmp/native-cases/object-store-pre-0.json" >/dev/null; then
		ok "native capture keeps unknown pod identity unavailable"
	else
		bad "native capture keeps unknown pod identity unavailable"
	fi
	native_capture pre 0 stable 1 "$tmp/native-stats.json"
	if jq -e '.available == false and .reason == "capture-unavailable" and .counters == null' "$tmp/native-cases/object-store-pre-0.json" >/dev/null; then
		ok "native endpoint failure remains unavailable"
	else
		bad "native endpoint failure remains unavailable"
	fi
	: >"$tmp/native-id-calls/0"
	: >"$tmp/native-id-calls/1"
	: >"$tmp/native-id-calls/2"
	: >"$tmp/native-curl-calls"
	: >"$tmp/missing-timeout-flag"
	rm "$tmp/missing-timeout-flag"
	script_dir=$tmp/mock-auth-scripts
	temp_dir=$tmp/native-auth-temp
	mkdir -p "$temp_dir" "$tmp/native-auth-evidence"
	ISOLATION113_EVIDENCE_DIR=$tmp/native-auth-evidence
	context=synthetic namespace=synthetic metrics_token=synthetic job_status=0 forward_pid=
	export MOCK_ID_CALLS_DIR=$tmp/native-id-calls MOCK_ID_MODE=timeout MOCK_STATS=$tmp/native-stats.json
	export MOCK_TIMEOUT_ASSERT=$tmp/missing-timeout-flag MOCK_NATIVE_CALLS=$tmp/native-curl-calls
	export MOCK_FETCH_FAIL=0 PATH=$tmp/native-bin:$PATH
	collect_auth_stage_metrics pre
	script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
	if [ "$job_status" -eq 0 ] && [ "$(wc -l <"$tmp/native-curl-calls" | tr -d ' ')" -eq 3 ] &&
		[ "$(wc -l <"$tmp/native-auth-evidence/auth-stage-pre-0.json" | tr -d ' ')" -eq 1 ] &&
		[ "$(wc -l <"$tmp/native-auth-evidence/auth-stage-pre-1.json" | tr -d ' ')" -eq 1 ] &&
		[ "$(wc -l <"$tmp/native-auth-evidence/auth-stage-pre-2.json" | tr -d ' ')" -eq 1 ] &&
		jq -s -e 'length == 3 and all(.[]; .available == false and .reason == "identity-unknown" and .counters == null)' \
			"$tmp/native-auth-evidence/object-store-pre-0.json" "$tmp/native-auth-evidence/object-store-pre-1.json" "$tmp/native-auth-evidence/object-store-pre-2.json" >/dev/null &&
		[ ! -s "$tmp/missing-timeout-flag" ]; then
		ok "timed-out identity lookups stay unavailable while actual pre auth capture continues"
	else
		bad "timed-out identity lookups stay unavailable while actual pre auth capture continues"
	fi
	if no_canary 'SYNTHETIC_RAW_ERROR_CANARY' "$tmp/native-cases/object-store-pre-0.json"; then
		ok "native capture never persists raw endpoint errors"
	else
		bad "native capture never persists raw endpoint errors"
	fi
fi

integration=$tmp/integration
gen_evidence "$integration" 1
if [ "$object_store_source_ready" = true ]; then
	gen_native_snapshots "$integration" 10 14 stable
fi
results=$tmp/integration-results
mkdir -p "$results"
if sh "$wrapper" --summarize "$integration" "$results" >/dev/null 2>"$tmp/integration.err"; then
	if jq -e '
		.available == true
		and (.series | length) == 6
		and .auth_stage.available == true
		and .auth_stage.captured == true
		and .object_store.available == true
		and (.object_store.pods | map(.pod_index)) == [0,1,2]
		and all(.object_store.pods[]; .available == true and .counters_delta.http_requests == 4 and .counters_delta.sdk_retries == 4 and ((.counters_delta | keys | sort) == ["condition_conflicts","dedup_hits","http_4xx_unexpected","http_5xx","http_failures","http_requests","sdk_retries","transport_failures"]))
	' "$results/resource-summary.json" >/dev/null 2>&1 &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$results/criterion.json" >/dev/null 2>&1 &&
		no_canary 'synthetic-uid-' "$results/resource-summary.json"; then
		ok "direct integration projects only eight deltas and ignores gauge drops"
	else
		bad "direct integration projects only eight deltas and ignores gauge drops"
	fi
else
	bad "direct integration projects only eight deltas and ignores gauge drops (summarize failed)"
	sed -n '1,3p' "$tmp/integration.err" >&2 || true
fi

if [ "$object_store_source_ready" = true ]; then
	gen_native_snapshots "$integration" 10 10 stable
	zero_results=$tmp/integration-zero-results
	mkdir -p "$zero_results"
	if sh "$wrapper" --summarize "$integration" "$zero_results" >/dev/null 2>"$tmp/integration-zero.err" &&
		jq -e '.object_store.available == true and (.object_store.pods | map(.pod_index)) == [0,1,2] and all(.object_store.pods[]; .available == true and ([.counters_delta[]] | all(. == 0)))' "$zero_results/resource-summary.json" >/dev/null; then
		ok "three correctly indexed unchanged captures produce observed zero deltas"
	else
		bad "three correctly indexed unchanged captures produce observed zero deltas"
	fi

	gen_native_snapshots "$integration" 10 9 stable
	reset_results=$tmp/integration-reset-results
	mkdir -p "$reset_results"
	if sh "$wrapper" --summarize "$integration" "$reset_results" >/dev/null 2>"$tmp/integration-reset.err" &&
		jq -e '
			def all_three_reset:
				.object_store.available == false
				and (.object_store.pods | map(.pod_index)) == [0,1,2]
				and all(.object_store.pods[]; .available == false and .reason == "counter-reset" and .counters_delta == null)
				and .available == true and (.series | length) == 6;
			. as $actual |
			($actual | all_three_reset)
			and (($actual | del(.object_store.pods[1]) | all_three_reset) | not)
			and (($actual | .object_store.pods[1].pod_index = 7 | all_three_reset) | not)
		' "$reset_results/resource-summary.json" >/dev/null &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$reset_results/criterion.json" >/dev/null; then
		ok "all three indexed counter resets are required; omitted/wrong pod controls fail"
	else
		bad "all three indexed counter resets are required; omitted/wrong pod controls fail"
	fi

	gen_native_snapshots "$integration" 10 14 stable
	mkdir -p "$tmp/per-file-records"
	for name in object-store-pre-0.json object-store-pre-1.json object-store-pre-2.json object-store-post-0.json object-store-post-1.json object-store-post-2.json; do
		cp "$integration/$name" "$tmp/per-file-records/$name"
	done
	printf ' \n' >"$integration/object-store-pre-0.json"
	cat "$tmp/per-file-records/object-store-pre-0.json" "$tmp/per-file-records/object-store-pre-1.json" >"$integration/object-store-pre-1.json"
	perfile_same_results=$tmp/integration-perfile-same-results
	mkdir -p "$perfile_same_results"
	if sh "$wrapper" --summarize "$integration" "$perfile_same_results" >/dev/null 2>"$tmp/integration-perfile-same.err" &&
		jq -e '.object_store.available == false and .object_store.reason == "capture-invalid" and (.object_store.pods | length) == 0 and .available == true and (.series | length) == 6' "$perfile_same_results/resource-summary.json" >/dev/null &&
		jq -n -e --slurpfile before "$results/criterion.json" --slurpfile after "$perfile_same_results/criterion.json" '$before[0] == $after[0]' >/dev/null; then
		ok "per-file validation rejects a blank pre capture compensated within pre files"
	else
		bad "per-file validation rejects a blank pre capture compensated within pre files"
		jq -c '.object_store | {available,reason,pod_indexes:(.pods | map(.pod_index))}' "$perfile_same_results/resource-summary.json" >&2 2>/dev/null || true
	fi

	printf ' \n' >"$integration/object-store-pre-0.json"
	cp "$tmp/per-file-records/object-store-pre-0.json" "$integration/object-store-pre-1.json"
	cp "$tmp/per-file-records/object-store-pre-1.json" "$integration/object-store-pre-2.json"
	cat "$tmp/per-file-records/object-store-pre-2.json" "$tmp/per-file-records/object-store-post-0.json" >"$integration/object-store-post-0.json"
	cp "$tmp/per-file-records/object-store-post-1.json" "$integration/object-store-post-1.json"
	cp "$tmp/per-file-records/object-store-post-2.json" "$integration/object-store-post-2.json"
	perfile_cross_results=$tmp/integration-perfile-cross-results
	mkdir -p "$perfile_cross_results"
	if sh "$wrapper" --summarize "$integration" "$perfile_cross_results" >/dev/null 2>"$tmp/integration-perfile-cross.err" &&
		jq -e '.object_store.available == false and .object_store.reason == "capture-invalid" and (.object_store.pods | length) == 0 and .available == true and (.series | length) == 6' "$perfile_cross_results/resource-summary.json" >/dev/null &&
		jq -n -e --slurpfile before "$results/criterion.json" --slurpfile after "$perfile_cross_results/criterion.json" '$before[0] == $after[0]' >/dev/null; then
		ok "per-file validation rejects a blank pre capture compensated across the pre/post boundary"
	else
		bad "per-file validation rejects a blank pre capture compensated across the pre/post boundary"
		jq -c '.object_store | {available,reason,pod_indexes:(.pods | map(.pod_index))}' "$perfile_cross_results/resource-summary.json" >&2 2>/dev/null || true
	fi

	gen_native_snapshots "$integration" 10 14 replace
	replace_results=$tmp/integration-replace-results
	mkdir -p "$replace_results"
	if sh "$wrapper" --summarize "$integration" "$replace_results" >/dev/null 2>"$tmp/integration-replace.err" &&
		jq -e '.object_store.available == false and .object_store.pods[0].reason == "identity-unstable"' "$replace_results/resource-summary.json" >/dev/null &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$replace_results/criterion.json" >/dev/null; then
		ok "pod replacement makes native deltas unavailable without changing criterion"
	else
		bad "pod replacement makes native deltas unavailable without changing criterion"
	fi
	gen_native_snapshots "$integration" 10 14 restart
	restart_results=$tmp/integration-restart-results
	mkdir -p "$restart_results"
	if sh "$wrapper" --summarize "$integration" "$restart_results" >/dev/null 2>"$tmp/integration-restart.err" &&
		jq -e '.object_store.available == false and .object_store.pods[0].reason == "identity-unstable"' "$restart_results/resource-summary.json" >/dev/null &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$restart_results/criterion.json" >/dev/null; then
		ok "container restart makes native deltas unavailable without changing criterion"
	else
		bad "container restart makes native deltas unavailable without changing criterion"
	fi
	rm -f "$integration/object-store-pre-2.json"
	missing_results=$tmp/integration-missing-results
	mkdir -p "$missing_results"
	if sh "$wrapper" --summarize "$integration" "$missing_results" >/dev/null 2>"$tmp/integration-missing.err" &&
		jq -e '.object_store.available == false and .object_store.reason == "capture-missing"' "$missing_results/resource-summary.json" >/dev/null &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$missing_results/criterion.json" >/dev/null; then
		ok "missing native capture is unavailable and leaves criterion unchanged"
	else
		bad "missing native capture is unavailable and leaves criterion unchanged"
	fi
	gen_native_snapshots "$integration" 10 14 stable
	jq '. + {unapproved_label:"SYNTHETIC_PRIVATE_CANARY"}' "$integration/object-store-post-1.json" >"$tmp/object-store-invalid.json"
	mv "$tmp/object-store-invalid.json" "$integration/object-store-post-1.json"
	invalid_results=$tmp/integration-invalid-results
	mkdir -p "$invalid_results"
	if sh "$wrapper" --summarize "$integration" "$invalid_results" >/dev/null 2>"$tmp/integration-invalid.err" &&
		jq -e '.object_store.available == false and .object_store.reason == "capture-invalid"' "$invalid_results/resource-summary.json" >/dev/null &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$invalid_results/criterion.json" >/dev/null &&
		no_canary 'SYNTHETIC_PRIVATE_CANARY' "$invalid_results/resource-summary.json"; then
		ok "invalid native snapshot is rejected without exposing fields or changing criterion"
	else
		bad "invalid native snapshot is rejected without exposing fields or changing criterion"
	fi
fi

integration_noauth=$tmp/integration-noauth
gen_evidence "$integration_noauth" 0
results_noauth=$tmp/integration-noauth-results
mkdir -p "$results_noauth"
if sh "$wrapper" --summarize "$integration_noauth" "$results_noauth" >/dev/null 2>"$tmp/integration-noauth.err"; then
	if jq -e '
		.available == true
		and (.series | length) == 6
		and .auth_stage.available == false
		and (.auth_stage.reason == "capture-missing")
	' "$results_noauth/resource-summary.json" >/dev/null 2>&1 &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$results_noauth/criterion.json" >/dev/null 2>&1; then
		ok "an unavailable auth summary does not remove the mandatory resource gates"
	else
		bad "an unavailable auth summary does not remove the mandatory resource gates"
	fi
else
	bad "an unavailable auth summary does not remove the mandatory resource gates (summarize failed)"
	sed -n '1,3p' "$tmp/integration-noauth.err" >&2 || true
fi

# ---------------------------------------------------------------------------
# Structural and wiring controls.
# ---------------------------------------------------------------------------
if grep -q 'fsGroup: 65532' "$script_dir/../deploy/k8s/statefulset.yaml" &&
	grep -q 'defaultMode":256' "$runner"; then
	ok "metrics token mount relies on the existing fsGroup for group read"
else
	bad "metrics token mount relies on the existing fsGroup for group read"
fi

if grep -F 'collect-saas-isolation-113-auth-stage.sh' "$runner" >/dev/null &&
	grep -F -- '--connect-timeout 1 --max-time 2' "$runner" >/dev/null &&
	grep -F 'auth-stage-$auth_phase-$auth_index.json' "$runner" >/dev/null; then
	ok "runner wires the bounded native auth-stage collection"
else
	bad "runner wires the bounded native auth-stage collection"
fi

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
