#!/bin/sh
# Focused offline tests for the privacy-safe authentication-stage collector and
# capture-interval summarizer used by the issue #113 native per-pod metrics
# path. Self-contained: builds synthetic Prometheus exposition text, bounded
# collector records, and one direct --summarize integration control. It never
# runs a cluster, build, campaign, or dispatch.
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

stages="credential_lookup password_verify subject_revalidate interaction_consume session_rotate oauth_issue authorize_validate authorize_session"

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
# Collector: exact family, all eight fixed stages, privacy redaction.
# ---------------------------------------------------------------------------
all8_in=$tmp/all8.txt
: >"$all8_in"
n=1
for s in $stages; do
	hist "$s" "$n" "$((n + 1))" "0.0$n" "$((n + 1))" >>"$all8_in"
	n=$((n + 1))
done
printf '# HELP goauthy_http_requests_total nope\n' >>"$all8_in"
printf 'goauthy_http_requests_total{method="GET",route_class="authorize",status_class="2xx",tenant="SECRET_TENANT_CANARY"} 42\n' >>"$all8_in"
if out=$(collect 0 1700000000000 "$all8_in") &&
	printf '%s' "$out" | jq -e --argjson n 8 '
		.schema_version == 1
		and .family == "goauthy_auth_stage_duration_seconds"
		and .pod_index == 0
		and (.stages | length) == $n
		and .stages.credential_lookup.count == 2
		and .stages.authorize_validate.count == 8
		and .stages.authorize_session.count == 9
	' >/dev/null; then
	ok "collector extracts all eight fixed stages"
else
	bad "collector extracts all eight fixed stages"
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

# ---------------------------------------------------------------------------
# Summarizer: capture-interval deltas over a realistic eight-stage fixture.
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
	printf '%s' "$out" | jq -e --argjson n 8 '
		.available == true and .captured == true
		and (.known_stages | length) == $n
		and (.observed_stages | length) == $n
		and ([.pods[].pod_index] | sort) == [0, 1, 2]
		and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "credential_lookup") | .count_delta) == 9
		and ([.pods[] | select(.pod_index == 0)][0].stages[] | select(.stage == "authorize_session") | .count_delta) == 9
		and ([.totals[] | select(.stage == "credential_lookup")][0].count_delta) == 27
		and ([.pods[] | select(.pod_index == 0)][0].span_ms) == 1000
	' >/dev/null; then
	ok "summarizer reports eight-stage capture-interval deltas"
else
	bad "summarizer reports eight-stage capture-interval deltas"
	printf '%s\n' "$out" >&2 || true
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
schema_case() { # DIR MUTATOR
	dir=$1; mutator=$2
	rm -rf "$dir"; mkdir -p "$dir"
	for idx in 0 1 2; do
		collect "$idx" 1000 "$tmp/pre-src.txt" >"$dir/auth-stage-pre-$idx.json"
		collect "$idx" 2000 "$tmp/post-src.txt" >"$dir/auth-stage-post-$idx.json"
	done
	# shellcheck disable=SC2086
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

schema_case "$tmp/schema-missing" 'rm -f "$tmp/schema-missing/auth-stage-post-2.json"'
expect_unavailable "strict schema rejects a missing expected pod" "$tmp/schema-missing" capture-incomplete

schema_case "$tmp/schema-binding" 'cp "$tmp/schema-binding/auth-stage-post-1.json" "$tmp/schema-binding/auth-stage-post-2.json"'
expect_unavailable "strict schema rejects a mismatched native pod binding" "$tmp/schema-binding" capture-invalid

if out=$("$summarizer" "$tmp") && printf '%s' "$out" | jq -e '.available == false and .reason == "capture-missing"' >/dev/null; then
	ok "summarizer reports a missing capture as unavailable"
else
	bad "summarizer reports a missing capture as unavailable"
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
	rm -f "$harness/evidence"/auth-stage-*.json
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
# Direct integration: auth_stage must not remove the mandatory resource gates.
# ---------------------------------------------------------------------------
gen_evidence() { # DIR WITH_AUTH(0/1)
	dir=$1; with_auth=$2
	rm -rf "$dir"; mkdir -p "$dir"
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

integration=$tmp/integration
gen_evidence "$integration" 1
results=$tmp/integration-results
mkdir -p "$results"
if sh "$wrapper" --summarize "$integration" "$results" >/dev/null 2>"$tmp/integration.err"; then
	if jq -e '
		.available == true
		and (.series | length) == 6
		and .auth_stage.available == true
		and .auth_stage.captured == true
	' "$results/resource-summary.json" >/dev/null 2>&1 &&
		jq -e '.criterion_pass == true and .overall.correctness == "pass"' "$results/criterion.json" >/dev/null 2>&1; then
		ok "direct integration keeps resource gates with a validated auth summary"
	else
		bad "direct integration keeps resource gates with a validated auth summary"
	fi
else
	bad "direct integration keeps resource gates with a validated auth summary (summarize failed)"
	sed -n '1,3p' "$tmp/integration.err" >&2 || true
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
