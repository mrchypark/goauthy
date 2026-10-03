#!/bin/sh
# Focused negative-control tests for scripts/summarize-e2e-kind-saas-isolation-113.sh
# Self-contained: builds synthetic diagnostic directories and checks the analyzer.
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
analyzer=$script_dir/summarize-e2e-kind-saas-isolation-113.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1" >&2; }
bad() { fail=$((fail + 1)); echo "not ok: $1" >&2; }

stamp=0
rec() {
	log=$1; phase=$2; route=$3; operation=$4; outcome=$5; status=$6; latency=$7
	stamp=$((stamp + 1))
	opfield=""; [ -n "$operation" ] && opfield=" operation=$operation"
	statusfield=""; [ -n "$status" ] && statusfield=" status=$status"
	schedfield=""; [ "$route" = "iam" ] && schedfield=" scheduled_unix_ms=$stamp"
	printf 'connection_use_grant_test.go:1: isolation113 phase=%s route=%s%s outcome=%s%s%s start_lag_ms=0.100 completion_latency_ms=%s\n' \
		"$phase" "$route" "$opfield" "$outcome" "$statusfield" "$schedfield" "$latency" >>"$log"
}

gen_driver_log() {
	dir=$1; idx=$2; base_ms=$3; mixed_ms=$4; rec_ms=$5
	log=$dir/driver-isolation113-driver-goauthy-$idx-0-test.log
	: >"$log"
	i=0; while [ $i -lt 6 ]; do rec "$log" baseline iam "" success "" "$base_ms"; i=$((i + 1)); done
	i=0; while [ $i -lt 6 ]; do rec "$log" mixed iam "" success "" "$mixed_ms"; i=$((i + 1)); done
	i=0; while [ $i -lt 4 ]; do rec "$log" recovery iam "" success "" "$rec_ms"; i=$((i + 1)); done
	rec "$log" mixed api-key "account" success "200" "$mixed_ms"
	i=0; while [ $i -lt 4 ]; do rec "$log" recovery api-key "account" success "200" "$rec_ms"; i=$((i + 1)); done
	i=0; while [ $i -lt 2 ]; do rec "$log" mixed api-key "slow-headers" http-error "502" 5000; i=$((i + 1)); done
	i=0; while [ $i -lt 2 ]; do rec "$log" mixed api-key "slow-body" http-error "502" 5000; i=$((i + 1)); done
	rec "$log" mixed api-key "failure" http-error "502" 5000
}

gen_samples() {
	dir=$1
	: >"$dir/container-samples.jsonl"
	for pod in 0 1 2; do
		for cont in goauthy sidecarfixture; do
			for t in 1 2; do
				jq -nc --arg ts "2026-01-01T00:00:0${t}Z" --argjson p "$pod" --arg c "$cont" \
					'{hostTimestampUTC:$ts,pod:("goauthy-"+($p|tostring)),container:$c,cpuUsageCoreNanoSeconds:1000,memoryWorkingSetBytes:1000000,memoryRSSBytes:900000,unavailable:[]}' \
					>>"$dir/container-samples.jsonl"
			done
		done
	done
}

gen_fixture() {
	dir=$1
	for i in 0 1 2; do
		jq -nc '{healthy:{started:5,completed:5,active:0},"slow-headers":{started:2,completed:2,active:0},"slow-body":{started:2,completed:2,active:0},fail:{started:1,completed:1,active:0}}' \
			>"$dir/fixture-metrics-$i.json"
	done
}

mkcase() {
	case_dir=$1; base_ms=$2; mixed_ms=$3; rec_ms=$4
	mkdir -p "$case_dir"
	stamp=0
	for idx in 0 1 2; do gen_driver_log "$case_dir" "$idx" "$base_ms" "$mixed_ms" "$rec_ms"; done
	gen_samples "$case_dir"
	gen_fixture "$case_dir"
}

sanitize_err() {
	sed -E 's/[0-9]{4,}/N/g; s/[0-9a-f]{16,}/H/g' "$1" 2>/dev/null | head -3
}

expect_status() {
	desc=$1; case_dir=$2; correctness=$3; performance=$4; overall=$5
	if out=$("$analyzer" "$case_dir" 2>"$tmp/err"); then
		if printf '%s' "$out" | jq -e --arg c "$correctness" --arg p "$performance" --arg o "$overall" \
			'.overall.correctness == $c and .overall.performance == $p and .overall.status == $o and .overall.issue_closure == false' >/dev/null; then
			ok "$desc"
		else
			bad "$desc (unexpected status)"
			printf '%s' "$out" | jq -c '{correctness:.overall.correctness,performance:.overall.performance,status:.overall.status,incomplete:(.denominators.incomplete|length),excess:(.denominators.excess|length),unexpected:(.denominators.unexpected_groups|length),protected_errors:.protected.errors}' >&2 || true
		fi
	else
		bad "$desc (analyzer exited nonzero)"
		sanitize_err "$tmp/err" >&2
	fi
}

expect_fail() {
	desc=$1; case_dir=$2
	if "$analyzer" "$case_dir" >/dev/null 2>"$tmp/err"; then
		bad "$desc (expected nonzero exit)"
	else
		ok "$desc"
	fi
}

# Base case: all protected succeed, latency within relation, resource ceiling missing.
base=$tmp/base
mkcase "$base" 100 110 90
expect_status "base case" "$base" "pass" "pass" "inconclusive"

# Group quantiles: baseline n=6 p95/p99=100, mixed n=6 p95/p99=110; no raw array.
if out=$("$analyzer" "$base" 2>"$tmp/err"); then
	if printf '%s' "$out" | jq -e '
		([.groups[] | select(.phase == "baseline" and .route == "iam")] | length) == 3 and
		([.groups[] | select(.phase == "baseline" and .route == "iam" and .n == 6 and .p95_ms == 100 and .p99_ms == 100)] | length) == 3 and
		([.groups[] | select(.phase == "mixed" and .route == "iam" and .n == 6 and .p95_ms == 110 and .p99_ms == 110)] | length) == 3 and
		([.groups[] | has("success_latencies_ms")] | any) == false
	' >/dev/null; then
		ok "group quantiles"
	else
		bad "group quantiles (unexpected values)"
	fi
else
	bad "group quantiles (analyzer exited nonzero)"
	sanitize_err "$tmp/err" >&2
fi

# Combined driver.log fallback (unattributed aggregate denominator).
fallback=$tmp/fallback
mkcase "$fallback" 100 110 90
cat "$fallback"/driver-isolation113-driver-*.log >"$fallback/driver.log"
rm "$fallback"/driver-isolation113-driver-*.log
expect_status "driver.log fallback" "$fallback" "pass" "pass" "inconclusive"

# Latency breach: mixed iam far above baseline relation.
breach=$tmp/breach
mkcase "$breach" 100 1000 90
expect_status "latency breach" "$breach" "pass" "fail" "fail"

# Protected error: one baseline iam record fails.
protected=$tmp/protected
mkcase "$protected" 100 110 90
f=$protected/driver-isolation113-driver-goauthy-0-0-test.log
awk 'BEGIN{done=0} { if(!done && /phase=baseline route=iam outcome=success/){ sub(/outcome=success/,"outcome=failed"); done=1 } print }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_status "protected error" "$protected" "fail" "pass" "fail"

# Missing denominator: drop one baseline iam record.
missing=$tmp/missing
mkcase "$missing" 100 110 90
f=$missing/driver-isolation113-driver-goauthy-1-0-test.log
awk 'BEGIN{n=0} /phase=baseline route=iam/{n++; if(n==1) next} {print}' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_status "missing denominator" "$missing" "fail" "pass" "fail"

# Negative latency: fail closed.
negative=$tmp/negative
mkcase "$negative" 100 110 90
f=$negative/driver-isolation113-driver-goauthy-2-0-test.log
awk 'BEGIN{done=0} { if(!done && /completion_latency_ms=100$/){ sub(/completion_latency_ms=100$/,"completion_latency_ms=-5"); done=1 } print }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_fail "negative latency" "$negative"

# Malformed observation: fail closed.
malformed=$tmp/malformed
mkcase "$malformed" 100 110 90
printf 'connection_use_grant_test.go:1: isolation113 phase=baseline route=iam outcome=success scheduled_unix_ms=bad start_lag_ms=0.1 completion_latency_ms=1.0\n' \
	>>"$malformed/driver-isolation113-driver-goauthy-0-0-test.log"
expect_fail "malformed observation" "$malformed"

# Non-finite latency: fail closed.
nonfinite=$tmp/nonfinite
mkcase "$nonfinite" 100 110 90
printf 'connection_use_grant_test.go:1: isolation113 phase=baseline route=iam outcome=success scheduled_unix_ms=999 start_lag_ms=0.1 completion_latency_ms=nan\n' \
	>>"$nonfinite/driver-isolation113-driver-goauthy-0-0-test.log"
expect_fail "non-finite latency" "$nonfinite"

# Duplicate observation record: fail closed.
dupobs=$tmp/dupobs
mkcase "$dupobs" 100 110 90
f=$dupobs/driver-isolation113-driver-goauthy-0-0-test.log
head -1 "$f" >>"$f"
expect_fail "duplicate observation" "$dupobs"

# Excess duplicated API count: denominator rejects the extra record.
excessapi=$tmp/excessapi
mkcase "$excessapi" 100 110 90
f=$excessapi/driver-isolation113-driver-goauthy-0-0-test.log
rg -m1 'operation=slow-headers' "$f" >>"$f"
expect_status "excess duplicated API count" "$excessapi" "fail" "pass" "fail"

# Legitimate same-valued distinct API observations remain accepted.
identical=$tmp/identical
mkcase "$identical" 100 110 90
if out=$("$analyzer" "$identical" 2>"$tmp/err"); then
	if printf '%s' "$out" | jq -e '.overall.status == "inconclusive" and ([.groups[] | select(.operation == "slow-headers") | .n] | add) == 6 and .duplicate_detection.iam_schedule_unique == true' >/dev/null; then
		ok "identical API observations accepted"
	else
		bad "identical API observations accepted (unexpected result)"
	fi
else
	bad "identical API observations accepted (analyzer exited nonzero)"
	sanitize_err "$tmp/err" >&2
fi

# Entire driver missing: fixed profile requires drivers 0,1,2.
nodriver=$tmp/nodriver
mkcase "$nodriver" 100 110 90
rm "$nodriver/driver-isolation113-driver-goauthy-2-0-test.log"
expect_status "entire driver missing" "$nodriver" "fail" "pass" "fail"

# Whole baseline missing: baseline denominators and comparisons stay structured.
nobase=$tmp/nobase
mkcase "$nobase" 100 110 90
for f in "$nobase"/driver-isolation113-driver-*.log; do
	awk '!/phase=baseline route=iam/' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
done
expect_status "whole baseline missing" "$nobase" "fail" "inconclusive" "fail"

# All baseline IAM failed: protected errors and null limits, no crash.
allfailed=$tmp/allfailed
mkcase "$allfailed" 100 110 90
for f in "$allfailed"/driver-isolation113-driver-*.log; do
	awk '{ if (/phase=baseline route=iam/) { sub(/outcome=success/, "outcome=failed") } print }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
done
expect_status "all baseline failed" "$allfailed" "fail" "inconclusive" "fail"

# Fixture non-drained: structured correctness fail, not a hard error.
nondrained=$tmp/nondrained
mkcase "$nondrained" 100 110 90
f=$nondrained/fixture-metrics-1.json
jq '.healthy.completed = 3 | .healthy.active = 2' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_status "fixture non-drained" "$nondrained" "fail" "pass" "fail"

# Wrong fault status: expected 502 fault rejected.
wrongfault=$tmp/wrongfault
mkcase "$wrongfault" 100 110 90
f=$wrongfault/driver-isolation113-driver-goauthy-0-0-test.log
awk 'BEGIN{done=0} { if (!done && /operation=failure/) { sub(/status=502/, "status=200"); done=1 } print }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_status "wrong fault status" "$wrongfault" "fail" "pass" "fail"

# Fixture missing route: raw fixture validation hard error.
fixroute=$tmp/fixroute
mkcase "$fixroute" 100 110 90
f=$fixroute/fixture-metrics-0.json
jq 'del(."slow-body")' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_fail "fixture missing route" "$fixroute"

# Duplicate sample: fail closed.
duplicate=$tmp/duplicate
mkcase "$duplicate" 100 110 90
head -1 "$duplicate/container-samples.jsonl" >>"$duplicate/container-samples.jsonl"
expect_fail "duplicate sample" "$duplicate"

# Missing fixture metrics: fail closed.
nofixture=$tmp/nofixture
mkcase "$nofixture" 100 110 90
rm "$nofixture"/fixture-metrics-*.json
expect_fail "missing fixture metrics" "$nofixture"

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
