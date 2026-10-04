#!/bin/sh
# Focused offline tests for scripts/run-capacity-113-ci.sh --summarize
# report aggregation and missing-baseline failure handling. It never runs a
# campaign, Kind cluster, build, or dispatch.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
wrapper=$script_dir/run-capacity-113-ci.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

pass=0
fail=0
case_n=0
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
	log=$dir/driver-isolation113-driver-$idx-abcde.log
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

new_results() {
	case_n=$((case_n + 1))
	results=$tmp/results-$case_n
	mkdir -p "$results"
	printf '%s' "$results"
}

expect_summary() {
	desc=$1; case_dir=$2; want_correctness=$3; want_performance=$4; want_pass=$5; want_resource=$6
	results=$(new_results)
	if "$wrapper" --summarize "$case_dir" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
	if [ "$want_correctness" = fail ] && [ "$rc" -eq 0 ]; then
		bad "$desc (expected nonzero exit for correctness fail)"
		return
	fi
	if [ "$want_correctness" = pass ] && [ "$rc" -ne 0 ]; then
		bad "$desc (unexpected nonzero exit)"
		sed -n '1,3p' "$tmp/err" >&2 || true
		return
	fi
	if ! jq -e --arg c "$want_correctness" --arg p "$want_performance" --arg pass "$want_pass" \
		'.overall.correctness == $c and .overall.performance == $p and .criterion_pass == ($pass == "true")' \
		"$results/criterion.json" >/dev/null 2>&1; then
		bad "$desc (unexpected criterion)"
		jq -c '{correctness:.overall.correctness,performance:.overall.performance,criterion_pass}' "$results/criterion.json" >&2 || true
		return
	fi
	if ! jq -e --arg res "$want_resource" '.available == ($res == "true")' "$results/resource-summary.json" >/dev/null 2>&1; then
		bad "$desc (unexpected resource marker)"
		return
	fi
	for f in pins.json runner-environment.json report.md resource-summary.json; do
		[ -s "$results/$f" ] || { bad "$desc (missing $f)"; return; }
	done
	ok "$desc"
}

base=$tmp/base
mkcase "$base" 100 110 90
expect_summary "positive" "$base" pass pass true true

explicit=$tmp/explicit
mkcase "$explicit" 100 110 90
for idx in 0 1 2; do
	mv "$explicit/driver-isolation113-driver-$idx-abcde.log" "$explicit/driver-isolation113-driver-goauthy-$idx-0-test.log"
done
expect_summary "explicit goauthy names" "$explicit" pass pass true true

missing=$tmp/missing
mkcase "$missing" 100 110 90
f=$missing/driver-isolation113-driver-1-abcde.log
awk 'BEGIN{n=0} /phase=baseline route=iam/{n++; if(n==1) next} {print}' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_summary "missing baseline" "$missing" fail pass false true

protected=$tmp/protected
mkcase "$protected" 100 110 90
f=$protected/driver-isolation113-driver-0-abcde.log
awk 'BEGIN{done=0} { if(!done && /phase=baseline route=iam outcome=success/){ sub(/outcome=success/,"outcome=failed"); done=1 } print }' "$f" >"$f.tmp" && mv "$f.tmp" "$f"
expect_summary "admitted error" "$protected" fail pass false true

breach=$tmp/breach
mkcase "$breach" 100 1000 90
expect_summary "latency breach" "$breach" pass fail false true

noanalyzer=$tmp/noanalyzer
mkcase "$noanalyzer" 100 110 90
rm "$noanalyzer"/fixture-metrics-*.json
results=$(new_results)
if "$wrapper" --summarize "$noanalyzer" "$results" >"$tmp/out" 2>"$tmp/err"; then
	bad "analyzer failure (expected nonzero exit)"
else
	if jq -e '.overall.correctness == "fail" and .criterion_pass == false' "$results/criterion.json" >/dev/null 2>&1 &&
		jq -e '.available == false' "$results/resource-summary.json" >/dev/null 2>&1 &&
		[ -s "$results/pins.json" ] && [ -s "$results/runner-environment.json" ] && [ -s "$results/report.md" ] && [ -s "$results/resource-summary.json" ]; then
		ok "analyzer failure"
	else
		bad "analyzer failure (unexpected error report)"
	fi
fi

# Baseline multi-document transform regression (offline; no kubectl/Kind).
eval "$(sed -n "/^baseline_normalize_jq=/,/^'\$/p;/^baseline_patch_jq=/,/^'\$/p;/^baseline_validate_jq=/,/^'\$/p" "$wrapper")"
bt_img="ghcr.io/mrchypark/goauthy@sha256:21c941913d6ae6333d59fa5da4dfc4d61ab2ecafa0eb9299ade01815d486c499"
bt_ss='{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"goauthy","namespace":"goauthy"},"spec":{"replicas":3,"template":{"spec":{"containers":[{"name":"goauthy","image":"old@sha256:aaa"}]}}}}'
bt_cm='{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"goauthy"},"data":{"k":"v"}}'
bt_svc='{"apiVersion":"v1","kind":"Service","metadata":{"name":"svc","namespace":"goauthy"},"spec":{"ports":[{"port":80}]}}'
bt_ns='{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"goauthy"}}'
bt_run() {
	raw=$1
	jq -s "$baseline_normalize_jq" "$raw" >"$tmp/bt-list.json" &&
	jq --arg image "$bt_img" "$baseline_patch_jq" "$tmp/bt-list.json" >"$tmp/bt-patched.json" &&
	jq -e --arg image "$bt_img" "$baseline_validate_jq" "$tmp/bt-patched.json" >/dev/null
}
bt_case=$tmp/bt
mkdir -p "$bt_case"
printf '%s\n' "$bt_ss" "$bt_cm" "$bt_svc" "$bt_ns" >"$bt_case/valid.json"
if bt_run "$bt_case/valid.json"; then
	if jq -e --arg img "$bt_img" '
		([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy")] | length) == 1
		and ([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy" and .spec.replicas == 0)] | length) == 1
		and ([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[] | select(.name == "goauthy" and .image == $img)] | length) == 1
		and ([.items[] | select(.kind == "ConfigMap" and .metadata.name == "cm")] | length) == 1
		and ([.items[] | select(.kind == "Service" and .metadata.name == "svc")] | length) == 1
		and ([.items[] | select(.kind == "Namespace" and .metadata.name == "goauthy")] | length) == 1
	' "$tmp/bt-patched.json" >/dev/null; then
		ok "baseline transform valid"
	else
		bad "baseline transform valid (unexpected patch)"
	fi
else
	bad "baseline transform valid (expected pass)"
fi

printf '%s\n' "$bt_cm" "$bt_svc" "$bt_ns" >"$bt_case/missing.json"
if bt_run "$bt_case/missing.json"; then bad "baseline missing target (expected reject)"; else ok "baseline missing target"; fi

printf '%s\n' "$bt_ss" "$bt_ss" "$bt_cm" "$bt_svc" "$bt_ns" >"$bt_case/dup.json"
if bt_run "$bt_case/dup.json"; then bad "baseline duplicate target (expected reject)"; else ok "baseline duplicate target"; fi

printf 'not json' >"$bt_case/malformed.json"
if bt_run "$bt_case/malformed.json"; then bad "baseline malformed source (expected reject)"; else ok "baseline malformed source"; fi

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
