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

# Source-build pin projection (offline). The released-image default keeps the
# candidate digests null; the source-build mode records the OCI manifest and
# config digests as separate fields and never conflates them.
sb_default=$(new_results)
if "$wrapper" --summarize "$base" "$sb_default" >/dev/null 2>"$tmp/err" &&
	jq -e '.candidate.mode == "released-image" and .candidate.manifest_digest == null and .candidate.config_digest == null' "$sb_default/pins.json" >/dev/null 2>&1; then
	ok "released-image pin projection"
else
	bad "released-image pin projection"
fi
sb_manifest=sha256:$(printf '%064d' 6)
sb_config=sha256:$(printf '%064d' 3)
sb_local=$(new_results)
if GOAUTHY_LOCAL_BUILD=1 GOAUTHY_CANDIDATE_MANIFEST_DIGEST="$sb_manifest" GOAUTHY_CANDIDATE_CONFIG_DIGEST="$sb_config" \
	"$wrapper" --summarize "$base" "$sb_local" >/dev/null 2>"$tmp/err" &&
	jq -e --arg m "$sb_manifest" --arg c "$sb_config" '.candidate.mode == "source-build" and .candidate.manifest_digest == $m and .candidate.config_digest == $c and .candidate.manifest_digest != .candidate.config_digest' "$sb_local/pins.json" >/dev/null 2>&1; then
	ok "source-build pin projection"
else
	bad "source-build pin projection"
	jq -c '.candidate' "$sb_local/pins.json" >&2 || true
fi

# Privacy/ownership: a raw or malformed env digest must never leak into the
# safe aggregate; each field is emitted only as a strict sha256 digest or null.
sb_raw=$(new_results)
if GOAUTHY_LOCAL_BUILD=1 GOAUTHY_CANDIDATE_MANIFEST_DIGEST='not-a-digest' GOAUTHY_CANDIDATE_CONFIG_DIGEST='sha256:short' \
	"$wrapper" --summarize "$base" "$sb_raw" >/dev/null 2>"$tmp/err" &&
	jq -e '.candidate.mode == "source-build" and .candidate.manifest_digest == null and .candidate.config_digest == null' "$sb_raw/pins.json" >/dev/null 2>&1 &&
	! grep -q 'not-a-digest' "$sb_raw/pins.json"; then
	ok "source-build pin projection rejects raw digests"
else
	bad "source-build pin projection rejects raw digests"
	jq -c '.candidate' "$sb_raw/pins.json" >&2 || true
fi
sb_mixed=$(new_results)
if GOAUTHY_LOCAL_BUILD=1 GOAUTHY_CANDIDATE_MANIFEST_DIGEST="$sb_manifest" GOAUTHY_CANDIDATE_CONFIG_DIGEST='raw-value' \
	"$wrapper" --summarize "$base" "$sb_mixed" >/dev/null 2>"$tmp/err" &&
	jq -e --arg m "$sb_manifest" '.candidate.mode == "source-build" and .candidate.manifest_digest == $m and .candidate.config_digest == null' "$sb_mixed/pins.json" >/dev/null 2>&1; then
	ok "source-build pin projection keeps valid manifest only"
else
	bad "source-build pin projection keeps valid manifest only"
	jq -c '.candidate' "$sb_mixed/pins.json" >&2 || true
fi

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
	if jq -e '.overall.correctness == "fail" and .criterion_pass == false
		and (.iam_failure_diagnostics | keys == ["anchored", "complete", "criterion", "errors", "excess", "groups", "missing", "source", "status", "unrecognized"])
		and (.iam_failure_diagnostics | .errors == null and .anchored == null and .unrecognized == null and .excess == null and .missing == null and .complete == false and .status == "unavailable" and .source == "unavailable" and .groups == [])' "$results/criterion.json" >/dev/null 2>&1 &&
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

# Startup observability projection (offline; reuses failure-capture/pods.json).
startup_case=$tmp/startup
mkdir -p "$startup_case/failure-capture"
jq -nc '{
	kind: "PodList",
	items: [
		{metadata: {name: "goauthy-0", namespace: "goauthy"},
		 spec: {initContainers: [{name: "wait-for-rhiza-bucket", image: "img", imageID: "sha256:private-img", containerID: "containerd://private-init"}],
		       containers: [{name: "goauthy", image: "img", imageID: "sha256:private-app", containerID: "containerd://private-app"},
		                     {name: "sidecarfixture", image: "img", imageID: "sha256:private-fx", containerID: "containerd://private-fx"},
		                     {name: "mystery", image: "img"},
		                     {name: "extra", image: "img"},
		                     {name: "weird", image: "img"}]},
		 status: {phase: "Pending", podIP: "10.0.0.9",
		       initContainerStatuses: [
		         {name: "wait-for-rhiza-bucket", ready: false, restartCount: 0, state: {waiting: {reason: "ErrImageNeverPull", message: "private-msg"}}}],
		       containerStatuses: [
		         {name: "goauthy", ready: false, restartCount: 0, state: {waiting: {reason: "ErrImageNeverPull"}}},
		         {name: "sidecarfixture", ready: false, restartCount: 0, state: {terminated: {reason: "Completed"}}},
		         {name: "mystery", ready: false, restartCount: 0, state: {waiting: {reason: "ImagePullBackOff", message: "private-pull"}}},
		         {name: "extra", ready: false, restartCount: 0, state: {waiting: {reason: "CreateContainerConfigError", message: "private-cfg"}}},
		         {name: "weird", ready: false, restartCount: 0, state: {waiting: {reason: "SomeArbitraryPrivateReason", message: "private-weird"}}}]}},
		{metadata: {name: "goauthy-1", namespace: "goauthy"},
		 spec: {containers: [{name: "goauthy"}]},
		 status: {phase: "Running",
		       containerStatuses: [{name: "goauthy", ready: false, state: {waiting: {reason: "CrashLoopBackOff"}}}]}},
		{metadata: {name: "goauthy-9", namespace: "other"},
		 spec: {containers: [{name: "goauthy"}]},
		 status: {phase: "Running", containerStatuses: [{name: "goauthy", ready: true, restartCount: 0, state: {running: {}}}]}}
	]
}' >"$startup_case/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$startup_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.available == true
	and .startup.complete == false
	and .startup.observed == true
	and ([.startup.pods[].index] | sort | unique) == [0, 1]
	and ([.startup.pods[] | select(.index == 0 and .present)] | length) == 1
	and ([.startup.pods[] | select(.index == 2)] | length) == 0
	and ([.startup.pods[].containers[] | select(.name == "init" and .waiting == "ErrImageNeverPull")] | length) == 1
	and ([.startup.pods[].containers[] | select(.name == "app" and .waiting == "ErrImageNeverPull")] | length) == 1
	and ([.startup.pods[].containers[] | select(.name == "fixture" and .terminated == "Completed")] | length) == 1
	and ([.startup.pods[].containers[] | select(.name == "other" and .waiting == "ImagePullBackOff")] | length) == 1
	and ([.startup.pods[].containers[] | select(.name == "other" and .waiting == "CreateContainerConfigError")] | length) == 1
	and ([.startup.pods[].containers[] | select(.name == "other" and .waiting == "other")] | length) == 1
	and ([.startup.pods[] | select(.index == 1) | .containers[] | select(.name == "app" and .waiting == "CrashLoopBackOff" and .restart_bucket == "unknown")] | length) == 1
	and ([.startup.pods[].containers[] | keys[] | select(. == "imageID" or . == "containerID" or . == "podIP" or . == "message" or . == "env" or . == "url" or . == "logs" or . == "image")] | length) == 0
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup projection"
else
	bad "startup projection (unexpected view)"
	jq -c '.startup' "$results/resource-summary.json" >&2 || true
fi

nostatus_startup=$tmp/nostatus-startup
mkdir -p "$nostatus_startup/failure-capture"
jq -nc '{kind:"PodList",items:[{metadata:{name:"goauthy-0",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]},status:{phase:"Pending"}},{metadata:{name:"goauthy-1",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]}}]}' >"$nostatus_startup/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$nostatus_startup" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.available == true
	and .startup.observed == true
	and ([.startup.pods[].containers[] | select(.name == "app" and .phase == "Unknown" and .restart_bucket == "unknown")] | length) == 2
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup missing status retained"
else
	bad "startup missing status retained (capture lost)"
	jq -c '.startup' "$results/resource-summary.json" >&2 || true
fi

dup_startup=$tmp/dup-startup
mkdir -p "$dup_startup/failure-capture"
jq -nc '{kind:"PodList",items:[{metadata:{name:"goauthy-0",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]}},{metadata:{name:"goauthy-0",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]}},{metadata:{name:"goauthy-1",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]}}]}' >"$dup_startup/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$dup_startup" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.available == true and .startup.complete == false' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup duplicate capture not complete"
else
	bad "startup duplicate capture not complete (false complete)"
fi

missing_startup=$tmp/missing-startup
mkdir -p "$missing_startup"
results=$(new_results)
"$wrapper" --summarize "$missing_startup" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.available == false and .startup.reason == "capture-missing" and .startup.complete == false and .startup.observed == false and (.startup.pods | length) == 0' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup missing source"
else
	bad "startup missing source (expected honest unavailable)"
fi

malformed_startup=$tmp/malformed-startup
mkdir -p "$malformed_startup/failure-capture"
printf 'not json' >"$malformed_startup/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$malformed_startup" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.available == false and .startup.reason == "capture-invalid" and .startup.complete == false and .startup.observed == false' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup malformed source"
else
	bad "startup malformed source (expected honest unavailable)"
fi

projerr_startup=$tmp/projerr-startup
mkdir -p "$projerr_startup/failure-capture"
printf '{"items":[1,2,3]}' >"$projerr_startup/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$projerr_startup" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.available == false and .startup.reason == "projection-error" and .startup.complete == false and .startup.observed == false' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup projection error"
else
	bad "startup projection error (expected projection-error reason)"
fi

# Valid JSON but not a PodList/List array shape -> capture-invalid.
for shape in '{}' '{"items":null}' '{"items":"notanarray"}'; do
	shape_startup=$tmp/shape-startup
	rm -rf "$shape_startup"
	mkdir -p "$shape_startup/failure-capture"
	printf '%s' "$shape" >"$shape_startup/failure-capture/pods.json"
	results=$(new_results)
	"$wrapper" --summarize "$shape_startup" "$results" >/dev/null 2>"$tmp/err" || true
	if jq -e '.startup.available == false and .startup.reason == "capture-invalid"' "$results/resource-summary.json" >/dev/null 2>&1; then
		ok "startup non-list shape"
	else
		bad "startup non-list shape (expected capture-invalid)"
	fi
done

# capture-status pods.json_exit signal (null-or-0..255 integer, no passthrough).
exit_case=$tmp/exit-case
mkdir -p "$exit_case/failure-capture"
jq -nc '{kind:"PodList",items:[{metadata:{name:"goauthy-0",namespace:"goauthy"},spec:{containers:[{name:"goauthy"}]}}]}' >"$exit_case/failure-capture/pods.json"
printf 'pods.json_exit=1\n' >"$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == 1 and .startup.available == true' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup pods.json_exit known"
else
	bad "startup pods.json_exit known (expected 1)"
fi
printf 'pods.json_exit=0\n' >"$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == 0' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup pods.json_exit zero"
else
	bad "startup pods.json_exit zero (expected 0)"
fi
rm -f "$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == null' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup pods.json_exit absent null"
else
	bad "startup pods.json_exit absent null"
fi
printf 'pods.json_exit=secret-token-value\npods.json_exit=2\n' >"$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == null' "$results/resource-summary.json" >/dev/null 2>&1 &&
	! grep -q 'secret-token-value' "$results/resource-summary.json"; then
	ok "startup pods.json_exit malformed duplicate"
else
	bad "startup pods.json_exit malformed duplicate (leak or wrong value)"
fi
printf 'pods.json_exit=999\n' >"$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == null' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup pods.json_exit out of range"
else
	bad "startup pods.json_exit out of range (expected null)"
fi
printf 'pods.json_exit=1=secret\n' >"$exit_case/failure-capture/capture-status.txt"
results=$(new_results)
"$wrapper" --summarize "$exit_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '.startup.pods_json_exit == null' "$results/resource-summary.json" >/dev/null 2>&1 &&
	! grep -q 'secret' "$results/resource-summary.json"; then
	ok "startup pods.json_exit extra equals"
else
	bad "startup pods.json_exit extra equals (expected null)"
fi

# Anchored IAM failure diagnostics (offline; the actual wrapper and the actual
# shared analyzer run together; no browser, Kind, or Go execution).
flip_recovery_iam() {
	log=$1
	awk 'BEGIN{done=0} { if(!done && /phase=recovery route=iam outcome=success/){ sub(/outcome=success/,"outcome=failed"); done=1 } print }' "$log" >"$log.tmp" && mv "$log.tmp" "$log"
}
flip_baseline_iam() {
	log=$1
	awk 'BEGIN{done=0} { if(!done && /phase=baseline route=iam outcome=success/){ sub(/outcome=success/,"outcome=failed"); done=1 } print }' "$log" >"$log.tmp" && mv "$log.tmp" "$log"
}
append_fatal() {
	log=$1
	shift
	printf '    connection_use_grant_test.go:337: %s\n' "$*" >>"$log"
}

diag_case=$tmp/iam-diag
mkcase "$diag_case" 100 110 90
canary='PRIVATE_BODY_CANARY_9f3c7a'
flip_recovery_iam "$diag_case/driver-isolation113-driver-1-abcde.log"
flip_recovery_iam "$diag_case/driver-isolation113-driver-2-abcde.log"
append_fatal "$diag_case/driver-isolation113-driver-1-abcde.log" "authorize status = 502, want login form: \"$canary connection_use_grant_test.go:337: session_cookie_unsafe https://private.example.test/secret?token=$canary\""
append_fatal "$diag_case/driver-isolation113-driver-2-abcde.log" "login status=403, want redirect, category=invalid_login_request"
results=$(new_results)
if "$wrapper" --summarize "$diag_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "anchored IAM diagnostics (expected nonzero exit for correctness fail)"
elif jq -e '
	.protected.errors == 2
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 2
	and .iam_failure_diagnostics.anchored == 2
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == true
	and .iam_failure_diagnostics.status == "diagnosed"
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1 and .error_n == 1 and .anchored_n == 1 and (.reasons | length) == 1 and .reasons[0].reason == "authorize_status" and .reasons[0].status == 502 and (.phase_error_counts == [{phase:"recovery",error_n:1}]))] | length) == 1
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 2 and .error_n == 1 and .reasons[0].reason == "login_403_invalid_request" and .reasons[0].status == 403 and (.phase_error_counts == [{phase:"recovery",error_n:1}]))] | length) == 1
	and ([.iam_failure_diagnostics.groups[].reasons[].reason | select(. == "session_cookie_unsafe")] | length) == 0
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "anchored IAM diagnostics"
else
	bad "anchored IAM diagnostics (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi
leaked=false
for f in "$results"/*; do
	[ -f "$f" ] || continue
	if grep -q "$canary" "$f" 2>/dev/null; then leaked=true; fi
done
if [ "$leaked" = false ]; then
	ok "IAM diagnostics privacy"
else
	bad "IAM diagnostics privacy (private body or URL canary exported)"
fi

unk_case=$tmp/iam-unknown
mkcase "$unk_case" 100 110 90
flip_recovery_iam "$unk_case/driver-isolation113-driver-1-abcde.log"
flip_recovery_iam "$unk_case/driver-isolation113-driver-2-abcde.log"
append_fatal "$unk_case/driver-isolation113-driver-2-abcde.log" "some unrecognized helper failure that is not a known reason"
results=$(new_results)
if "$wrapper" --summarize "$unk_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "unrecognized or missing IAM diagnostics incomplete (expected nonzero exit)"
elif jq -e '
	.protected.errors == 2
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 2
	and .iam_failure_diagnostics.anchored == 0
	and .iam_failure_diagnostics.unrecognized == 1
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 2
	and .iam_failure_diagnostics.complete == false
	and .iam_failure_diagnostics.status == "incomplete"
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "unknown" and .status == null)] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "unrecognized or missing IAM diagnostics incomplete"
else
	bad "unrecognized or missing IAM diagnostics incomplete"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

tp_case=$tmp/iam-transport
mkcase "$tp_case" 100 110 90
flip_recovery_iam "$tp_case/driver-isolation113-driver-1-abcde.log"
flip_recovery_iam "$tp_case/driver-isolation113-driver-1-abcde.log"
append_fatal "$tp_case/driver-isolation113-driver-1-abcde.log" 'authorize status = 504, want login form: "Get \"https://private.example.test/oidc/authorize?token=SECRET\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"'
append_fatal "$tp_case/driver-isolation113-driver-1-abcde.log" 'Get "https://private.example.test/oidc/authorize?token=SECRET": context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
results=$(new_results)
if "$wrapper" --summarize "$tp_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "transport and null-status IAM diagnostics (expected nonzero exit)"
elif jq -e '
	.protected.errors == 2
	and .criterion_pass == false
	and .iam_failure_diagnostics.status == "diagnosed"
	and .iam_failure_diagnostics.anchored == 2
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == true
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1 and .error_n == 2 and .anchored_n == 2 and .complete == true)] | length) == 1
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "authorize_status" and .status == 504)] | length) == 1
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "transport_timeout" and .status == null)] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "transport and null-status IAM diagnostics"
else
	bad "transport and null-status IAM diagnostics (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

two_phase=$tmp/iam-two-phase
mkcase "$two_phase" 100 110 90
flip_baseline_iam "$two_phase/driver-isolation113-driver-1-abcde.log"
flip_recovery_iam "$two_phase/driver-isolation113-driver-1-abcde.log"
append_fatal "$two_phase/driver-isolation113-driver-1-abcde.log" "login status = 500, want redirect"
append_fatal "$two_phase/driver-isolation113-driver-1-abcde.log" "login status = 503, want redirect"
results=$(new_results)
if "$wrapper" --summarize "$two_phase" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "same driver two phases (expected nonzero exit)"
elif jq -e '
	.protected.errors == 2
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 2
	and .iam_failure_diagnostics.anchored == 2
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == true
	and .iam_failure_diagnostics.status == "diagnosed"
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1)] | length) == 1
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1 and .error_n == 2 and .anchored_n == 2 and .complete == true)] | length) == 1
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1) | .phase_error_counts[] | select(.phase == "baseline" and .error_n == 1)] | length) == 1
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1) | .phase_error_counts[] | select(.phase == "recovery" and .error_n == 1)] | length) == 1
	and ([.iam_failure_diagnostics.groups[] | select(.driver_index == 1) | .reasons[] | select(.reason == "login_status")] | length) == 2
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "same driver two phases counted once"
else
	bad "same driver two phases counted once (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

extra=$tmp/iam-extra
mkcase "$extra" 100 110 90
flip_recovery_iam "$extra/driver-isolation113-driver-1-abcde.log"
append_fatal "$extra/driver-isolation113-driver-1-abcde.log" "login status = 500, want redirect"
append_fatal "$extra/driver-isolation113-driver-1-abcde.log" "login status = 503, want redirect"
results=$(new_results)
if "$wrapper" --summarize "$extra" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "extra known diagnostic incomplete (expected nonzero exit)"
elif jq -e '
	.protected.errors == 1
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 1
	and .iam_failure_diagnostics.anchored == 2
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 1
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == false
	and .iam_failure_diagnostics.status == "incomplete"
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "extra known diagnostic incomplete"
else
	bad "extra known diagnostic incomplete (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

wait_case=$tmp/iam-wait
mkcase "$wait_case" 100 110 90
flip_recovery_iam "$wait_case/driver-isolation113-driver-1-abcde.log"
append_fatal "$wait_case/driver-isolation113-driver-1-abcde.log" "login status = 500, want redirect"
append_fatal "$wait_case/driver-isolation113-driver-1-abcde.log" "waiting 5 seconds for the login attempt window"
results=$(new_results)
if "$wrapper" --summarize "$wait_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "ordinary wait log not unknown (expected nonzero exit)"
elif jq -e '
	.protected.errors == 1
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 1
	and .iam_failure_diagnostics.anchored == 1
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == true
	and .iam_failure_diagnostics.status == "diagnosed"
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "ordinary wait log not unknown"
else
	bad "ordinary wait log not unknown (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

bad_status=$tmp/iam-bad-status
mkcase "$bad_status" 100 110 90
flip_recovery_iam "$bad_status/driver-isolation113-driver-1-abcde.log"
append_fatal "$bad_status/driver-isolation113-driver-1-abcde.log" "authorize status = 9999, want login form: \"private\""
results=$(new_results)
if "$wrapper" --summarize "$bad_status" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "malformed status unknown incomplete (expected nonzero exit)"
elif jq -e '
	.protected.errors == 1
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 1
	and .iam_failure_diagnostics.anchored == 0
	and .iam_failure_diagnostics.unrecognized == 1
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 1
	and .iam_failure_diagnostics.complete == false
	and .iam_failure_diagnostics.status == "incomplete"
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "unknown" and .status == null)] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "malformed status unknown incomplete"
else
	bad "malformed status unknown incomplete (unexpected diagnostics)"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

url_case=$tmp/iam-url-marker
mkcase "$url_case" 100 110 90
flip_recovery_iam "$url_case/driver-isolation113-driver-1-abcde.log"
append_fatal "$url_case/driver-isolation113-driver-1-abcde.log" 'Get "https://private.example.test/Client.Timeout?token=context deadline exceeded": EOF'
results=$(new_results)
if "$wrapper" --summarize "$url_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -ne 0 ] && jq -e '
	.protected.errors == 1 and .criterion_pass == false
	and .iam_failure_diagnostics.status == "incomplete"
	and .iam_failure_diagnostics.anchored == 0
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "transport_timeout")] | length) == 0
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "private URL cannot classify a transport timeout"
else
	bad "private URL cannot classify a transport timeout"
fi

rec_stage() {
	log=$1; phase=$2; stage=$3; outcome=$4; status=$5; elapsed=$6; sched=$7
	printf 'connection_use_grant_test.go:1: isolation113-stage phase=%s route=iam stage=%s outcome=%s status=%s elapsed_ms=%s scheduled_unix_ms=%s\n' \
		"$phase" "$stage" "$outcome" "$status" "$elapsed" "$sched" >>"$log"
}

gen_samples_cfs() {
	dir=$1; mode=$2
	: >"$dir/container-samples.jsonl"
	for pod in 0 1 2; do
		for cont in goauthy sidecarfixture; do
			for t in 1 2 3; do
				case "$mode" in
					valid) periods=$((t * 100)); throttled=$((t * 10)); seconds=$t ;;
					missing) periods=null; throttled=null; seconds=null ;;
					reset) periods=$((300 - t * 100)); throttled=0; seconds=0 ;;
				esac
				jq -nc --arg ts "2026-01-01T00:00:0${t}Z" --argjson p "$pod" --arg c "$cont" --arg cid "containerd://cfs-${pod}-${cont}" \
					--argjson periods "$periods" --argjson throttled "$throttled" --argjson seconds "$seconds" \
					'{hostTimestampUTC:$ts,pod:("goauthy-"+($p|tostring)),container:$c,containerID:$cid,cpuUsageCoreNanoSeconds:1000,memoryWorkingSetBytes:1000000,memoryRSSBytes:900000,unavailable:[],cpuCfsPeriodsTotal:$periods,cpuCfsThrottledPeriodsTotal:$throttled,cpuCfsThrottledSecondsTotal:$seconds,cpuCfsUnavailable:[]}' \
					>>"$dir/container-samples.jsonl"
			done
		done
	done
}

stage_case=$tmp/iam-stage
mkcase "$stage_case" 100 110 90
rec_stage "$stage_case/driver-isolation113-driver-0-abcde.log" baseline authorize-get none 200 3000.000 1
rec_stage "$stage_case/driver-isolation113-driver-0-abcde.log" baseline login-post none 302 1000.000 1
rec_stage "$stage_case/driver-isolation113-driver-0-abcde.log" mixed authorize-get timeout 0 10000.000 7
stage_canary='PRIVATE_STAGE_CANARY_9f3c7a'
printf '%s\n' "$stage_canary" >> "$stage_case/driver-isolation113-driver-0-abcde.log"
results=$(new_results)
if "$wrapper" --summarize "$stage_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -ne 0 ]; then
	bad "stage survives wrapper (unexpected nonzero exit)"
elif jq -e '
	.iam_stages.timeout_n == 1
	and ([.iam_stages.stage_outcomes[] | select(.stage == "authorize-get" and .outcome == "timeout" and .n == 1 and .elapsed_ms_max == 10000)] | length) == 1
	and (.iam_stages.stage_outcomes | length) == 3
' "$results/criterion.json" >/dev/null 2>&1 &&
	! grep -q "$stage_canary" "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md" 2>/dev/null; then
	ok "stage survives wrapper 5 allowlist"
else
	bad "stage survives wrapper 5 allowlist"
	jq -c '.iam_stages' "$results/criterion.json" >&2 || true
fi

missing_stage=$tmp/iam-missing-stage
mkcase "$missing_stage" 100 110 90
results=$(new_results)
"$wrapper" --summarize "$missing_stage" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.iam_stages.complete == false
	and .iam_stages.attempt_complete == false
	and ([.iam_stages.attempt_coverage[] | select(.stage_n == 0)] | length) == 48
	and (.iam_stages.timeout_n == 0)
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "per-attempt missing stage evidence"
else
	bad "per-attempt missing stage evidence"
	jq -c '.iam_stages | {attempt_complete, timeout_n, coverage_n: (.attempt_coverage | length)}' "$results/criterion.json" >&2 || true
fi

unk_stage=$tmp/iam-unknown-stage
mkcase "$unk_stage" 100 110 90
printf 'connection_use_grant_test.go:1: isolation113-stage phase=baseline route=iam stage=bogus outcome=none status=200 elapsed_ms=1.000 scheduled_unix_ms=1\n' >> "$unk_stage/driver-isolation113-driver-0-abcde.log"
results=$(new_results)
if "$wrapper" --summarize "$unk_stage" "$results" >"$tmp/out" 2>"$tmp/err"; then
	bad "unknown stage rejected (expected nonzero exit)"
else
	ok "unknown stage rejected"
fi

for mode in valid missing reset; do
	cfs_case=$tmp/cfs-$mode
	mkdir -p "$cfs_case"
	for idx in 0 1 2; do gen_driver_log "$cfs_case" "$idx" 100 110 90; done
	gen_samples_cfs "$cfs_case" "$mode"
	gen_fixture "$cfs_case"
	results=$(new_results)
	"$wrapper" --summarize "$cfs_case" "$results" >/dev/null 2>"$tmp/err" || true
	if [ "$mode" = valid ]; then want_complete=true; want_delta=200; else want_complete=false; want_delta=null; fi
	if jq -e --argjson wc "$want_complete" --argjson wd "$want_delta" '
		([.series[] | select(.container == "goauthy")] | length) == 3
		and ([.series[] | select(.container == "goauthy") | .cfs_periods.complete] | all(. == $wc))
		and ([.series[] | select(.container == "goauthy") | .cfs_periods.delta] | all(. == $wd))
		' "$results/resource-summary.json" >/dev/null 2>&1; then
		ok "cfs $mode"
	else
		bad "cfs $mode"
		jq -c '.series[] | select(.container == "goauthy") | .cfs_periods' "$results/resource-summary.json" >&2 || true
	fi
done

gen_samples_cfs_bad() {
	dir=$1; mode=$2
	: >"$dir/container-samples.jsonl"
	for pod in 0 1 2; do
		for cont in goauthy sidecarfixture; do
			for t in 1 2; do
				case "$mode" in
					fractional) periods=100.5; throttled=10; seconds=1 ;;
					oversize) periods=9007199254740992; throttled=10; seconds=1 ;;
				esac
				jq -nc --arg ts "2026-01-01T00:00:0${t}Z" --argjson p "$pod" --arg c "$cont" --arg cid "containerd://bad-${pod}-${cont}" \
					--argjson periods "$periods" --argjson throttled "$throttled" --argjson seconds "$seconds" \
					'{hostTimestampUTC:$ts,pod:("goauthy-"+($p|tostring)),container:$c,containerID:$cid,cpuUsageCoreNanoSeconds:1000,memoryWorkingSetBytes:1000000,memoryRSSBytes:900000,unavailable:[],cpuCfsPeriodsTotal:$periods,cpuCfsThrottledPeriodsTotal:$throttled,cpuCfsThrottledSecondsTotal:$seconds,cpuCfsUnavailable:[]}' \
					>>"$dir/container-samples.jsonl"
			done
		done
	done
}

for mode in fractional oversize; do
	bad_case=$tmp/cfs-bad-$mode
	mkdir -p "$bad_case"
	for idx in 0 1 2; do gen_driver_log "$bad_case" "$idx" 100 110 90; done
	gen_samples_cfs_bad "$bad_case" "$mode"
	gen_fixture "$bad_case"
	results=$(new_results)
	if "$wrapper" --summarize "$bad_case" "$results" >"$tmp/out" 2>"$tmp/err"; then
		bad "cfs $mode rejected (expected nonzero exit)"
	else
		ok "cfs $mode rejected"
	fi
done

series_case=$tmp/cfs-series
mkdir -p "$series_case"
for idx in 0 1 2; do gen_driver_log "$series_case" "$idx" 100 110 90; done
gen_samples_cfs "$series_case" valid
gen_fixture "$series_case"
results=$(new_results)
"$wrapper" --summarize "$series_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	([.series[] | select(.container == "goauthy")] | length) == 3
	and ([.series[] | select(.container == "sidecarfixture")] | length) == 3
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "cfs three goauthy series"
else
	bad "cfs three goauthy series"
	jq -c '[.series[] | .container] | group_by(.) | map({container: .[0], n: length})' "$results/resource-summary.json" >&2 || true
fi

gen_samples_cfs_edge() {
	dir=$1; mode=$2
	: >"$dir/container-samples.jsonl"
	for pod in 0 1 2; do
		for cont in goauthy sidecarfixture; do
			for t in 1 2 3; do
				cid_null=false; cid="containerd://edge-${mode}-${pod}-${cont}"; periods=$((t * 100))
				case "$mode" in
					instance) cid="containerd://edge-${mode}-${pod}-${cont}-${t}" ;;
					missing-id) cid_null=true; cid="" ;;
					gap) if [ "$t" = 2 ]; then periods=null; fi ;;
				esac
				jq -nc --arg ts "2026-01-01T00:00:0${t}Z" --argjson p "$pod" --arg c "$cont" --argjson cid_null "$cid_null" --arg cid "$cid" \
					--argjson periods "$periods" --argjson throttled "$((t * 10))" --argjson seconds "$t" \
					'{hostTimestampUTC:$ts,pod:("goauthy-"+($p|tostring)),container:$c,containerID:(if $cid_null then null else $cid end),cpuUsageCoreNanoSeconds:1000,memoryWorkingSetBytes:1000000,memoryRSSBytes:900000,unavailable:[],cpuCfsPeriodsTotal:$periods,cpuCfsThrottledPeriodsTotal:$throttled,cpuCfsThrottledSecondsTotal:$seconds,cpuCfsUnavailable:[]}' \
					>>"$dir/container-samples.jsonl"
		done
	done
	done
}

for mode in instance missing-id gap; do
	edge_case=$tmp/cfs-edge-$mode
	mkdir -p "$edge_case"
	for idx in 0 1 2; do gen_driver_log "$edge_case" "$idx" 100 110 90; done
	gen_samples_cfs_edge "$edge_case" "$mode"
	gen_fixture "$edge_case"
	results=$(new_results)
	"$wrapper" --summarize "$edge_case" "$results" >/dev/null 2>"$tmp/err" || true
	if jq -e '
		([.series[] | select(.container == "goauthy")] | length) == 3
		and ([.series[] | select(.container == "goauthy") | .cfs_periods.complete] | all(. == false))
		and ([.series[] | select(.container == "goauthy") | .cfs_periods.delta] | all(. == null))
	' "$results/resource-summary.json" >/dev/null 2>&1; then
		ok "cfs $mode incomplete"
	else
		bad "cfs $mode incomplete"
		jq -c '.series[] | select(.container == "goauthy") | .cfs_periods' "$results/resource-summary.json" >&2 || true
	fi
done

wrong_phase=$tmp/iam-wrong-phase
mkcase "$wrong_phase" 100 110 90
rec_stage "$wrong_phase/driver-isolation113-driver-0-abcde.log" mixed authorize-get none 200 3000.000 1
results=$(new_results)
"$wrapper" --summarize "$wrong_phase" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.iam_stages.complete == false
	and .iam_stages.attempt_complete == false
	and ([.iam_stages.attempt_coverage[] | select(.scheduled_unix_ms == 1 and .stage_n == 0)] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "wrong-phase stage join fail closed"
else
	bad "wrong-phase stage join fail closed"
	jq -c '.iam_stages | {complete, attempt_complete}' "$results/criterion.json" >&2 || true
fi

mixed_stage=$tmp/iam-mixed-stage
mkcase "$mixed_stage" 100 110 90
flip_recovery_iam "$mixed_stage/driver-isolation113-driver-1-abcde.log"
failed_sched=$(awk '/phase=recovery route=iam outcome=failed/ {for(i=1;i<=NF;i++) if($i ~ /^scheduled_unix_ms=/) {sub(/^scheduled_unix_ms=/,"",$i); print $i; exit}}' "$mixed_stage/driver-isolation113-driver-1-abcde.log")
append_fatal "$mixed_stage/driver-isolation113-driver-1-abcde.log" 'Post "https://private.example.test/oidc/authorize?token=SECRET": context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
rec_stage "$mixed_stage/driver-isolation113-driver-1-abcde.log" recovery authorize-get none 200 1000.000 "$failed_sched"
rec_stage "$mixed_stage/driver-isolation113-driver-1-abcde.log" recovery login-post timeout 0 10000.000 "$failed_sched"
results=$(new_results)
if "$wrapper" --summarize "$mixed_stage" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "mixed stage + single timeout (expected nonzero exit)"
elif jq -e --argjson fs "$failed_sched" '
	.protected.errors == 1
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 1
	and .iam_failure_diagnostics.anchored == 1
	and .iam_failure_diagnostics.unrecognized == 0
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 0
	and .iam_failure_diagnostics.complete == true
	and .iam_failure_diagnostics.status == "diagnosed"
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "unknown")] | length) == 0
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "transport_timeout" and .status == null)] | length) == 1
	and ([.iam_stages.attempt_coverage[] | select(.driver_index == 1 and .phase == "recovery" and .scheduled_unix_ms == $fs and .stage_n == 2)] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "mixed stage + single timeout no unknown pollution"
else
	bad "mixed stage + single timeout no unknown pollution"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

near_prefix=$tmp/iam-near-prefix
mkcase "$near_prefix" 100 110 90
flip_recovery_iam "$near_prefix/driver-isolation113-driver-1-abcde.log"
printf '    connection_use_grant_test.go:1: isolation113-stageX bogus\n' >> "$near_prefix/driver-isolation113-driver-1-abcde.log"
results=$(new_results)
if "$wrapper" --summarize "$near_prefix" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "near-prefix stage unknown incomplete (expected nonzero exit)"
elif jq -e '
	.iam_failure_diagnostics.status == "incomplete"
	and .iam_failure_diagnostics.unrecognized == 1
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "unknown")] | length) == 1
' "$results/criterion.json" >/dev/null 2>&1; then
	ok "near-prefix stage unknown incomplete"
else
	bad "near-prefix stage unknown incomplete"
	jq -c '.iam_failure_diagnostics' "$results/criterion.json" >&2 || true
fi

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
