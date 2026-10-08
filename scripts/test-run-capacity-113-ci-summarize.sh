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
	mktemp -d "$tmp/results.XXXXXX"
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

# Wrapper safe output carries numeric fixture diagnosis for a real skew pass and
# for a wrong-route failure, so the failure explains itself.
skewwrap=$tmp/skewwrap
mkcase "$skewwrap" 100 110 90
jq -nc '{healthy:{started:0,completed:0,active:0},"slow-headers":{started:0,completed:0,active:0},"slow-body":{started:0,completed:0,active:0},fail:{started:0,completed:0,active:0}}' >"$skewwrap/fixture-metrics-2.json"
jq -nc '{healthy:{started:10,completed:10,active:0},"slow-headers":{started:4,completed:4,active:0},"slow-body":{started:4,completed:4,active:0},fail:{started:2,completed:2,active:0}}' >"$skewwrap/fixture-metrics-0.json"
skewres=$(new_results)
if "$wrapper" --summarize "$skewwrap" "$skewres" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '
		.overall.correctness == "pass" and .fixture.complete == true and (.fixture.mismatches | length) == 0 and
		.fixture.aggregate.started == 30 and .fixture.aggregate.completed == 30 and .fixture.aggregate.active == 0 and
		.fixture.index_completeness.observed == [0, 1, 2] and
		([.fixture.route_check[] | select(.route == "healthy" and .observed_started == 15)] | length) == 1 and
		([.fixture.per_index[] | select(.index == 2 and .complete == true)] | length) == 1
	' "$skewres/criterion.json" >/dev/null 2>&1; then
	ok "wrapper numeric fixture diagnosis on skew pass"
else
	bad "wrapper numeric fixture diagnosis on skew pass (unexpected criterion)"
	jq -c '{correctness:.overall.correctness,complete:.fixture.complete,mismatches:.fixture.mismatches}' "$skewres/criterion.json" >&2 || true
fi

failwrap=$tmp/failwrap
mkcase "$failwrap" 100 110 90
jq -nc '{healthy:{started:6,completed:6,active:0},"slow-headers":{started:2,completed:2,active:0},"slow-body":{started:2,completed:2,active:0},fail:{started:0,completed:0,active:0}}' >"$failwrap/fixture-metrics-0.json"
failres=$(new_results)
if "$wrapper" --summarize "$failwrap" "$failres" >"$tmp/out" 2>"$tmp/err"; then wrc=0; else wrc=$?; fi
if [ "$wrc" -eq 0 ]; then
	bad "wrapper numeric fixture diagnosis on route failure (expected nonzero exit)"
elif jq -e '
	.overall.correctness == "fail" and .fixture.complete == false and
	.fixture.aggregate.started == 30 and
	([.fixture.mismatches[] | select(.route == "healthy" and .expected_started == 15 and .observed_started == 16)] | length) == 1 and
	([.fixture.mismatches[] | select(.route == "fail" and .expected_started == 3 and .observed_started == 2)] | length) == 1 and
	.fixture.index_completeness.complete == true
' "$failres/criterion.json" >/dev/null 2>&1; then
	ok "wrapper numeric fixture diagnosis on route failure"
else
	bad "wrapper numeric fixture diagnosis on route failure (unexpected criterion)"
	jq -c '{correctness:.overall.correctness,complete:.fixture.complete,mismatches:.fixture.mismatches}' "$failres/criterion.json" >&2 || true
fi
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
		jq -e '.schema_version == 1 and .error.failure_code == "unknown" and .error.analyzer_status == 1 and .error.reason == "analyzer unavailable or malformed (exit status 1)"' "$results/criterion.json" >/dev/null 2>&1 &&
		jq -e '.available == false' "$results/resource-summary.json" >/dev/null 2>&1 &&
		jq -e '.failure_code == "unknown" and .reason == "analyzer unavailable or malformed (exit status 1)"' "$results/resource-summary.json" >/dev/null 2>&1 &&
		[ -s "$results/pins.json" ] && [ -s "$results/runner-environment.json" ] && [ -s "$results/report.md" ] && [ -s "$results/resource-summary.json" ]; then
		ok "analyzer failure"
	else
		bad "analyzer failure (unexpected error report)"
	fi
fi

# A whole known analyzer message gets a fixed code; source text and unknown
# path-bearing errors remain undisclosed in safe artifacts.
noobservations=$tmp/noobservations
mkcase "$noobservations" 100 110 90
for f in "$noobservations"/driver-isolation113-driver-*.log; do printf 'PRIVATE_ANALYZER_CANARY\n' >"$f"; done
driver0=$noobservations/driver-isolation113-driver-0-abcde.log
for stage in config_ready initial_login_complete provider_created collection_created connection_created api_key_bound consumer_created grant_created invoke_scope_ready invoke_token_issued invoke_prechecks_complete diagnostic_entered; do
	printf '    connection_use_grant_test.go:42: isolation113-setup-checkpoint stage=%s\n' "$stage" >>"$driver0"
done
printf '%s\n' \
	'    other_test.go:42: isolation113-setup-checkpoint stage=config_ready' \
	'    connection_use_grant_test.go:x: isolation113-setup-checkpoint stage=config_ready' \
	'    connection_use_grant_test.go:42: isolation113-setup-checkpoint stage=unknown_stage' \
	'    connection_use_grant_test.go:42: isolation113-setup-checkpoint stage=diagnostic_entered PRIVATE_CHECKPOINT_CANARY' \
	>>"$noobservations/driver-isolation113-driver-1-abcde.log"
rm "$noobservations/driver-isolation113-driver-2-abcde.log"
artifacts_ready() {
	for artifact do
		[ -f "$artifact" ] && [ -s "$artifact" ] && [ -r "$artifact" ] || return 1
	done
}
results=$(new_results)
known_artifacts_ready=false
if "$wrapper" --summarize "$noobservations" "$results" >"$tmp/out" 2>"$tmp/err"; then
	bad "known analyzer failure code (expected nonzero exit)"
elif jq -e '.schema_version == 1 and .error.failure_code == "no_observation_records" and .error.analyzer_status == 1 and .error.reason == "analyzer unavailable or malformed (exit status 1)" and .overall.correctness == "fail" and .overall.performance == "inconclusive" and .criterion_pass == false' "$results/criterion.json" >/dev/null 2>&1 &&
	jq -e '
		.failure_code == "no_observation_records" and .available == false
		and .setup_checkpoints.coverage == "recognized checkpoints observed in collected driver logs only; null does not prove absence or cause"
		and .setup_checkpoints.drivers == [
			{driver_index:0,log_available:true,observed_stages:["config_ready","initial_login_complete","provider_created","collection_created","connection_created","api_key_bound","consumer_created","grant_created","invoke_scope_ready","invoke_token_issued","invoke_prechecks_complete","diagnostic_entered"]},
			{driver_index:1,log_available:true,observed_stages:null},
			{driver_index:2,log_available:false,observed_stages:null}
		]
	' "$results/resource-summary.json" >/dev/null 2>&1 &&
	artifacts_ready "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md"; then
	known_artifacts_ready=true
	if grep -Eq 'PRIVATE_(ANALYZER|CHECKPOINT)_CANARY' "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md"; then
		bad "known analyzer failure code (canary disclosed)"
	else
		grep_status=$?
		if [ "$grep_status" -eq 1 ]; then ok "known analyzer failure code"; else bad "known analyzer failure code (artifact grep failed)"; fi
	fi
else
	bad "known analyzer failure code (unexpected error report)"
fi

if [ "$known_artifacts_ready" = true ]; then
	rm "$results/report.md"
	if artifacts_ready "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md"; then
		bad "missing analyzer report artifact accepted"
	else
		ok "missing analyzer report artifact rejected"
	fi
else
	bad "missing analyzer report artifact check not exercised"
fi

setup_control=$tmp/setup-control
mkcase "$setup_control" 100 110 90
setup_control_results=$(new_results)
"$wrapper" --summarize "$setup_control" "$setup_control_results" >"$tmp/out" 2>"$tmp/err"
setup_observed=$tmp/setup-observed
mkcase "$setup_observed" 100 110 90
setup_driver0=$setup_observed/driver-isolation113-driver-0-abcde.log
setup_driver1=$setup_observed/driver-isolation113-driver-1-abcde.log
setup_driver2=$setup_observed/driver-isolation113-driver-2-abcde.log
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY isolation113-setup-checkpoint' >>"$setup_driver0"
printf '%s\n' 'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' >>"$setup_driver1"
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=initial_login_complete' \
	'connection_use_grant_test.go:92: login status = 401, want redirect' >>"$setup_driver2"
setup_observed_results=$(new_results)
if "$wrapper" --summarize "$setup_observed" "$setup_observed_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '.protected.errors == 0 and .criterion_pass == true' "$setup_observed_results/criterion.json" >/dev/null 2>&1 &&
	jq -e '
		.setup_failure_diagnostics.drivers == [
			{driver_index:0,state:"classified",reason:"authorize_status",http_status:503},
			{driver_index:1,state:"incomplete",reason:null,http_status:null},
			{driver_index:2,state:"completed",reason:null,http_status:null}
		]
	' "$setup_observed_results/resource-summary.json" >/dev/null 2>&1 &&
	cmp -s "$setup_control_results/criterion.json" "$setup_observed_results/criterion.json"; then
	if grep -Eq 'PRIVATE_SETUP_FATAL_CANARY' "$setup_observed_results/criterion.json" "$setup_observed_results/resource-summary.json"; then
		bad "setup fatal projection (canary disclosed)"
	else
		setup_grep_status=$?
		if [ "$setup_grep_status" -eq 1 ]; then ok "setup fatal projection and criterion invariance"; else bad "setup fatal projection privacy check failed"; fi
	fi
else
	bad "setup fatal projection and criterion invariance"
fi

setup_unclassified=$tmp/setup-unclassified
mkcase "$setup_unclassified" 100 110 90
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: synthetic fatal PRIVATE_SETUP_FATAL_CANARY' >>"$setup_unclassified/driver-isolation113-driver-0-abcde.log"
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY' \
	'connection_use_grant_test.go:52: login status = 401, want redirect' >>"$setup_unclassified/driver-isolation113-driver-1-abcde.log"
setup_unclassified_results=$(new_results)
if "$wrapper" --summarize "$setup_unclassified" "$setup_unclassified_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '
		.setup_failure_diagnostics.drivers == [
			{driver_index:0,state:"incomplete",reason:null,http_status:null},
			{driver_index:1,state:"incomplete",reason:null,http_status:null},
			{driver_index:2,state:"incomplete",reason:null,http_status:null}
		]
	' "$setup_unclassified_results/resource-summary.json" >/dev/null 2>&1; then
	ok "setup fatal projection fails closed for unrecognized and ambiguous fatals"
else
	bad "setup fatal projection fails closed for unrecognized and ambiguous fatals"
fi

setup_ordered=$tmp/setup-ordered
mkcase "$setup_ordered" 100 110 90
printf '%s\n' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:57: isolation113-setup-checkpoint stage=initial_login_complete' >>"$setup_ordered/driver-isolation113-driver-0-abcde.log"
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY' \
	'connection_use_grant_test.go:57: isolation113-setup-checkpoint stage=initial_login_complete' >>"$setup_ordered/driver-isolation113-driver-1-abcde.log"
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY' \
	'connection_use_grant_test.go:57: isolation113-setup-checkpoint stage=initial_login_complete EXTRA' \
	'other_test.go:57: isolation113-setup-checkpoint stage=initial_login_complete' >>"$setup_ordered/driver-isolation113-driver-2-abcde.log"
setup_ordered_results=$(new_results)
if "$wrapper" --summarize "$setup_ordered" "$setup_ordered_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '
		.setup_failure_diagnostics.drivers == [
			{driver_index:0,state:"incomplete",reason:null,http_status:null},
			{driver_index:1,state:"incomplete",reason:null,http_status:null},
			{driver_index:2,state:"incomplete",reason:null,http_status:null}
		]
	' "$setup_ordered_results/resource-summary.json" >/dev/null 2>&1; then
	ok "setup fatal projection rejects out-of-interval and malformed checkpoints"
else
	bad "setup fatal projection rejects out-of-interval and malformed checkpoints"
fi

setup_wrong_anchor=$tmp/setup-wrong-anchor
mkcase "$setup_wrong_anchor" 100 110 90
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'other_test.go:57: isolation113-setup-checkpoint stage=initial_login_complete' \
	'connection_use_grant_test.go:92: authorize status = 503, want login form:' >>"$setup_wrong_anchor/driver-isolation113-driver-0-abcde.log"
setup_wrong_anchor_results=$(new_results)
if "$wrapper" --summarize "$setup_wrong_anchor" "$setup_wrong_anchor_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '.setup_failure_diagnostics.drivers[0] == {driver_index:0,state:"incomplete",reason:null,http_status:null}' \
		"$setup_wrong_anchor_results/resource-summary.json" >/dev/null 2>&1; then
	ok "setup fatal projection rejects wrong-anchor checkpoint"
else
	bad "setup fatal projection rejects wrong-anchor checkpoint"
fi

setup_no_separator=$tmp/setup-no-separator
mkcase "$setup_no_separator" 100 110 90
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:57:isolation113-setup-checkpoint stage=initial_login_complete' \
	'connection_use_grant_test.go:92: login status = 401, want redirect' >>"$setup_no_separator/driver-isolation113-driver-0-abcde.log"
printf '%s\n' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'other_test.go:57:isolation113-setup-checkpoint stage=initial_login_complete' \
	'connection_use_grant_test.go:92: login status = 401, want redirect' >>"$setup_no_separator/driver-isolation113-driver-1-abcde.log"
setup_no_separator_results=$(new_results)
if "$wrapper" --summarize "$setup_no_separator" "$setup_no_separator_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '
		.setup_failure_diagnostics.drivers[0] == {driver_index:0,state:"incomplete",reason:null,http_status:null}
		and .setup_failure_diagnostics.drivers[1] == {driver_index:1,state:"incomplete",reason:null,http_status:null}
	' \
		"$setup_no_separator_results/resource-summary.json" >/dev/null 2>&1; then
	ok "setup fatal projection rejects correct- and wrong-anchor checkpoints without separator"
else
	bad "setup fatal projection rejects correct- and wrong-anchor checkpoints without separator"
fi

setup_preconfig_ambiguous=$tmp/setup-preconfig-ambiguous
mkcase "$setup_preconfig_ambiguous" 100 110 90
printf '%s\n' \
	'connection_use_grant_test.go:52: authorize status = 503, want login form: PRIVATE_SETUP_FATAL_CANARY' \
	'connection_use_grant_test.go:52: isolation113-setup-checkpoint stage=config_ready' \
	'connection_use_grant_test.go:52: login status = 401, want redirect' >>"$setup_preconfig_ambiguous/driver-isolation113-driver-0-abcde.log"
setup_preconfig_ambiguous_results=$(new_results)
if "$wrapper" --summarize "$setup_preconfig_ambiguous" "$setup_preconfig_ambiguous_results" >"$tmp/out" 2>"$tmp/err" &&
	jq -e '.setup_failure_diagnostics.drivers[0] == {driver_index:0,state:"incomplete",reason:null,http_status:null}' \
		"$setup_preconfig_ambiguous_results/resource-summary.json" >/dev/null 2>&1; then
	ok "setup fatal projection keeps pre-config and interval fatals ambiguous"
else
	bad "setup fatal projection keeps pre-config and interval fatals ambiguous"
fi

unknownmessage=$tmp/unknownmessage
mkcase "$unknownmessage" 100 110 90
printf '{"unexpected":true}\n' >"$unknownmessage/fixture-metrics-0-PRIVATE_ANALYZER_CANARY.json"
results=$(new_results)
if "$wrapper" --summarize "$unknownmessage" "$results" >"$tmp/out" 2>"$tmp/err"; then
	bad "unknown analyzer failure code (expected nonzero exit)"
elif jq -e '.error.failure_code == "unknown" and .overall.correctness == "fail" and .overall.performance == "inconclusive" and .criterion_pass == false' "$results/criterion.json" >/dev/null 2>&1 &&
	jq -e '.failure_code == "unknown" and .available == false' "$results/resource-summary.json" >/dev/null 2>&1 &&
	artifacts_ready "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md"; then
	if grep -q PRIVATE_ANALYZER_CANARY "$results/criterion.json" "$results/resource-summary.json" "$results/pins.json" "$results/runner-environment.json" "$results/report.md"; then
		bad "unknown analyzer failure code (canary disclosed)"
	else
		grep_status=$?
		if [ "$grep_status" -eq 1 ]; then ok "unknown analyzer failure code and canary redaction"; else bad "unknown analyzer failure code (artifact grep failed)"; fi
	fi
else
	bad "unknown analyzer failure code and canary redaction (unexpected error report)"
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

# lastState.terminated projection: OOMKilled previous preserved while current Waiting CrashLoop.
laststate_case=$tmp/laststate-startup
mkdir -p "$laststate_case/failure-capture"
jq -nc '{
	kind: "PodList",
	items: [
		{metadata: {name: "goauthy-0", namespace: "goauthy"},
		 spec: {containers: [{name: "goauthy"}]},
		 status: {phase: "Pending",
		       containerStatuses: [{name: "goauthy", ready: false, restartCount: 2,
		                         state: {waiting: {reason: "CrashLoopBackOff"}},
		                         lastState: {terminated: {reason: "OOMKilled", exitCode: 137, signal: 9}}}]}}
	]
}' >"$laststate_case/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$laststate_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.available == true
	and ([.startup.pods[].containers[] | select(.name == "app" and .waiting == "CrashLoopBackOff" and .last_terminated == "OOMKilled" and .last_exit_code == 137 and .last_signal == 9)] | length) == 1
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup lastState OOMKilled preserved"
else
	bad "startup lastState OOMKilled preserved (unexpected view)"
	jq -c '.startup' "$results/resource-summary.json" >&2 || true
fi

# lastState arbitrary reason canary -> other (never the raw private reason).
lastreason_case=$tmp/lastreason-startup
mkdir -p "$lastreason_case/failure-capture"
last_reason_canary='PRIVATE_LAST_REASON_CANARY_7d2e'
jq -nc --arg r "$last_reason_canary" '{
	kind: "PodList",
	items: [
		{metadata: {name: "goauthy-0", namespace: "goauthy"},
		 spec: {containers: [{name: "goauthy"}]},
		 status: {phase: "Running",
		       containerStatuses: [{name: "goauthy", ready: false, restartCount: 0,
		                         state: {running: {}},
		                         lastState: {terminated: {reason: $r, exitCode: 1}}}]}}
	]
}' >"$lastreason_case/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$lastreason_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.available == true
	and ([.startup.pods[].containers[] | select(.name == "app" and .last_terminated == "other" and .last_exit_code == 1)] | length) == 1
' "$results/resource-summary.json" >/dev/null 2>&1 &&
	! grep -q "$last_reason_canary" "$results/resource-summary.json"; then
	ok "startup lastState arbitrary reason canary -> other"
else
	bad "startup lastState arbitrary reason canary -> other (leak or wrong value)"
	jq -c '.startup' "$results/resource-summary.json" >&2 || true
fi

# lastState malformed exit code / signal -> null (no passthrough).
lastmalformed_case=$tmp/lastmalformed-startup
mkdir -p "$lastmalformed_case/failure-capture"
jq -nc '{
	kind: "PodList",
	items: [
		{metadata: {name: "goauthy-0", namespace: "goauthy"},
		 spec: {containers: [{name: "goauthy"}]},
		 status: {phase: "Running",
		       containerStatuses: [{name: "goauthy", ready: false, restartCount: 0,
		                         state: {running: {}},
		                         lastState: {terminated: {reason: "Error", exitCode: 999, signal: "abc"}}}]}}
	]
}' >"$lastmalformed_case/failure-capture/pods.json"
results=$(new_results)
"$wrapper" --summarize "$lastmalformed_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.available == true
	and ([.startup.pods[].containers[] | select(.name == "app" and .last_terminated == "Error" and .last_exit_code == null and .last_signal == null)] | length) == 1
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "startup lastState malformed codes -> null"
else
	bad "startup lastState malformed codes -> null (unexpected view)"
	jq -c '.startup' "$results/resource-summary.json" >&2 || true
fi

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
append_fatal "$diag_case/driver-isolation113-driver-1-abcde.log" "authorize status = 502, want login form: \"$canary connection_use_grant_test.go:337: session_cookie_unsafe https://private.example.test/secret?token=$canary\" isolation113-setup-checkpoint"
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
append_fatal "$unk_case/driver-isolation113-driver-1-abcde.log" "some unrecognized helper failure isolation113-setup-checkpoint"
append_fatal "$unk_case/driver-isolation113-driver-2-abcde.log" "some unrecognized helper failure isolation113-setup-checkpointX"
results=$(new_results)
if "$wrapper" --summarize "$unk_case" "$results" >"$tmp/out" 2>"$tmp/err"; then rc=0; else rc=$?; fi
if [ "$rc" -eq 0 ]; then
	bad "unrecognized or missing IAM diagnostics incomplete (expected nonzero exit)"
elif jq -e '
	.protected.errors == 2
	and .criterion_pass == false
	and .iam_failure_diagnostics.errors == 2
	and .iam_failure_diagnostics.anchored == 0
	and .iam_failure_diagnostics.unrecognized == 2
	and .iam_failure_diagnostics.excess == 0
	and .iam_failure_diagnostics.missing == 2
	and .iam_failure_diagnostics.complete == false
	and .iam_failure_diagnostics.status == "incomplete"
	and ([.iam_failure_diagnostics.groups[].reasons[] | select(.reason == "unknown" and .status == null)] | length) == 2
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

# Probe evidence is an optional projection of retained events, not attempt counts.
probe_case=$tmp/probe-events
mkdir -p "$probe_case/failure-capture"
base_results=$tmp/probe-events-baseline
mkdir -p "$base_results"
"$wrapper" --summarize "$probe_case" "$base_results" >/dev/null 2>"$tmp/err" || true
jq -n '
	def event($i; $m): {involvedObject:{kind:"Pod",namespace:"goauthy",name:("goauthy-"+($i|tostring)),fieldPath:"spec.containers{goauthy}"},
		source:{component:"kubelet"},reason:"Killing",message:$m,count:99,metadata:{uid:"PRIVATE_EVENT_CANARY"},series:{count:88}};
	"Container goauthy failed startup probe, will be restarted" as $s
	| "Container goauthy failed liveness probe, will be restarted" as $l
	| {items:[event(0;$s), (event(1;$l)|del(.source)|.reportingComponent="kubelet"),
		event(2;($s+" PRIVATE_EVENT_CANARY")),
		(event(0;$s)|.involvedObject.namespace="other"), (event(0;$s)|.involvedObject.kind="Node"),
		(event(0;$s)|.involvedObject.name="goauthy-9"), (event(0;$s)|.involvedObject.fieldPath="spec.containers{sidecarfixture}"),
		(event(0;$s)|.source.component="scheduler"), (event(0;$s)|.reason="Unhealthy")]}
' >"$probe_case/failure-capture/events.json"
printf 'events.json_exit=0\n' >"$probe_case/failure-capture/capture-status.txt"
results=$tmp/probe-events-observed
mkdir -p "$results"
"$wrapper" --summarize "$probe_case" "$results" >/dev/null 2>"$tmp/err" || true
if jq -e '
	.startup.probe_events.available and .startup.probe_events.events_json_exit == 0
	and [.startup.probe_events.pods[] | [.index,.startup_probe_kill_records,.liveness_probe_kill_records,.other_kill_records]]
		== [[0,1,0,0],[1,0,1,0],[2,0,0,1]]
' "$results/resource-summary.json" >/dev/null 2>&1 &&
	! grep -Eq 'PRIVATE_EVENT_CANARY|involvedObject|will be restarted' "$results/resource-summary.json" &&
	[ "$base_results" != "$results" ] &&
	jq -e 'type == "object"' "$base_results/criterion.json" >/dev/null 2>&1 &&
	jq -e 'type == "object"' "$results/criterion.json" >/dev/null 2>&1 &&
	[ "$(jq -cS . "$base_results/criterion.json")" = "$(jq -cS . "$results/criterion.json")" ] &&
	[ "$(jq -cS '.startup|del(.probe_events)' "$base_results/resource-summary.json")" = "$(jq -cS '.startup|del(.probe_events)' "$results/resource-summary.json")" ]; then
	ok "probe events exact messages, scope, privacy, record counts and unchanged gates"
else
	bad "probe events exact messages, scope, privacy, record counts and unchanged gates"
fi
# Missing/invalid/failed captures must be unavailable rather than observed zeros.
for probe_state in missing malformed shape scalar absent duplicate failed extra range empty invalid_valid valid_invalid valid_valid zero_byte; do
	printf '{"items":[]}\n' >"$probe_case/failure-capture/events.json"
	printf 'events.json_exit=0\n' >"$probe_case/failure-capture/capture-status.txt"
	case "$probe_state" in
		missing) rm "$probe_case/failure-capture/events.json" ; want=capture-missing ;;
		malformed) printf 'PRIVATE_EVENT_CANARY' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		shape) printf '{"items":[1]}' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		scalar) printf '"PRIVATE_EVENT_CANARY"' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		absent) : >"$probe_case/failure-capture/capture-status.txt"; want=capture-status-invalid ;;
		duplicate) printf 'events.json_exit=0\nevents.json_exit=0\n' >"$probe_case/failure-capture/capture-status.txt"; want=capture-status-invalid ;;
		failed) printf 'events.json_exit=1\n' >"$probe_case/failure-capture/capture-status.txt"; want=capture-status-failed ;;
		extra) printf 'events.json_exit=0=PRIVATE_EVENT_CANARY\n' >"$probe_case/failure-capture/capture-status.txt"; want=capture-status-invalid ;;
		range) printf 'events.json_exit=999\n' >"$probe_case/failure-capture/capture-status.txt"; want=capture-status-invalid ;;
		empty) want=empty ;;
		invalid_valid) printf '{"items":[1]}\n{"items":[]}\n' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		valid_invalid) printf '{"items":[]}\n{"items":[1]}\n' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		valid_valid) printf '{"items":[]}\n{"items":[]}\n' >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
		zero_byte) : >"$probe_case/failure-capture/events.json"; want=capture-invalid ;;
	esac
	results=$(new_results)
	"$wrapper" --summarize "$probe_case" "$results" >/dev/null 2>"$tmp/err" || true
	if jq -e --arg want "$want" '
		.startup.probe_events as $p
		| if $want == "empty" then $p.available and ($p.pods|length) == 3
			and all($p.pods[]; .startup_probe_kill_records == 0 and .liveness_probe_kill_records == 0 and .other_kill_records == 0)
		  else $p.available == false and $p.reason == $want and $p.pods == [] end
	' "$results/resource-summary.json" >/dev/null 2>&1 && ! grep -q PRIVATE_EVENT_CANARY "$results/resource-summary.json" &&
		[ "$base_results" != "$results" ] &&
		jq -e 'type == "object"' "$base_results/criterion.json" >/dev/null 2>&1 &&
		jq -e 'type == "object"' "$results/criterion.json" >/dev/null 2>&1 &&
		[ "$(jq -cS . "$base_results/criterion.json")" = "$(jq -cS . "$results/criterion.json")" ] &&
		[ "$(jq -cS '.startup|del(.probe_events)' "$base_results/resource-summary.json")" = "$(jq -cS '.startup|del(.probe_events)' "$results/resource-summary.json")" ]; then
		ok "probe events eligibility $probe_state"
	else
		bad "probe events eligibility $probe_state"
	fi
done

# The readiness file records only successful, ordered HTTP 200 probes. Pair its
# safe prefix projection with the existing pre/post capture result to separate
# a gate that stopped early from one that completed; never infer a failed status.
readiness_no_private_data() {
	if grep -Eq 'PRIVATE_READINESS_CANARY|NOT_A_TIMESTAMP|2099-12-31T23:59:59Z|goauthy-00|500' "$@"; then
		return 1
	else
		grep_status=$?
		[ "$grep_status" -eq 1 ] && return 0
		return "$grep_status"
	fi
}

readiness_base=$tmp/authorize-readiness-base
mkcase "$readiness_base" 100 110 90
rm "$readiness_base"/fixture-metrics-*.json
for phase in pre post; do
	value=0
	[ "$phase" = pre ] || value=1
	for pod in 0 1 2; do
		jq -nc --argjson pod "$pod" --argjson value "$value" \
			'{schema_version:1,available:true,reason:null,pod_index:$pod,incarnation_stable:true,counters:{http_requests:$value,http_failures:0,sdk_retries:0,transport_failures:0,condition_conflicts:0,dedup_hits:0,http_4xx_unexpected:0,http_5xx:0}}' \
			>"$readiness_base/object-store-$phase-$pod.json"
	done
done
readiness_partial=$tmp/authorize-readiness-partial
readiness_full=$tmp/authorize-readiness-full
cp -R "$readiness_base" "$readiness_partial"
cp -R "$readiness_base" "$readiness_full"
printf '2099-12-31T23:59:59Z\tgoauthy-0\t200\n' >"$readiness_partial/authorize-readiness.tsv"
printf '2026-10-08T00:00:01Z\tgoauthy-0\t200\n2026-10-08T00:00:02Z\tgoauthy-1\t200\n2026-10-08T00:00:03Z\tgoauthy-2\t200\n' \
	>"$readiness_full/authorize-readiness.tsv"
partial_results=$(new_results)
full_results=$(new_results)
if [ "$partial_results" = "$full_results" ] || [ -e "$partial_results/criterion.json" ] || [ -e "$partial_results/resource-summary.json" ] ||
	[ -e "$full_results/criterion.json" ] || [ -e "$full_results/resource-summary.json" ]; then
	bad "authorize readiness partial/full result directories are distinct and empty"
else
	ok "authorize readiness partial/full result directories are distinct and empty"
fi
"$wrapper" --summarize "$readiness_partial" "$partial_results" >/dev/null 2>"$tmp/err" || true
"$wrapper" --summarize "$readiness_full" "$full_results" >/dev/null 2>"$tmp/err" || true
if jq -e '.overall.correctness == "fail" and .criterion_pass == false' "$partial_results/criterion.json" >/dev/null 2>&1 &&
	jq -e '.overall.correctness == "fail" and .criterion_pass == false' "$full_results/criterion.json" >/dev/null 2>&1 &&
	jq -e '.authorize_readiness.available and .authorize_readiness.successful_pod_indices == [0] and .object_store.available and (.object_store.pods | map(.pod_index) == [0,1,2]) and all(.object_store.pods[]; .available)' "$partial_results/resource-summary.json" >/dev/null 2>&1 &&
	jq -e '.authorize_readiness.available and .authorize_readiness.successful_pod_indices == [0,1,2] and .object_store.available and (.object_store.pods | map(.pod_index) == [0,1,2]) and all(.object_store.pods[]; .available)' "$full_results/resource-summary.json" >/dev/null 2>&1 &&
	[ "$(jq -cS . "$partial_results/criterion.json")" = "$(jq -cS . "$full_results/criterion.json")" ] &&
	[ "$(jq -cS 'del(.authorize_readiness)' "$partial_results/resource-summary.json")" = "$(jq -cS 'del(.authorize_readiness)' "$full_results/resource-summary.json")" ]; then
	if readiness_no_private_data "$partial_results/resource-summary.json"; then
		ok "authorize readiness prefix distinguishes partial/full with post captures and unchanged fail-closed criterion"
	else
		privacy_status=$?
		if [ "$privacy_status" -eq 1 ]; then
			bad "authorize readiness prefix privacy check (timestamp disclosed)"
		else
			bad "authorize readiness prefix privacy check (artifact grep failed)"
		fi
	fi
else
	bad "authorize readiness prefix distinguishes partial/full with post captures and unchanged fail-closed criterion"
fi

readiness_case=$tmp/authorize-readiness-validation
cp -R "$readiness_base" "$readiness_case"
previous_readiness_results=$full_results
for readiness_mode in empty missing malformed out-of-order duplicate extra-field noncanonical-index non-200 extra-row; do
	readiness_file=$readiness_case/authorize-readiness.tsv
	case "$readiness_mode" in
		empty) : >"$readiness_file"; want_available=true; want_reason=null; want_indices='[]' ;;
		missing) rm -f "$readiness_file"; want_available=false; want_reason=capture-missing; want_indices=null ;;
		malformed) printf 'NOT_A_TIMESTAMP\tgoauthy-0\t200\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		out-of-order) printf '2026-10-08T00:00:01Z\tgoauthy-1\t200\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		duplicate) printf '2026-10-08T00:00:01Z\tgoauthy-0\t200\n2026-10-08T00:00:02Z\tgoauthy-0\t200\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		extra-field) printf '2026-10-08T00:00:01Z\tgoauthy-0\t200\tPRIVATE_READINESS_CANARY\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		noncanonical-index) printf '2026-10-08T00:00:01Z\tgoauthy-00\t200\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		non-200) printf '2026-10-08T00:00:01Z\tgoauthy-0\t500\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
		extra-row) printf '2026-10-08T00:00:01Z\tgoauthy-0\t200\n2026-10-08T00:00:02Z\tgoauthy-1\t200\n2026-10-08T00:00:03Z\tgoauthy-2\t200\n2026-10-08T00:00:04Z\tgoauthy-2\t200\n' >"$readiness_file"; want_available=false; want_reason=capture-invalid; want_indices=null ;;
	esac
	results=$(new_results)
	if [ "$results" = "$previous_readiness_results" ] || [ -e "$results/criterion.json" ] || [ -e "$results/resource-summary.json" ]; then
		bad "authorize readiness $readiness_mode result directory is not fresh"
	else
		ok "authorize readiness $readiness_mode result directory is fresh"
	fi
	previous_readiness_results=$results
	"$wrapper" --summarize "$readiness_case" "$results" >/dev/null 2>"$tmp/err" || true
	if jq -e --argjson available "$want_available" --arg reason "$want_reason" --argjson indices "$want_indices" '
		.authorize_readiness.available == $available
		and .authorize_readiness.reason == (if $reason == "null" then null else $reason end)
		and .authorize_readiness.successful_pod_indices == $indices
		and .object_store.available
		and (.object_store.pods | map(.pod_index) == [0,1,2])
	' "$results/resource-summary.json" >/dev/null 2>&1 &&
		jq -e '.overall.correctness == "fail" and .criterion_pass == false' "$results/criterion.json" >/dev/null 2>&1 &&
		[ "$(jq -cS . "$full_results/criterion.json")" = "$(jq -cS . "$results/criterion.json")" ]; then
		if readiness_no_private_data "$results/resource-summary.json"; then
			ok "authorize readiness $readiness_mode validation and fail-closed criterion"
		else
			privacy_status=$?
			if [ "$privacy_status" -eq 1 ]; then bad "authorize readiness $readiness_mode privacy check (canary disclosed)"
			else bad "authorize readiness $readiness_mode privacy check (artifact grep failed)"; fi
		fi
	else
		bad "authorize readiness $readiness_mode validation and fail-closed criterion"
	fi
done

missing_pod_summary=$tmp/authorize-readiness-missing-pod.json
jq 'del(.object_store.pods[1])' "$full_results/resource-summary.json" >"$missing_pod_summary"
if jq -e '.authorize_readiness.available and .authorize_readiness.successful_pod_indices == [0,1,2] and .object_store.available and (.object_store.pods | map(.pod_index) == [0,1,2]) and all(.object_store.pods[]; .available)' \
	"$missing_pod_summary" >/dev/null 2>&1; then
	bad "authorize readiness exact object-store pod set accepts a missing pod"
else
	ok "authorize readiness exact object-store pod set rejects a missing pod"
fi

grep() { return 2; }
if readiness_no_private_data "$partial_results/resource-summary.json"; then
	bad "authorize readiness privacy guard accepts grep error"
else
	privacy_status=$?
	if [ "$privacy_status" -eq 2 ]; then ok "authorize readiness privacy guard rejects grep error"
	else bad "authorize readiness privacy guard unexpected error status $privacy_status"; fi
fi

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
