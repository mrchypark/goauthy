#!/bin/sh
# Execute the real boot-only branch against synthetic pod status, offline.
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
harness=$root/scripts/e2e-kind-saas-isolation-113.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1" >&2; }
bad() { fail=$((fail + 1)); echo "not ok: $1" >&2; }
extract() {
	awk -v s="$1" -v e="$2" '
		$0 == s { seen++; on = 1 }
		on { print; if ($0 == e) { done++; on = 0 } }
		END { if (seen != 1 || done != 1 || on) exit 1 }' "$harness" >"$3" ||
		{ echo 'startup-only source anchor drift' >&2; exit 1; }
}
extract 'if [ "$startup_only" -eq 1 ]; then' 'fi' "$work/branch.sh"
extract 'startup_only=${GOAUTHY_113_STARTUP_ONLY:-0}' 'esac' "$work/validate.sh"
extract 'baseline_iam_only=${GOAUTHY_113_BASELINE_IAM_ONLY:-0}' 'fi' "$work/baseline-validate.sh"
extract 'if [ "$baseline_iam_only" -eq 1 ]; then' 'fi' "$work/baseline-job.sh"
awk '
	/case "\$BASELINE_IAM_ONLY" in$/ { copying=1 }
	copying { sub(/^          /, ""); print; if ($0 == "export GOAUTHY_113_BASELINE_IAM_ONLY") { found=1; exit } }
	END { if (!found) exit 1 }
' "$root/.github/workflows/capacity-113.yml" >"$work/workflow-map.sh" || { echo 'workflow baseline mapping source anchor drift' >&2; exit 1; }
awk '/^if \[ "\$startup_only" -eq 1 \]; then$/ {b=NR} /^start_ms=/ {s=NR} /kubectl.*apply.*driver-job\.yaml/ {d=NR} END {exit !(b>0 && s>b && d>s)}' "$harness" ||
	{ echo 'startup-only must precede scheduling and workload' >&2; exit 1; }
grep -Fq 'baseline_iam_only:' "$root/.github/workflows/capacity-113.yml" || { echo 'workflow baseline-IAM-only input missing' >&2; exit 1; }
grep -Fq 'Baseline IAM-only diagnostic; not a qualification' "$root/.github/workflows/capacity-113.yml" || { echo 'workflow diagnostic summary label missing' >&2; exit 1; }
pods() {
	jq -nc --argjson n "$1" --argjson r "$2" --argjson k "$3" --argjson h "$4" '
		{items:[range(0;$n)|{status:{containerStatuses:((if $h then [{name:"goauthy",ready:$r,restartCount:$k}] else [] end)+[{name:"sidecarfixture",ready:true,restartCount:0}])}}]}'
}
mkdir "$work/stubs"
printf '#!/bin/sh\ncat "$GOAUTHY_113_TEST_PODS"\n' >"$work/stubs/kubectl"
chmod 755 "$work/stubs/kubectl"
# DESC MODE EXIT PODS WORKLOAD CAPTURE
run() {
	printf '%s' "$4" >"$work/pods.json"
	rm -f "$work/capture.ran"
	{ echo 'set -eu'; echo "startup_only=$2"; echo 'context=k'; echo 'namespace=goauthy'
		echo 'runner_completed=false'
		echo "capture_failure_state() { : >\"$work/capture.ran\"; }"
		cat "$work/branch.sh"; echo 'echo WORKLOAD_SENTINEL'; } >"$work/driver.sh"
	status=0
	out=$(PATH="$work/stubs:$PATH" GOAUTHY_113_TEST_PODS="$work/pods.json" sh "$work/driver.sh" 2>&1) || status=$?
	case "$out" in *WORKLOAD_SENTINEL*) wl=1 ;; *) wl=0 ;; esac
	cap=0
	[ ! -e "$work/capture.ran" ] || cap=1
	if [ "$status" = "$3" ] && [ "$wl" = "$5" ] && [ "$cap" = "$6" ]; then
		ok "$1"
	else
		bad "$1 (status=$status/$3 workload=$wl/$5 capture=$cap/$6)"
	fi
}
for v in 0 1; do
	if ( GOAUTHY_113_STARTUP_ONLY=$v; . "$work/validate.sh" ) >/dev/null 2>&1; then ok "validation accepts $v"; else bad "validation rejects $v"; fi
done
if ( GOAUTHY_113_STARTUP_ONLY=2x; . "$work/validate.sh" ) >/dev/null 2>&1; then bad 'invalid mode accepted'; else ok 'invalid mode rejected'; fi
if ( unset GOAUTHY_113_STARTUP_ONLY; . "$work/validate.sh"; [ "$startup_only" = 0 ] ) >/dev/null 2>&1; then ok 'unset defaults to 0'; else bad 'unset default'; fi
mode_check() {
	startup=$1
	baseline=$2
	expected=$3
	status=0
	out=$(GOAUTHY_113_STARTUP_ONLY="$startup" GOAUTHY_113_BASELINE_IAM_ONLY="$baseline" sh -c '. "$1"; . "$2"; [ "$startup_only:$baseline_iam_only" = "$3" ]' sh "$work/validate.sh" "$work/baseline-validate.sh" "$expected" 2>&1) || status=$?
	if [ "$status" -eq 0 ]; then ok "mode $startup/$baseline accepted"; else bad "mode $startup/$baseline rejected ($out)"; fi
}
mode_check 0 0 0:0
mode_check 0 1 0:1
mode_check 1 0 1:0
if ( GOAUTHY_113_STARTUP_ONLY=1 GOAUTHY_113_BASELINE_IAM_ONLY=1; . "$work/validate.sh"; . "$work/baseline-validate.sh" ) >/dev/null 2>&1; then bad 'mutually exclusive modes accepted together'; else ok 'mutually exclusive modes rejected'; fi
if ( GOAUTHY_113_STARTUP_ONLY=0 GOAUTHY_113_BASELINE_IAM_ONLY=2x; . "$work/validate.sh"; . "$work/baseline-validate.sh" ) >/dev/null 2>&1; then bad 'invalid baseline mode accepted'; else ok 'invalid baseline mode rejected'; fi
workflow_mode_check() {
	startup=$1
	baseline=$2
	expected=$3
	status=0
	result=$(BASELINE_IAM_ONLY="$baseline" GOAUTHY_113_STARTUP_ONLY="$startup" sh -c '. "$1"; printf "%s:%s" "$GOAUTHY_113_STARTUP_ONLY" "$GOAUTHY_113_BASELINE_IAM_ONLY"' sh "$work/workflow-map.sh" 2>/dev/null) || status=$?
	if [ "$status" -eq 0 ] && [ "$result" = "$expected" ]; then ok "workflow maps $startup/$baseline to $expected"; else bad "workflow mapping $startup/$baseline"; fi
}
workflow_mode_check 0 false 0:0
workflow_mode_check 0 true 0:1
status=0
BASELINE_IAM_ONLY=yes GOAUTHY_113_STARTUP_ONLY=0 sh "$work/workflow-map.sh" >/dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && ok 'workflow rejects non-boolean input' || bad 'workflow accepted non-boolean input'
if ( BASELINE_IAM_ONLY=true GOAUTHY_113_STARTUP_ONLY=1 . "$work/workflow-map.sh" ) >/dev/null 2>&1; then bad 'workflow accepted conflicting diagnostic modes'; else ok 'workflow rejects conflicting diagnostic modes'; fi

mkdir -p "$work/job-stubs"
jq -nc '{apiVersion:"batch/v1",kind:"Job",metadata:{name:"isolation113-driver",namespace:"goauthy"},spec:{template:{spec:{containers:[{name:"driver",args:["-test.run=^TestConnectionUseGrantLive$","-test.timeout=240s","-test.v"],env:[{name:"keep",value:"unchanged"}]},{name:"fixture",args:["fixture-arg"]}]}}}}' >"$work/job.json"
cat >"$work/job-stubs/kubectl" <<'STUB'
#!/bin/sh
for arg do
	if [ "$arg" = apply ]; then printf '%s\n' "$*" >>"$GOAUTHY_TEST_APPLY_ATTEMPTS"; break; fi
done
case "$*" in
	*'create --dry-run=client'*)
		case "$GOAUTHY_TEST_KUBECTL_MODE" in
			valid) cat "$GOAUTHY_TEST_JOB_JSON" ;;
			producer-exit) cat "$GOAUTHY_TEST_JOB_JSON"; exit 17 ;;
			trailing-malformed) cat "$GOAUTHY_TEST_JOB_JSON"; printf '{malformed' ;;
			multiple-docs) cat "$GOAUTHY_TEST_JOB_JSON"; cat "$GOAUTHY_TEST_JOB_JSON" ;;
			wrong-kind) jq '.kind="ConfigMap"' "$GOAUTHY_TEST_JOB_JSON" ;;
			missing-driver) jq 'del(.spec.template.spec.containers[] | select(.name=="driver"))' "$GOAUTHY_TEST_JOB_JSON" ;;
			duplicate-driver) jq '.spec.template.spec.containers += [.spec.template.spec.containers[] | select(.name=="driver")]' "$GOAUTHY_TEST_JOB_JSON" ;;
			*) exit 92 ;;
		esac ;;
	*'apply '*)
		apply_file=
		want_file=0
		for arg do
			if [ "$want_file" -eq 1 ]; then apply_file=$arg; break; fi
			[ "$arg" = -f ] && want_file=1
		done
		case "$apply_file" in
			-) cat >"$GOAUTHY_TEST_APPLIED_JOB"; printf 'stdin\n' >>"$GOAUTHY_TEST_APPLY_MODE" ;;
			"$GOAUTHY_TEST_SELECTED_JOB") cat "$apply_file" >"$GOAUTHY_TEST_APPLIED_JOB"; printf 'selected\n' >>"$GOAUTHY_TEST_APPLY_MODE" ;;
			deploy/kind-saas-isolation-113/driver-job.yaml) printf 'original\n' >>"$GOAUTHY_TEST_APPLY_MODE" ;;
			*) exit 91 ;;
		esac ;;
	*) exit 91 ;;
esac
STUB
chmod 755 "$work/job-stubs/kubectl"
run_job_apply() {
	mode=$1
	producer_mode=$2
	mutation=${3:-}
	rm -f "$work/applied-job.json" "$work/apply-mode" "$work/apply-attempts" "$work/baseline-driver-job.json" "$work/baseline-driver-job-selected.json"
	job_branch=$work/baseline-job.sh
	case "$mutation" in
		unknown-apply)
			awk '
				{ print }
				index($0, "baseline driver Job dry-run failed; refusing to apply") {
					print "\t\tkubectl --context test-context -n goauthy apply -f missing"
					injected++
				}
				END { if (injected != 1) exit 1 }
			' "$job_branch" >"$work/baseline-job-mutant.sh" || return 1
			job_branch=$work/baseline-job-mutant.sh ;;
		stdin-apply) sed 's@apply -f "$baseline_job_selected"@apply -f -@' "$job_branch" >"$work/baseline-job-mutant.sh"; job_branch=$work/baseline-job-mutant.sh ;;
	esac
	{ echo 'set -eu'; echo "baseline_iam_only=$mode"; echo 'context=test-context'; echo 'namespace=goauthy'; echo "temp_dir=$work"; cat "$job_branch"; } >"$work/apply-driver.sh"
	if PATH="$work/job-stubs:$PATH" GOAUTHY_TEST_JOB_JSON="$work/job.json" GOAUTHY_TEST_APPLIED_JOB="$work/applied-job.json" GOAUTHY_TEST_APPLY_MODE="$work/apply-mode" GOAUTHY_TEST_APPLY_ATTEMPTS="$work/apply-attempts" GOAUTHY_TEST_SELECTED_JOB="$work/baseline-driver-job-selected.json" GOAUTHY_TEST_KUBECTL_MODE="$producer_mode" sh "$work/apply-driver.sh" </dev/null >/dev/null 2>&1; then return 0; else return 1; fi
}
selected_apply_only() {
	[ "$(wc -l <"$work/apply-attempts" | tr -d ' ')" = 1 ] &&
	[ "$(cat "$work/apply-attempts")" = "--context test-context -n goauthy apply -f $work/baseline-driver-job-selected.json" ] &&
	[ "$(cat "$work/apply-mode")" = selected ]
}
if run_job_apply 1 valid && selected_apply_only && jq -e '.spec.template.spec.containers[]|select(.name=="driver")|.args==["-test.run=^TestConnectionUseGrantLive$/^baseline-iam-","-test.timeout=240s","-test.v"]' "$work/applied-job.json" >/dev/null && jq -e '.spec.template.spec.containers[]|select(.name=="driver")|.env==[{name:"keep",value:"unchanged"}]' "$work/applied-job.json" >/dev/null && jq -e '.spec.template.spec.containers[]|select(.name=="fixture")|.args==["fixture-arg"]' "$work/applied-job.json" >/dev/null; then ok 'baseline mode applies only the exact selected file once and preserves other Job fields'; else bad 'baseline Job selector, apply path, attempt count, or preservation'; fi
if run_job_apply 1 valid stdin-apply && selected_apply_only; then bad 'positive oracle accepted apply from stdin'; else ok 'positive oracle rejects apply from stdin'; fi
if run_job_apply 0 valid && [ "$(wc -l <"$work/apply-attempts" | tr -d ' ')" = 1 ] && [ "$(cat "$work/apply-attempts")" = '--context test-context -n goauthy apply -f deploy/kind-saas-isolation-113/driver-job.yaml' ] && [ "$(cat "$work/apply-mode")" = original ] && [ ! -e "$work/applied-job.json" ]; then ok 'default mode applies the original Job manifest unchanged'; else bad 'default Job path changed'; fi
reject_before_apply() {
	status=0
	run_job_apply 1 "$1" "${2:-}" || status=$?
	[ "$status" -ne 0 ] && [ ! -e "$work/apply-attempts" ] && [ ! -e "$work/apply-mode" ]
}
for producer_mode in producer-exit trailing-malformed multiple-docs wrong-kind missing-driver duplicate-driver; do
	if reject_before_apply "$producer_mode"; then ok "baseline rejects $producer_mode before apply"; else bad "baseline attempted apply for invalid dry-run output: $producer_mode"; fi
done
if reject_before_apply producer-exit unknown-apply; then bad 'negative assertion accepted unknown apply argv'; else ok 'same negative assertion fails on unknown apply argv'; fi
run 'default reaches workload without capture' 0 0 "$(pods 3 true 0 true)" 1 0
run 'boot-only captures and stops before workload' 1 0 "$(pods 3 true 0 true)" 0 1
run 'restart rejected' 1 1 "$(pods 3 true 1 true)" 0 1
run 'not ready rejected' 1 1 "$(pods 3 false 0 true)" 0 1
run 'missing app rejected' 1 1 "$(pods 3 true 0 false)" 0 1
run 'missing pod rejected' 1 1 "$(pods 2 true 0 true)" 0 1
run 'malformed status rejected' 1 1 '{"items":[{}, {}, {}]}' 0 1
echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
