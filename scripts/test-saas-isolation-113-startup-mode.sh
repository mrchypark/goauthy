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
awk '/^if \[ "\$startup_only" -eq 1 \]; then$/ {b=NR} /^start_ms=/ {s=NR} /kubectl.*apply.*driver-job\.yaml/ {d=NR} END {exit !(b>0 && s>b && d>s)}' "$harness" ||
	{ echo 'startup-only must precede scheduling and workload' >&2; exit 1; }
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
run 'default reaches workload without capture' 0 0 "$(pods 3 true 0 true)" 1 0
run 'boot-only captures and stops before workload' 1 0 "$(pods 3 true 0 true)" 0 1
run 'restart rejected' 1 1 "$(pods 3 true 1 true)" 0 1
run 'not ready rejected' 1 1 "$(pods 3 false 0 true)" 0 1
run 'missing app rejected' 1 1 "$(pods 3 true 0 false)" 0 1
run 'missing pod rejected' 1 1 "$(pods 2 true 0 true)" 0 1
run 'malformed status rejected' 1 1 '{"items":[{}, {}, {}]}' 0 1
echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
