#!/bin/sh
set -eu
umask 077
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$repo/scripts/e2e-kind-saas-isolation-113.sh
system_rm=$(command -v rm)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/goauthy-capture-stub.XXXXXX")
remove_temp() { "$system_rm" -rf "$run_dir"; }
trap remove_temp 0 HUP INT TERM
mkdir -m 700 "$run_dir/bin"
evidence=$run_dir/diagnostic
mkdir -m 700 "$evidence"
cat >"$run_dir/bin/kubectl" <<'KUBECTL'
#!/bin/sh
case "$*" in
	*' get pods -o json'*) printf '%s\n' '{"items":[{"metadata":{"name":"goauthy-0"},"status":{"containerStatuses":[{"containerID":"containerd://abc","lastState":{"terminated":{"exitCode":17,"reason":"Error","startedAt":"2026-10-03T00:00:00Z","finishedAt":"2026-10-03T00:00:01Z"}}}]}}]}' ;;
	*' get jobs -o json'*) printf '%s\n' '{"items":[{"metadata":{"name":"isolation113-driver"},"status":{"failed":1}}]}' ;;
	*' get events '*) echo 'injected event capture error' >&2; exit 42 ;;
	*'--previous'*) printf '%s\n' 'synthetic previous log' ;;
	*' logs pod/'*) printf '%s\n' 'synthetic current log' ;;
	*) echo 'unexpected kubectl stub call' >&2; exit 3 ;;
esac
KUBECTL
cat >"$run_dir/bin/docker" <<'DOCKER'
#!/bin/sh
case "$*" in
	*'crictl stats --all -o json'*) sleep 20 ;;
	*'crictl ps --all -o json'*) printf '%s\n' '{"containers":[{"id":"abc","state":"CONTAINER_EXITED"}]}' ;;
	*) echo 'unexpected docker stub call' >&2; exit 3 ;;
esac
DOCKER
cat >"$run_dir/bin/rm" <<'RM'
#!/bin/sh
printf '%s\n' "$*" >>"$CAPTURE_TEST_RM_LOG"
RM
chmod 700 "$run_dir/bin/"*
{
	sed -n '/^capture_failure_state() {/,/^}/p' "$runner"
	sed -n '/^cleanup() {/,/^}/p' "$runner"
	cat <<'INNER'
KIND_CLUSTER=stub-cluster
ISOLATION113_EVIDENCE_DIR=$CAPTURE_TEST_EVIDENCE
namespace=goauthy
context=kind-stub-cluster
runner_completed=false
failure_capture_done=false
sampler_pid=
forward_pid=
image_container=
temp_dir=/stub-temp
mkdir -m 700 -p "$CAPTURE_TEST_EVIDENCE/failure-capture"
mkdir -m 700 "$CAPTURE_TEST_EVIDENCE/failure-capture/goauthy-2-current.log"
trap cleanup 0
exit 23
INNER
} >"$run_dir/inner.sh"
chmod 600 "$run_dir/inner.sh"
export PATH="$run_dir/bin:$PATH" CAPTURE_TEST_EVIDENCE="$evidence" CAPTURE_TEST_RM_LOG="$run_dir/cleanup.log"
set +e
sh "$run_dir/inner.sh" >"$run_dir/inner.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 23 ] || { echo "exit status changed: $rc" >&2; exit 1; }
[ -s "$run_dir/cleanup.log" ] || { echo 'cleanup did not run' >&2; exit 1; }
jq -e '.items[0].status.containerStatuses[0].lastState.terminated.exitCode == 17' "$evidence/failure-capture/pods.json" >/dev/null
jq -e '.items[0].metadata.name == "isolation113-driver"' "$evidence/failure-capture/jobs.json" >/dev/null
jq -e '.containers[0].state == "CONTAINER_EXITED"' "$evidence/failure-capture/cri-containers-all.json" >/dev/null
grep -Fx 'synthetic previous log' "$evidence/failure-capture/goauthy-0-previous.log" >/dev/null
grep -Fx 'synthetic previous log' "$evidence/failure-capture/versity-previous.log" >/dev/null
grep -Fx 'synthetic current log' "$evidence/failure-capture/versity-current.log" >/dev/null
grep -Fx 'events.json_exit=42' "$evidence/failure-capture/capture-status.txt" >/dev/null
grep -Fx 'cri-stats-all.json_exit=124' "$evidence/failure-capture/capture-status.txt" >/dev/null
grep -Fx 'goauthy-2-current.log_exit=1' "$evidence/failure-capture/capture-status.txt" >/dev/null
grep -Fx 'capture_json_validation=failed' "$evidence/failure-capture/capture-status.txt" >/dev/null
printf '%s\n' 'stub capture check: PASS (bounded CRI hang, failed command and output write; previous GoAuthy/Versity logs retained; exit 23 and cleanup preserved)'
