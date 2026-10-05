#!/bin/sh
# Focused offline controls for the derive and drift guards of
# scripts/run-capacity-113-ci-trace-diagnostic.sh.
#
# The runner is exercised only in its --derive-only mode, which is pure shell and
# AWK and runs before any Go, Docker, cluster or network action. Fixtures are
# copies of the owned runner plus the qualification wrapper and e2e sources in a
# temporary repository. PATH is reduced to a stub directory first, so any drift
# failure is proven to happen BEFORE an external tool could run: every stub exits
# 91 and appends its own name to a log.
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$root/scripts/e2e-kind-saas-isolation-113.sh" ] || { echo 'missing e2e source' >&2; exit 1; }
[ -f "$root/scripts/run-capacity-113-ci.sh" ] || { echo 'missing wrapper source' >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

checks=0
fail() {
  echo "FAIL: $1" >&2
  exit 1
}
ok() {
  checks=$((checks + 1))
}

stubs="$work/stubs"
mkdir -p "$stubs"
stub_log="$work/stub.log"
: >"$stub_log"
for tool in go docker kind kubectl kustomize curl git jq nc openssl tar timeout; do
  cat >"$stubs/$tool" <<STUB
#!/bin/sh
echo "$tool" >> "$stub_log"
exit 91
STUB
  chmod 755 "$stubs/$tool"
done

# make_fixture -> a fresh temporary repository with owned runner plus the two
# untouched qualification sources, returning its path.
make_fixture() {
  fixture=$(mktemp -d "$work/repo.XXXXXX")
  mkdir -p "$fixture/scripts"
  cp "$root/scripts/run-capacity-113-ci-trace-diagnostic.sh" "$fixture/scripts/"
  cp "$root/scripts/e2e-kind-saas-isolation-113.sh" "$fixture/scripts/"
  cp "$root/scripts/run-capacity-113-ci.sh" "$fixture/scripts/"
  chmod 755 "$fixture/scripts/run-capacity-113-ci-trace-diagnostic.sh"
  chmod 644 "$fixture/scripts/e2e-kind-saas-isolation-113.sh" "$fixture/scripts/run-capacity-113-ci.sh"
  printf '%s\n' "$fixture"
}

# derive FIXTURE EXPECTED_STATUS -> runs the runner in derive-only mode with a
# stubbed PATH and returns its status. Prints the scratch path when EXPECTED is
# 'keep'.
derive() {
  fixture=$1
  expected=$2
  evidence="$fixture/evidence"
  results="$fixture/results"
  mkdir -p "$results"
  [ -e "$evidence" ] || : >"$fixture/.evidence-sentinel"
  if [ -e "$evidence" ]; then rm "$evidence"; fi
  : >"$stub_log"
  set +e
  out=$(PATH="$stubs:$PATH" /bin/sh "$fixture/scripts/run-capacity-113-ci-trace-diagnostic.sh" --derive-only "$evidence" "$results" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$out" >"$work/last-output"
  if [ "$expected" != keep ]; then
    [ "$status" = "$expected" ] || {
      cat "$work/last-output" >&2
      fail "derive status $status, expected $expected"
    }
  fi
  # No external tool may run before a drift failure.
  if [ -s "$stub_log" ]; then
    cat "$stub_log" >&2
    fail "an external tool was invoked: the drift guard must fail first"
  fi
  if [ "$expected" != 0 ]; then
    return 0
  fi
  scratch=$(printf '%s\n' "$out" | sed -n 's/^diagnostic: derive-only scratch kept at //p' | tail -n 1)
  [ -n "$scratch" ] || fail 'derive-only must report its scratch path'
  [ -d "$scratch" ] || fail 'derive-only must leave the generated scratch in place'
  printf '%s\n' "$scratch"
}

# ------------------------------------------------------- unmodified happy path
scratch=$(make_fixture | tail -n 1)
derived=$(derive "$scratch" 0 | tail -n 1)
ok

e2e="$derived/e2e.sh"
wrapper="$derived/wrapper.sh"
[ -s "$e2e" ] || fail 'derive-only must produce e2e.sh'
[ -s "$wrapper" ] || fail 'derive-only must produce wrapper.sh'
[ -s "$derived/collector.yaml" ] || fail 'derive-only must produce the collector manifest'

# The generated scripts must still be valid shell.
/bin/sh -n "$e2e"
/bin/sh -n "$wrapper"
ok

# The collector image context is not produced in derive mode, and no external
# tool ran, so the launcher was never consulted.
[ -e "$derived/collector-context" ] && fail 'derive-only must not build the collector image context'
ok

# Endpoint appears exactly once, before the single profile apply, and never after.
endpoint_count=$(grep -Fc 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT' "$e2e")
[ "$endpoint_count" = 1 ] || fail "trace endpoint must appear exactly once, got $endpoint_count"
compose_line=$(grep -Fn 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT' "$e2e" | cut -d: -f1)
apply_line=$(grep -Fn 'apply -f "$temp_dir/profile.yaml"' "$e2e" | cut -d: -f1 | head -n 1)
[ -n "$apply_line" ] || fail 'the profile apply anchor must be present'
[ "$compose_line" -lt "$apply_line" ] || fail 'the trace endpoint must be composed before the first profile apply'
tail_endpoint=$(awk -v n="$apply_line" 'NR > n && index($0, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") { c++ } END { print c + 0 }' "$e2e")
[ "$tail_endpoint" = 0 ] || fail 'no post-apply template patch may carry the trace endpoint'
apply_count=$(grep -Fc 'apply -f "$temp_dir/profile.yaml"' "$e2e")
[ "$apply_count" = 1 ] || fail "exactly one profile apply must remain, got $apply_count"
ok

# The endpoint value is the exact service address and nothing else.
grep -Fq 'http://isolation113-trace.goauthy.svc.cluster.local:4318/v1/traces' "$e2e" || fail 'the endpoint address must be exact'
case_count=$(grep -Fc 'isolation113-trace.goauthy.svc.cluster.local:4318' "$e2e")
[ "$case_count" = 1 ] || fail "the collector address must appear exactly once, got $case_count"
ok

# No post-apply spec.template mutation is introduced anywhere.
post_apply_template=$(awk -v applied="$apply_line" 'NR > applied && index($0, "kubectl") && index($0, "patch") && index($0, "spec.template") { c++ } END { print c + 0 }' "$e2e")
[ "$post_apply_template" = 0 ] || fail 'no post-apply spec.template mutation may be introduced'
ok

# Collector readiness and load are injected, both narrow policies are preserved,
# and the diagnostic resource budget is frozen.
grep -Fq 'rollout status deployment/isolation113-trace-collector --timeout=120s' "$e2e" || fail 'collector readiness must be awaited'
grep -Fq 'kind load docker-image' "$e2e" || fail 'the collector image must be loaded into the cluster'
grep -Fq 'name: isolation113-trace-allow' "$derived/collector.yaml" || fail 'the narrow ingress policy must be present'
grep -Fq 'name: isolation113-trace-egress' "$derived/collector.yaml" || fail 'the narrow egress policy must be present'
for frozen in 'cpu: 100m' 'memory: 64Mi' 'readOnlyRootFilesystem: true' 'runAsNonRoot: true' 'fsGroup: 65532' 'type: ClusterIP' 'port: 4318'; do
  grep -Fq "$frozen" "$derived/collector.yaml" || fail "frozen collector property missing: $frozen"
done
grep -Fq 'sizeLimit: 256Mi' "$derived/collector.yaml" || fail 'the diagnostic scratch volume must have its 256Mi bound'
cpu_limits=$(grep -Fc 'cpu: 100m' "$derived/collector.yaml")
mem_limits=$(grep -Fc 'memory: 64Mi' "$derived/collector.yaml")
[ "$cpu_limits" = 2 ] || fail "collector cpu limit must be frozen, got $cpu_limits"
[ "$mem_limits" = 2 ] || fail "collector memory limit must be frozen, got $mem_limits"
policy_count=$(grep -Fc 'kind: NetworkPolicy' "$derived/collector.yaml")
[ "$policy_count" = 2 ] || fail "exactly two narrow policies expected, got $policy_count"
ok

# Upstream guard and inline export survive the derivation, and the aggregator is
# not injected into the child wrapper.
grep -Fq ': "${KIND_CLUSTER:?' "$scratch/scripts/e2e-kind-saas-isolation-113.sh" || fail 'the e2e KIND_CLUSTER required guard must exist upstream'
grep -Fq ': "${KIND_CLUSTER:?' "$e2e" || fail 'the derived e2e must keep the KIND_CLUSTER required guard'
export_count=$(grep -Fc 'KIND_CLUSTER="$KIND_CLUSTER" \' "$wrapper")
[ "$export_count" = 1 ] || fail "the inline KIND_CLUSTER export must survive exactly once, got $export_count"
summary_count=$(grep -c '^summarize_results$' "$wrapper")
[ "$summary_count" = 1 ] || fail "summarize_results must be called exactly once, got $summary_count"
if grep -Fq 'summarize-isolation113-stage-aggregate.sh' "$wrapper"; then
  fail 'the aggregator must not be injected into the child wrapper'
fi
grep -Fq 'summarize-isolation113-stage-aggregate.sh' "$scratch/scripts/run-capacity-113-ci-trace-diagnostic.sh" || fail 'the runner must own the aggregator call'
grep -Fq 'auth-traces.jsonl' "$wrapper" || fail 'raw capture must still happen inside the child wrapper'
ok

# --------------------------------------------------------------- drift controls
# Each mutation must fail closed, before any external tool, with a non-zero status.
mutate() {
  fixture=$1
  file=$2
  from=$3
  to=$4
  # Deliberate exact-line replacement using awk, so no dependency is needed.
  FILE="$fixture/scripts/$file" FROM="$from" TO="$to" awk '
    BEGIN { replaced = 0 }
    $0 == ENVIRON["FROM"] { print ENVIRON["TO"]; replaced = 1; next }
    { print }
    END { if (replaced != 1) exit 1 }
  ' "$fixture/scripts/$file" >"$fixture/scripts/$file.mutated" || fail "mutation target not found in $file"
  mv "$fixture/scripts/$file.mutated" "$fixture/scripts/$file"
}

# 1. The metrics token compose anchor moves: the endpoint can no longer be added.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  'cat >"$temp_dir/metrics-overlay/metrics-enable-patch.json" <<'"'"'JSON'"'"'' \
  'cat >"$temp_dir/other-patch.json" <<'"'"'JSON'"'"''
derive "$fixture" 1 >/dev/null
ok

# 2. The token env entry inside the patch changes shape.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  '{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"goauthy","namespace":"goauthy"},"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_METRICS_LISTEN_ADDR","value":"127.0.0.1:9090"},{"name":"GOAUTHY_METRICS_TOKEN_FILE","value":"/run/metrics-token/token"}],"volumeMounts":[{"name":"isolation113-metrics-token","mountPath":"/run/metrics-token","readOnly":true}]}],"volumes":[{"name":"isolation113-metrics-token","secret":{"secretName":"isolation113-metrics-token","defaultMode":256}}]}}}}' \
  '{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"goauthy","namespace":"goauthy"},"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_METRICS_LISTEN_ADDR","value":"127.0.0.1:9090"},{"name":"GOAUTHY_METRICS_TOKEN_FILE","value":"/run/metrics/token"}],"volumeMounts":[{"name":"isolation113-metrics-token","mountPath":"/run/metrics-token","readOnly":true}]}],"volumes":[{"name":"isolation113-metrics-token","secret":{"secretName":"isolation113-metrics-token","defaultMode":256}}]}}}}'
derive "$fixture" 1 >/dev/null
ok

# 3. The single profile apply anchor changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  'kubectl --context "$context" apply -f "$temp_dir/profile.yaml"' \
  'kubectl --context "$context" apply -f "$temp_dir/profile-renamed.yaml"'
derive "$fixture" 1 >/dev/null
ok

# 4. The node-pins source line changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  '. "$(dirname -- "$0")/e2e-kind-saas-isolation-113-node-pins.sh"' \
  '. "$(dirname -- "$0")/e2e-kind-saas-isolation-113-pins.sh"'
derive "$fixture" 1 >/dev/null
ok

# 5. script_dir assignment changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  'script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)' \
  'script_dir=$(pwd)'
derive "$fixture" 1 >/dev/null
ok

# 6. profile_root assignment changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  'profile_root=$(CDPATH='"''"' cd -- "$(dirname -- "$0")/.." && pwd)' \
  'profile_root=$(pwd)'
derive "$fixture" 1 >/dev/null
ok

# 7. The e2e invocation line in the wrapper changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" run-capacity-113-ci.sh \
  '	"$root/scripts/e2e-kind-saas-isolation-113.sh" || runner_status=$?' \
  '	"$root/scripts/e2e-kind-saas-isolation-113.sh" || true'
derive "$fixture" 1 >/dev/null
ok

# 8. summarize_results is called twice.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" run-capacity-113-ci.sh \
  'summarize_results' \
  'summarize_results; summarize_results'
derive "$fixture" 1 >/dev/null
ok

# 9. The inline KIND_CLUSTER export is removed: the derived wrapper must fail the
#    export anchor check.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" run-capacity-113-ci.sh \
  'KIND_CLUSTER="$KIND_CLUSTER" \' \
  '# KIND_CLUSTER export removed'
derive "$fixture" 1 >/dev/null
ok

# 10. The e2e KIND_CLUSTER required guard is removed.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" e2e-kind-saas-isolation-113.sh \
  ': "${KIND_CLUSTER:?set KIND_CLUSTER to the owned qualification cluster}"' \
  '# KIND_CLUSTER guard removed'
derive "$fixture" 1 >/dev/null
ok

# 11. The evidence directory export is removed.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" run-capacity-113-ci.sh \
  'ISOLATION113_EVIDENCE_DIR="$evidence_dir" \' \
  '# evidence export removed'
derive "$fixture" 1 >/dev/null
ok

# 12. The wrapper root assignment changes.
fixture=$(make_fixture | tail -n 1)
mutate "$fixture" run-capacity-113-ci.sh \
  'root=$(CDPATH='"''"' cd -- "$(dirname -- "$0")/.." && pwd)' \
  'root=$(pwd)'
derive "$fixture" 1 >/dev/null
ok

# ------------------------------------------------------------------- hygiene
# The derive path must not have created anything outside the caller results dir.
for fixture in "$work"/repo.*; do
  [ -d "$fixture" ] || continue
  [ ! -e "$fixture/evidence" ] || fail 'derive-only must not create the evidence directory'
done
# No derive output may reference the original private state directory.
if grep -Rqs '/.codex/task-state' "$work/repo."*/scripts/run-capacity-113-ci-trace-diagnostic.sh; then
  fail 'the runner must not hardcode any private state path'
fi
ok

echo "test-capacity113-trace-derive: $checks checks passed"
