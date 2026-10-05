#!/bin/sh
# DIAGNOSTIC ONLY private-scope variant of the existing #113 capacity campaign.
#
# Derived from the existing e2e and wrapper scripts without editing either one.
# The FULL e2e workload/capture/summary and the full wrapper results are kept:
# the only functional addition is a diagnostic OTLP collector (built from the
# cached host binary of scripts/iam-trace-collector-src) plus a trace-endpoint
# env var composed into the SAME metrics overlay BEFORE the first profile apply.
#
# Modes:
#   --derive-only EVIDENCE_DIR RESULTS_DIR
#       Pure shell/AWK generator. Runs BEFORE any Go, Docker, cluster or network
#       action, so the derived scripts can be inspected and tested offline.
#       Leaves the generated scratch in place for inspection.
#   EVIDENCE_DIR RESULTS_DIR
#       Full recording run. Linux/native-Go/4-logical-CPU preconditions are
#       enforced before the collector launcher is invoked.
#
# This extra tracing resource is DIAGNOSTIC ONLY. It is never a qualification,
# performance or production claim. A failing campaign exit code is the expected
# source performance failure: the recording is still produced and that code is
# preserved, never converted into a pass. An incomplete diagnostic is non-zero
# even when the campaign itself passed.
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

derive_only=0
if [ "${1:-}" = --derive-only ]; then
  derive_only=1
  shift
fi

[ "$#" -eq 2 ] || {
  echo 'usage: run-capacity-113-ci-trace-diagnostic.sh [--derive-only] EVIDENCE_DIR RESULTS_DIR' >&2
  exit 2
}
[ ! -e "$1" ] || { echo 'evidence must be a new path' >&2; exit 1; }
[ -d "$2" ] || { echo 'results dir must already exist' >&2; exit 2; }

# Owned per-run scratch inside the caller-private results parent. Never uploaded:
# the workflow upload lists explicit result file names only. --derive-only keeps
# it for inspection; the full run removes exactly this owned directory.
scratch=$(mktemp -d "$2/derive.XXXXXX")
if [ "$derive_only" -eq 1 ]; then
  echo "diagnostic: derive-only scratch kept at $scratch"
else
  trap 'rm -rf "$scratch"' 0
fi
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# ---------------------------------------------------------------- collector
# Owned, single-container, ClusterIP-only diagnostic collector. No host port, no
# extra capabilities, read-only rootfs, owned emptyDir with the profile's 65532
# fsGroup, diagnostic-only 100m/64Mi. Both policies are additive and narrow: the
# collector ingress allows only GoAuthy pods on 4318, and the GoAuthy egress adds
# only the collector on 4318. The namespace default-deny and the existing
# goauthy-ingress DNS/Versity/peer entries are relied on as-is and not restated.
collector_image=iam-trace-collector:diagnostic113
cat >"$scratch/collector.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: isolation113-trace-collector
  namespace: goauthy
  labels:
    app.kubernetes.io/name: isolation113-trace-collector
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: isolation113-trace-collector
  template:
    metadata:
      labels:
        app.kubernetes.io/name: isolation113-trace-collector
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: isolation113-trace-collector
          image: iam-trace-collector:diagnostic113
          args: ["--listen", "0.0.0.0:4318", "--output", "/data/traces.jsonl"]
          ports:
            - name: otlp-http
              containerPort: 4318
          readinessProbe:
            tcpSocket:
              port: 4318
            periodSeconds: 2
            failureThreshold: 30
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 64Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            privileged: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: isolation113-trace
  namespace: goauthy
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: isolation113-trace-collector
  ports:
    - name: otlp-http
      port: 4318
      targetPort: 4318
---
# Ingress: only goauthy-labelled pods may reach the collector on 4318.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolation113-trace-allow
  namespace: goauthy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: isolation113-trace-collector
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: goauthy
      ports:
        - protocol: TCP
          port: 4318
---
# Egress: separate scoped policy, goauthy pods -> collector 4318 ONLY. This is
# required, not optional: the namespace default-deny selects Egress, so a policy
# for the same pods must state the collector destination explicitly. Existing
# policies are untouched and no other destination is added.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolation113-trace-egress
  namespace: goauthy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: goauthy
  policyTypes: ["Egress"]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: isolation113-trace-collector
      ports:
        - protocol: TCP
          port: 4318
YAML
chmod 600 "$scratch/collector.yaml"

# ------------------------------------------------------------------ e2e derive
# Five exactly-once anchors, all fail-closed on drift:
#   1 node-pins source line
#   2 script_dir assignment
#   3 profile_root assignment
#   4 metrics token env anchor (the compose point for the trace endpoint)
#   5 the single profile apply line
awk -v root="$root" -v scratch="$scratch" -v img="$collector_image" '
  BEGIN {
    q=sprintf("%c",39)
    dp=scratch "/collector-context/Dockerfile"
    dc=scratch "/collector-context"
    yml=scratch "/collector.yaml"
  }
  $0 == ". \"$(dirname -- \"$0\")/e2e-kind-saas-isolation-113-node-pins.sh\"" {
    print ". \"" root "/scripts/e2e-kind-saas-isolation-113-node-pins.sh\""
    pins++
    next
  }
  $0 == "script_dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)" {
    print "script_dir=" root "/scripts"
    dirs++
    next
  }
  $0 == "profile_root=$(CDPATH=" q q " cd -- \"$(dirname -- \"$0\")/..\" && pwd)" {
    print "profile_root=" root
    profiles++
    next
  }
  # Trace endpoint composed into the SAME metrics overlay, before the first
  # apply. A post-apply spec.template mutation would roll the StatefulSet Pods
  # and discard the data emptyDir holding cluster member identity.
  index($0, "cat >\"$temp_dir/metrics-overlay/metrics-enable-patch.json\"") { overlay_header++ }
  index($0, "{\"name\":\"GOAUTHY_METRICS_TOKEN_FILE\",\"value\":\"/run/metrics-token/token\"}") {
    if (index($0, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) exit 1
    sub("{\"name\":\"GOAUTHY_METRICS_TOKEN_FILE\",\"value\":\"/run/metrics-token/token\"}",
        "{\"name\":\"GOAUTHY_METRICS_TOKEN_FILE\",\"value\":\"/run/metrics-token/token\"},{\"name\":\"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT\",\"value\":\"http://isolation113-trace.goauthy.svc.cluster.local:4318/v1/traces\"}")
    otel++
  }
  $0 == "kubectl --context \"$context\" apply -f \"$temp_dir/profile.yaml\"" {
    # --load keeps the image in the local Docker store so `kind load` can find
    # it; without an explicit output the docker-container driver silently
    # exports nothing and the Kind load fails with "image not present locally".
    print "docker build --quiet --load -t " img " -f " dp " " dc " >/dev/null || { echo " q "diagnostic: collector image build failed" q " >&2; exit 1; }"
    print "docker image inspect " img " >/dev/null 2>&1 || { echo " q "diagnostic: collector image missing from local Docker" q " >&2; exit 1; }"
    print "kind load docker-image " img " --name \"$KIND_CLUSTER\" >/dev/null || { echo " q "diagnostic: collector image load failed" q " >&2; exit 1; }"
    print "kubectl --context \"$context\" -n \"$namespace\" apply -f " yml " >/dev/null || { echo " q "diagnostic: collector apply failed" q " >&2; exit 1; }"
    print "kubectl --context \"$context\" -n \"$namespace\" rollout status deployment/isolation113-trace-collector --timeout=120s || { echo " q "diagnostic: collector not ready" q " >&2; exit 1; }"
    print "echo " q "diagnostic: collector ready (tracing is DIAGNOSTIC ONLY; final campaign keeps tracing disabled)" q " >&2"
    print ""
    applied++
    print
    next
  }
  { print }
  END { if (pins != 1 || dirs != 1 || profiles != 1 || otel != 1 || applied != 1 || overlay_header != 1) exit 1 }
' "$root/scripts/e2e-kind-saas-isolation-113.sh" >"$scratch/e2e.sh" || {
  echo 'diagnostic: e2e source drift' >&2
  exit 1
}

# -------------------------------------------------------------- wrapper derive
# The e2e call anchor and summarize_results are matched as contiguous blocks, so
# the KIND_CLUSTER inline export that precedes the call and the summarize call
# that follows it are asserted together. Deriving does not restate them.
awk -v root="$root" -v e2e="$scratch/e2e.sh" -v ev='$evidence_dir' -v agg='$2/isolation113-stage-aggregate.json' -v crit='$2/criterion.json' -v summ="$root/scripts/summarize-isolation113-stage-aggregate.sh" '
  BEGIN { q=sprintf("%c",39) }
  $0 == "root=$(CDPATH=" q q " cd -- \"$(dirname -- \"$0\")/..\" && pwd)" {
    print "root=" root
    roots++
    next
  }
  $0 == "summarize_results" {
    summaries++
    print
    next
  }
  $0 == "\t\"$root/scripts/e2e-kind-saas-isolation-113.sh\" || runner_status=$?" {
    print "\t\"" e2e "\" || runner_status=$?"
    # Diagnostic capture happens here, inside the child wrapper, before its own
    # cleanup trap tears the cluster down. A fixed short settle window only: no
    # workload retry, no deadline change, no gate change.
    print "sleep 6  # diagnostic only: settle window for the async exporter final batch"
    print "if kubectl --request-timeout=5s --context \"$context\" -n goauthy exec deploy/isolation113-trace-collector -c isolation113-trace-collector -- cat /data/traces.jsonl >\"" ev "/auth-traces.jsonl.part\" 2>/dev/null && [ -s \"" ev "/auth-traces.jsonl.part\" ]; then"
    print "\tchmod 600 \"" ev "/auth-traces.jsonl.part\" && mv \"" ev "/auth-traces.jsonl.part\" \"" ev "/auth-traces.jsonl\" || echo \"capacity-113-ci: warning: diagnostic auth traces could not be stored\" >&2"
    print "else"
    print "\t[ ! -e \"" ev "/auth-traces.jsonl.part\" ] || rm \"" ev "/auth-traces.jsonl.part\""
    print "\techo \"capacity-113-ci: warning: diagnostic auth traces are MISSING in this run; tracing evidence is diagnostic only and must not be read as a pass\" >&2"
    print "fi"
    calls++
    next
  }
  { print }
  END { if (roots != 1 || summaries != 1 || calls != 1) exit 1 }
' "$root/scripts/run-capacity-113-ci.sh" >"$scratch/wrapper.sh" || {
  echo 'diagnostic: wrapper source drift' >&2
  exit 1
}

# Verify the single-line exports and the e2e guard before any runtime action.
awk '
  $0 == "KIND_CLUSTER=\"$KIND_CLUSTER\" \\" { cluster++ }
  $0 == "ISOLATION113_EVIDENCE_DIR=\"$evidence_dir\" \\" { evidence++ }
  $0 == "summarize_results" { summaries++ }
  END { if (cluster != 1 || evidence != 1 || summaries != 1) exit 1 }
' "$scratch/wrapper.sh" || { echo 'diagnostic: wrapper export/summary source drift' >&2; exit 1; }
awk '
  index($0, ": \"${KIND_CLUSTER:?") { guards++ }
  END { if (guards != 1) exit 1 }
' "$root/scripts/e2e-kind-saas-isolation-113.sh" || { echo 'diagnostic: e2e cluster guard source drift' >&2; exit 1; }

# Offline anchor assertions over the derived e2e script.
derived_e2e_anchor_count() {
  awk -v pattern="$1" -v expected="$2" -v label="$3" '
    index($0, pattern) { n++ }
    END { if (n != expected) exit 1 }
  ' "$scratch/e2e.sh" || {
    echo "diagnostic: derived e2e $label anchor count is not $expected" >&2
    exit 1
  }
}
derived_e2e_anchor_count 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT' 1 'trace endpoint'
derived_e2e_anchor_count 'isolation113-trace-collector --timeout=120s' 1 'collector readiness'
derived_e2e_anchor_count 'collector image load failed' 1 'collector kind load'

# Ordering: the compose point must precede the single profile apply, and nothing
# may patch the StatefulSet template after that apply.
compose_line=$(awk 'index($0, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") { print NR; exit }' "$scratch/e2e.sh")
apply_line=$(awk 'index($0, "apply -f \"$temp_dir/profile.yaml\"") { print NR; exit }' "$scratch/e2e.sh")
[ -n "$compose_line" ] && [ -n "$apply_line" ] && [ "$compose_line" -lt "$apply_line" ] || {
  echo 'diagnostic: trace endpoint must be composed before the first profile apply' >&2
  exit 1
}
if awk 'NR > '"$apply_line"' && index($0, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") { found = 1 } END { exit(found ? 0 : 1) }' "$scratch/e2e.sh"; then
  echo 'diagnostic: trace endpoint must not appear after the profile apply' >&2
  exit 1
fi

# Frozen diagnostic resource budget, asserted against the generated manifest.
collector_limit_checks() {
  awk -v file="$1" '
    BEGIN { ro = 0; nonroot = 0; fsg = 0; cpus = 0; mem = 0 }
    /cpu: 100m$/ { cpus++ }
    /memory: 64Mi$/ { mem++ }
    /readOnlyRootFilesystem: true/ { ro++ }
    /runAsNonRoot: true/ { nonroot++ }
    /fsGroup: 65532/ { fsg++ }
    END { if (cpus != 2 || mem != 2 || ro != 1 || nonroot != 1 || fsg != 1) exit 1 }
  ' "$1"
}
collector_limit_checks "$scratch/collector.yaml" || {
  echo 'diagnostic: collector resource/security budget is not the frozen 100m/64Mi non-root read-only shape' >&2
  exit 1
}

chmod 700 "$scratch/e2e.sh" "$scratch/wrapper.sh"
sh -n "$scratch/e2e.sh"
sh -n "$scratch/wrapper.sh"

if [ "$derive_only" -eq 1 ]; then
  exit 0
fi

# ------------------------------------------------------- runtime preconditions
# Enforced only on the full recording path, and only AFTER all derivation and
# offline inspection above, so the derive mode needs neither Go nor Docker.
[ "$(uname -s)" = Linux ] || { echo 'diagnostic: the recording path requires a Linux runner' >&2; exit 2; }
host_arch=$(uname -m)
case "$host_arch" in
x86_64) host_goarch=amd64 ;;
aarch64 | arm64) host_goarch=arm64 ;;
*) echo "diagnostic: unsupported runner arch $host_arch" >&2; exit 2 ;;
esac
[ "$(go env GOOS)" = linux ] || { echo 'diagnostic: GOOS must be linux for the collector image' >&2; exit 2; }
[ "$(go env GOARCH)" = "$host_goarch" ] || { echo 'diagnostic: GOARCH must match the runner arch' >&2; exit 2; }
logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '')
case "$logical_cpus" in
'' | *[!0-9]*) echo 'diagnostic: cannot determine logical CPU count' >&2; exit 2 ;;
esac
[ "$logical_cpus" -eq 4 ] || {
  echo "diagnostic: this recording is defined for exactly4 logical CPUs, found $logical_cpus" >&2
  exit 2
}

# ------------------------------------------------------- collector binary/image
collector_bin=$("$root/scripts/iam-trace-collector" --print-bin)
[ -x "$collector_bin" ] || { echo 'diagnostic: cached collector binary is not executable' >&2; exit 1; }
context=$scratch/collector-context
mkdir -p "$context"
cp "$collector_bin" "$context/iam-trace-collector"
chmod 755 "$context/iam-trace-collector"
# Pinned runtime base; busybox provides cat for the existing kubectl capture.
cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY iam-trace-collector /usr/local/bin/iam-trace-collector
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/iam-trace-collector"]
DOCKERFILE

GOAUTHY_LOCAL_BUILD=1
GOAUTHY_CANDIDATE_SOURCE=${GOAUTHY_CANDIDATE_SOURCE:-}
if [ -z "$GOAUTHY_CANDIDATE_SOURCE" ]; then
  echo 'diagnostic: GOAUTHY_CANDIDATE_SOURCE must be set to the exact reviewed diagnostic SHA' >&2
  exit 2
fi
export GOAUTHY_LOCAL_BUILD GOAUTHY_CANDIDATE_SOURCE

# The recording is source-build only on this side branch: no immutable image is
# consumed, so candidate_image is irrelevant here.
set +e
sh "$scratch/wrapper.sh" "$1" "$2"
campaign_rc=$?
set -e

# The aggregate runs AFTER the child wrapper has exited, so the criterion file it
# cross-references already exists. The aggregator exit status is not discarded:
# the campaign result stays the primary signal and an incomplete diagnostic is
# non-zero even when the campaign passed.
aggregate="$2/isolation113-stage-aggregate.json"
set +e
"$root/scripts/summarize-isolation113-stage-aggregate.sh" "$1/auth-traces.jsonl" "$aggregate" "$campaign_rc" "$2/criterion.json"
diagnostic_rc=$?
set -e

if [ "$campaign_rc" -ne 0 ]; then
  exit "$campaign_rc"
fi
if [ "$diagnostic_rc" -ne 0 ]; then
  echo "diagnostic: campaign passed but the recording is INCOMPLETE (aggregator status $diagnostic_rc); unresolved, never a pass" >&2
  exit "$diagnostic_rc"
fi
exit 0
