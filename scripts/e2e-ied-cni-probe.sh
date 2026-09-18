#!/bin/sh
# Bounded LIVE CNI enforcement probe on IED.
# Proves NetworkPolicy enforcement via ingress toggle on server port 8080.
# Uses pod IP directly (no DNS confound), positive control first.
# Images: nginx:1.27-alpine, busybox:1.37, digests verified via docker pull.
set -eu

CONTEXT="gke_ied-cluster"
NS="goauthy-cni-probe-0917"
PROBE_ID="cni-probe-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]')"
SERVER_IMAGE="docker.io/library/nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"
CLIENT_IMAGE="docker.io/library/busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

kubectl() { command kubectl --context "$CONTEXT" "$@"; }

# --- preflight: verify CNI enforces NetworkPolicy on cluster ---
preflight_json=$(gcloud container clusters describe ied-cluster \
  --project patch2-the-new-era --region asia-northeast3 --format=json 2>/dev/null) || {
  echo "BLOCKED: failed to describe cluster ied-cluster" >&2; exit 1
}
echo "$preflight_json" | jq -e '
  (.networkConfig.datapathProvider == "ADVANCED_DATAPATH")
  or
  (.networkPolicy.enabled == true and
   (.addonsConfig.networkPolicyConfig.disabled != true))
' > /dev/null 2>&1 || {
  dp=$(echo "$preflight_json" | jq -r '.networkConfig.datapathProvider // "null"')
  npe=$(echo "$preflight_json" | jq -r '.networkPolicy.enabled // "null"')
  ad=$(echo "$preflight_json" | jq -r '.addonsConfig.networkPolicyConfig.disabled // "null"')
  echo "BLOCKED: CNI enforcement not enabled on $CONTEXT (datapathProvider=$dp, networkPolicy.enabled=$npe, addon.disabled=$ad)" >&2
  exit 1
}

# --- helpers ---
assert_pass() {
  desc=$1; shift
  server_ip=$1; shift
  attempt=0 max=10
  while [ "$attempt" -lt "$max" ]; do
    attempt=$((attempt + 1))
    out=$(kubectl exec -n "$NS" cni-client -- wget -q -O- --timeout=2 "http://$server_ip:8080/" 2>/dev/null) && ec=0 || ec=$?
    if [ "$ec" -eq 0 ] && [ "$out" = "ok" ]; then
      echo "PASS: $desc (attempt $attempt)"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: $desc not pass after $max attempts (last ec=$ec body='$out')" >&2
  return 1
}

assert_deny() {
  desc=$1; shift
  server_ip=$1; shift
  attempt=0 max=10
  while [ "$attempt" -lt "$max" ]; do
    attempt=$((attempt + 1))
    out=$(kubectl exec -n "$NS" cni-client -- wget -q -O- --timeout=2 "http://$server_ip:8080/" 2>&1) && ec=0 || ec=$?
    if [ "$ec" -ne 0 ] && { echo "$out" | grep -Eq 'timed out|refused|Network is unreachable|No route'; }; then
      echo "PASS: $desc (attempt $attempt)"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: $desc not deny after $max attempts (last ec=$ec out='$out')" >&2
  return 1
}

# --- refuse if exists ---
if kubectl get namespace "$NS" >/dev/null 2>&1; then
  echo "refusing: namespace $NS already exists" >&2; exit 1
fi

created=false
NS_UID=""
cleanup() {
  status=$?
  trap - 0 1 2 15
  if [ "$created" = true ] && [ -n "$NS_UID" ]; then
    _del=$(mktemp)
    jq -n --arg uid "$NS_UID" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' > "$_del"
    kubectl delete namespace "$NS" --raw "/api/v1/namespaces/$NS" -f "$_del" 2>/dev/null && echo "cleaned up owned namespace $NS" || echo "WARNING: cleanup delete failed for $NS" >&2
    rm -f "$_del"
  fi
  exit "$status"
}
trap cleanup 0 1 2 15

# --- namespace ---
kubectl create -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    app.kubernetes.io/part-of: goauthy-cni-probe
    cni-probe-id: $PROBE_ID
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
EOF
created=true

vid=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.cni-probe-id}')
NS_UID=$(kubectl get namespace "$NS" -o jsonpath='{.metadata.uid}')
[ "$vid" = "$PROBE_ID" ] || { echo "FATAL: ownership label wrong: '$vid'" >&2; exit 1; }
[ -n "$NS_UID" ] || { echo "FATAL: could not read namespace UID" >&2; exit 1; }

# --- policies: default-deny + DNS + client egress 8080 ---
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: goauthy-cni-probe-0917
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: goauthy-cni-probe-0917
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-client-egress-8080
  namespace: goauthy-cni-probe-0917
spec:
  podSelector:
    matchLabels:
      app: cni-client
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: cni-server
      ports:
        - protocol: TCP
          port: 8080
EOF

# --- server ---
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
  namespace: goauthy-cni-probe-0917
data:
  nginx.conf: |
    worker_processes 1;
    error_log /dev/stderr;
    pid /tmp/nginx.pid;
    events { worker_connections 32; }
    http {
      access_log /dev/stdout;
      server {
        listen 8080;
        location / { return 200 "ok\n"; }
      }
    }
EOF

kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cni-server
  namespace: $NS
  labels:
    app: cni-server
    app.kubernetes.io/part-of: goauthy-cni-probe
    cni-probe-id: $PROBE_ID
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cni-server
  template:
    metadata:
      labels:
        app: cni-server
        app.kubernetes.io/part-of: goauthy-cni-probe
        cni-probe-id: $PROBE_ID
    spec:
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: nginx
          image: $SERVER_IMAGE
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: nginx-config
              mountPath: /etc/nginx/nginx.conf
              subPath: nginx.conf
              readOnly: true
            - name: tmp
              mountPath: /var/cache/nginx
            - name: run
              mountPath: /var/run
            - name: tmp2
              mountPath: /tmp
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
          resources:
            requests: { cpu: 10m, memory: 16Mi }
            limits: { cpu: 50m, memory: 32Mi }
      volumes:
        - name: nginx-config
          configMap:
            name: nginx-config
        - name: tmp
          emptyDir: {}
        - name: run
          emptyDir: {}
        - name: tmp2
          emptyDir: {}
EOF

# --- client ---
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: cni-client
  namespace: $NS
  labels:
    app: cni-client
    app.kubernetes.io/part-of: goauthy-cni-probe
    cni-probe-id: $PROBE_ID
spec:
  automountServiceAccountToken: false
  securityContext:
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: client
      image: $CLIENT_IMAGE
      command: ["sleep", "infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
      resources:
        requests: { cpu: 10m, memory: 16Mi }
        limits: { cpu: 50m, memory: 32Mi }
EOF

# --- service ---
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: cni-server
  namespace: $NS
  labels:
    app: cni-server
    app.kubernetes.io/part-of: goauthy-cni-probe
    cni-probe-id: $PROBE_ID
spec:
  selector:
    app: cni-server
  ports:
    - port: 8080
      targetPort: http
EOF

# --- wait ---
echo "waiting for pods..."
kubectl rollout status deployment/cni-server -n "$NS" --timeout=120s
kubectl wait --for=condition=Ready pod/cni-client -n "$NS" --timeout=120s

# --- server local readiness ---
SERVER_IP=$(kubectl get pod -n "$NS" -l app=cni-server -o jsonpath='{.items[0].status.podIP}')
CLIENT_IP=$(kubectl get pod -n "$NS" -l app=cni-client -o jsonpath='{.items[0].status.podIP}')
echo "server_ip=$SERVER_IP client_ip=$CLIENT_IP"

ready=$(kubectl exec -n "$NS" deploy/cni-server -- wget -q -O- --timeout=2 "http://127.0.0.1:8080/" 2>/dev/null) && rec=0 || rec=$?
if [ "$rec" -eq 0 ] && [ "$ready" = "ok" ]; then
  echo "server local readiness: OK"
else
  echo "FATAL: server not ready locally (ec=$rec body='$ready')" >&2
  exit 1
fi

echo ""
echo "=== pod nodes ==="
kubectl get pods -n "$NS" -o wide
echo "=== network policies ==="
kubectl get networkpolicy -n "$NS"

# --- Phase 1: positive control (allow-http present => PASS) ---
echo ""
echo "=== Phase 1: positive control (allow PASS) ==="
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-http
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      app: cni-server
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: cni-client
      ports:
        - protocol: TCP
          port: 8080
EOF

assert_pass "positive control" "$SERVER_IP"

# --- Phase 2: remove allow => DENY ---
echo ""
echo "=== Phase 2: remove allow => DENY ==="
kubectl delete networkpolicy allow-http -n "$NS"
assert_deny "remove allow => DENY" "$SERVER_IP"

# --- Phase 3: restore allow => PASS ---
echo ""
echo "=== Phase 3: restore allow => PASS ==="
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-http
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      app: cni-server
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: cni-client
      ports:
        - protocol: TCP
          port: 8080
EOF

assert_pass "restore allow => PASS" "$SERVER_IP"

echo ""
echo "=== CNI enforcement probe PASSED ==="
echo "Namespace: $NS (probe-id=$PROBE_ID)"
echo "Context: $CONTEXT"
echo "Server: $SERVER_IMAGE"
echo "Client: $CLIENT_IMAGE"
echo "Server pod IP: $SERVER_IP on $(kubectl get pod -n "$NS" -l app=cni-server -o jsonpath='{.items[0].spec.nodeName}')"
echo "Client pod IP: $CLIENT_IP on $(kubectl get pod -n "$NS" -l app=cni-client -o jsonpath='{.items[0].spec.nodeName}')"
echo ""
kubectl get networkpolicy -n "$NS"
