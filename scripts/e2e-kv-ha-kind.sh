#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
: "${E2E_PORT:=19986}"
: "${KIND_CLUSTER:=goauthy-kv-ha-e2e-$$}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:kv-e2e-$$}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl kustomize go nc seq sed; do command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }; done
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be decimal' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65532 ] || { echo 'E2E_PORT must be between 1024 and 65532' >&2; exit 1; }
. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
temp_dir=$(mktemp -d); pids=; created=false
cleanup() { status=$?; trap - 0 1 2 15; for pid in $pids; do kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; done; [ "$created" = true ] && kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true; rm -rf "$temp_dir"; e2e_port_lock_release; exit "$status"; }
trap cleanup 0 1 2 15
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null 2>&1 && { echo "cluster exists: $KIND_CLUSTER" >&2; exit 1; }
for offset in 0 1 2; do port=$((E2E_PORT + offset)); nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && { echo "port $port is in use" >&2; exit 1; }; done
docker build --tag "$GOAUTHY_IMAGE" "$root"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s; created=true
context=kind-$KIND_CLUSTER
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
"$root/scripts/e2e-preflight.sh" kind-inotify --cluster "$KIND_CLUSTER"
api_server=$(kubectl config view --raw --minify --context "$context" -o jsonpath='{.clusters[0].cluster.server}')
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kubectl --context "$context" apply -f "$root/deploy/k8s/namespace.yaml"
phc=$(printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password")
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$phc" --from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"v0"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"v1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"v2"}]' \
	--from-literal=versity-root-user=goauthy-e2e --from-literal=versity-root-password=goauthy-e2e-versity-password
kustomize build "$root/deploy/e2e-kv-ha" | sed "s#goauthy:e2e#$GOAUTHY_IMAGE#g; s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/versity --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/versity-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
wait_exact3_ready() { kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; }
wait_exact3_ready
start_forwards() { for i in 0 1 2; do kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-$i "$((E2E_PORT+i)):8080" >"$temp_dir/$i.log" 2>&1 & pids="$pids $!"; done; }
wait_forwards() { for i in 0 1 2; do for _ in $(seq 1 120); do nc -z 127.0.0.1 "$((E2E_PORT+i))" >/dev/null 2>&1 && break; sleep 1; done; nc -z 127.0.0.1 "$((E2E_PORT+i))" >/dev/null 2>&1 || { cat "$temp_dir/$i.log" >&2; exit 1; }; done; }
run_phase() { GOAUTHY_E2E_KV=1 GOAUTHY_E2E_KV_PHASE="$1" GOAUTHY_E2E_KV_STATE="$temp_dir/kv-state.json" GOAUTHY_E2E_KV_URLS="http://localhost:$E2E_PORT,http://localhost:$((E2E_PORT+1)),http://localhost:$((E2E_PORT+2))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v "$root/test/e2e/browser" -run '^TestKVAPI$'; }
start_forwards; wait_forwards; run_phase initial
for pid in $pids; do kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; done; pids=
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
new_uid=; ready=
for _ in $(seq 1 180); do new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true); ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true); [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] && break; sleep 1; done
[ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'replacement pod was not Ready' >&2; exit 1; }
wait_exact3_ready; start_forwards; wait_forwards; run_phase post-restart
echo 'HA KV E2E passed'
