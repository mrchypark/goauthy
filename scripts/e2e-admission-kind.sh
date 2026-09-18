#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18080}"
: "${KIND_CLUSTER:=goauthy-admission-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl curl go kustomize grep; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null && { echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; }
temp_dir=$(mktemp -d); created=false; f0=; f1=
cleanup() {
	status=$?; trap - 0 1 2 15
	for pid in "$f0" "$f1"; do [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true; done
	for pid in "$f0" "$f1"; do [ -n "$pid" ] && wait "$pid" 2>/dev/null || true; done
	if [ "$created" = true ]; then kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true; fi
	rm -rf "$temp_dir"; e2e_port_lock_release; exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire
docker build --tag "$GOAUTHY_IMAGE" .
created=true
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"
context=kind-$KIND_CLUSTER
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password \
	--dry-run=client -o yaml >"$temp_dir/secrets.yaml"
kubectl --context "$context" apply -f "$temp_dir/secrets.yaml"
kustomize build deploy/kind-admission >"$temp_dir/admission.yaml"
sed "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" "$temp_dir/admission.yaml" >"$temp_dir/admission-rendered.yaml"
kubectl --context "$context" apply -f "$temp_dir/admission-rendered.yaml"
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/f0" 2>&1 & f0=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/f1" 2>&1 & f1=$!
until grep -q '^Forwarding from 127.0.0.1:' "$temp_dir/f0" && grep -q '^Forwarding from 127.0.0.1:' "$temp_dir/f1"; do kill -0 "$f0"; kill -0 "$f1"; sleep 0.1; done
GOAUTHY_E2E_ADMISSION=before GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestAdmissionBeforeReplacement$'
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod/goauthy-1 -o jsonpath='{.metadata.uid}')
kill "$f1" >/dev/null 2>&1 || true; wait "$f1" 2>/dev/null || true; f1=
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod/goauthy-1 --wait=true
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-1 --timeout=180s
new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod/goauthy-1 -o jsonpath='{.metadata.uid}')
[ "$old_uid" != "$new_uid" ]
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/f1-replaced" 2>&1 & f1=$!
until grep -q '^Forwarding from 127.0.0.1:' "$temp_dir/f1-replaced"; do kill -0 "$f1"; sleep 0.1; done
GOAUTHY_E2E_ADMISSION=after GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestAdmissionAfterReplacement$'
