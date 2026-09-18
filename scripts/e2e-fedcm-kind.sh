#!/bin/sh
set -eu

for command in docker kind kubectl kustomize go openssl curl nc; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
cluster=${KIND_CLUSTER:-goauthy-fedcm-e2e}; port=${E2E_PORT:-18443}; image=${GOAUTHY_IMAGE:-goauthy:e2e}; namespace=${K8S_NAMESPACE:-goauthy}; temp=$(mktemp -d); forward=; secondary_forward=; created=false
cleanup() { status=$?; trap - 0 1 2 15; [ -z "$forward" ] || { kill "$forward" 2>/dev/null || true; wait "$forward" 2>/dev/null || true; }; [ -z "$secondary_forward" ] || { kill "$secondary_forward" 2>/dev/null || true; wait "$secondary_forward" 2>/dev/null || true; }; [ "$created" != true ] || kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$temp"; exit "$status"; }
trap cleanup 0 1 2 15
[ "${GOAUTHY_FEDCM_RUN_KIND:-}" = 1 ] || { echo 'FedCM Kind E2E source is opt-in; set GOAUTHY_FEDCM_RUN_KIND=1 to execute' >&2; exit 2; }
kind get clusters | grep -Fx "$cluster" >/dev/null && { echo "refusing to use existing kind cluster: $cluster" >&2; exit 1; }
./scripts/e2e-preflight.sh host-capacity
for offset in 0 1; do check_port=$((port + offset)); nc -z 127.0.0.1 "$check_port" >/dev/null 2>&1 && { echo "E2E host port $check_port is already in use; choose E2E_PORT" >&2; exit 1; }; done
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp/tls.key" -out "$temp/tls.crt" -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost >/dev/null 2>&1
printf '%s\n' '{"client_origins":{"rp-client":"https://rp.example.test"},"login_url":"/auth/login"}' >"$temp/fedcm.json"
docker build --tag "$image" .
kind create cluster --name "$cluster" --wait 120s; created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
kind load docker-image "$image" --name "$cluster"
kubectl --context kind-$cluster apply -f deploy/k8s/namespace.yaml
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
kubectl --context kind-$cluster -n "$namespace" create secret generic goauthy-secrets --from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=bootstrap-client=correct-horse-battery-staple --from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef --from-literal=bootstrap-user-password-phc="$browser_phc" --from-literal=rhiza-admin-token=goauthy-e2e-admin-token --from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' --from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password --from-file=fedcm-config="$temp/fedcm.json"
kubectl --context kind-$cluster -n "$namespace" create secret generic goauthy-fedcm-tls --from-file=tls.crt="$temp/tls.crt" --from-file=tls.key="$temp/tls.key"
kustomize build deploy/e2e-fedcm | sed "s#https://localhost:18443#https://localhost:$port#g" | kubectl --context kind-$cluster apply -f -
kubectl --context kind-$cluster -n "$namespace" rollout status statefulset/goauthy --timeout=180s
kubectl --context kind-$cluster -n "$namespace" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
secondary_forward=
kubectl --context kind-$cluster -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-0 "$port:8443" >"$temp/forward.log" 2>&1 & forward=$!
kubectl --context kind-$cluster -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-1 "$((port + 1)):8443" >"$temp/secondary-forward.log" 2>&1 & secondary_forward=$!
for _ in $(seq 1 120); do grep -q 'Forwarding from 127.0.0.1:' "$temp/forward.log" && break; kill -0 "$forward" 2>/dev/null || { cat "$temp/forward.log" >&2; exit 1; }; sleep 1; done
grep -q 'Forwarding from 127.0.0.1:' "$temp/forward.log"
for _ in $(seq 1 120); do grep -q 'Forwarding from 127.0.0.1:' "$temp/secondary-forward.log" && break; kill -0 "$secondary_forward" 2>/dev/null || { cat "$temp/secondary-forward.log" >&2; exit 1; }; sleep 1; done
grep -q 'Forwarding from 127.0.0.1:' "$temp/secondary-forward.log"
GOAUTHY_E2E_FEDCM_URL="https://localhost:$port" GOAUTHY_E2E_FEDCM_SECONDARY_URL="https://localhost:$((port + 1))" GOAUTHY_E2E_FEDCM_USERNAME=admin GOAUTHY_E2E_FEDCM_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CA_FILE="$temp/tls.crt" go test -count=1 ./test/e2e/fedcm
old_uid=$(kubectl --context kind-$cluster -n "$namespace" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
kubectl --context kind-$cluster -n "$namespace" delete pod goauthy-0 --wait=true --timeout=180s
for _ in $(seq 1 180); do
	new_uid=$(kubectl --context kind-$cluster -n "$namespace" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
	ready=$(kubectl --context kind-$cluster -n "$namespace" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
	[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] && break
	sleep 1
done
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'replacement pod did not become Ready' >&2; exit 1; }
kill "$forward" 2>/dev/null || true; wait "$forward" 2>/dev/null || true; forward=
kill "$secondary_forward" 2>/dev/null || true; wait "$secondary_forward" 2>/dev/null || true; secondary_forward=
kubectl --context kind-$cluster -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-0 "$port:8443" >"$temp/forward-replacement.log" 2>&1 & forward=$!
for _ in $(seq 1 120); do grep -q 'Forwarding from 127.0.0.1:' "$temp/forward-replacement.log" && break; kill -0 "$forward" 2>/dev/null || { cat "$temp/forward-replacement.log" >&2; exit 1; }; sleep 1; done
grep -q 'Forwarding from 127.0.0.1:' "$temp/forward-replacement.log"
kubectl --context kind-$cluster -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-1 "$((port + 1)):8443" >"$temp/secondary-replacement-forward.log" 2>&1 & secondary_forward=$!
for _ in $(seq 1 120); do grep -q 'Forwarding from 127.0.0.1:' "$temp/secondary-replacement-forward.log" && break; kill -0 "$secondary_forward" 2>/dev/null || { cat "$temp/secondary-replacement-forward.log" >&2; exit 1; }; sleep 1; done
grep -q 'Forwarding from 127.0.0.1:' "$temp/secondary-replacement-forward.log"
GOAUTHY_E2E_FEDCM_URL="https://localhost:$port" GOAUTHY_E2E_FEDCM_SECONDARY_URL="https://localhost:$((port + 1))" GOAUTHY_E2E_FEDCM_USERNAME=admin GOAUTHY_E2E_FEDCM_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CA_FILE="$temp/tls.crt" go test -count=1 ./test/e2e/fedcm
