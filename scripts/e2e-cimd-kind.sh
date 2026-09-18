#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18080}"
: "${KIND_CLUSTER:=goauthy-cimd-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${GOAUTHY_CIMD_FIXTURE_IMAGE:=goauthy-cimd-fixture:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"

for command in docker kind kubectl curl go kustomize openssl grep; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
if kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null; then
	echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2
	exit 1
fi

ensure_image() {
	docker image inspect "$1" >/dev/null 2>&1 || docker pull "$1"
}

temp_dir=$(mktemp -d)
created=false
app_forward=
secondary_forward=
admin_forward=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs deployment/goauthy-cimd-fixture --all-containers=true 2>&1 | sed 's/^/[fixture] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true
		done
		if [ -n "$admin_forward" ] && kill -0 "$admin_forward" 2>/dev/null; then
			curl --silent "http://127.0.0.1:$((E2E_PORT + 3))/admin/state" 2>&1 | sed 's/^/[fixture-state] /' || true
		fi
	fi
	for pid in "$app_forward" "$secondary_forward" "$admin_forward"; do
		if [ -n "$pid" ]; then kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; fi
	done
	if [ "$created" = true ] && { [ "$status" -eq 0 ] || [ "${KEEP_CLUSTER_ON_FAILURE:-false}" != true ]; }; then
		kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
	elif [ "$created" = true ]; then
		echo "kept failed CIMD cluster for diagnosis: $KIND_CLUSTER" >&2
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

rendered="$temp_dir/cimd.yaml"
kustomize build deploy/e2e-cimd >"$rendered"
for contract in CIMD_FIXTURE_TLS_CERT_FILE CIMD_FIXTURE_TLS_KEY_FILE CIMD_FIXTURE_CLIENT_ID CIMD_FIXTURE_REDIRECT_URI GOAUTHY_CIMD_ENABLED SSL_CERT_FILE cimd.e2e.test; do
	grep -Fq "$contract" "$rendered" || { echo "CIMD overlay missing render contract: $contract" >&2; exit 1; }
done

# Throwaway key material is mounted only into the disposable fixture; the app
# receives the public CA only through its opt-in overlay.
openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy CIMD E2E Test CA' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/tls.key" -out "$temp_dir/tls.csr" -subj '/CN=cimd.e2e.test' -addext 'subjectAltName=DNS:cimd.e2e.test' >/dev/null 2>&1
openssl x509 -req -in "$temp_dir/tls.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/tls.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1

./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
docker build --target cimd-fixture --tag "$GOAUTHY_CIMD_FIXTURE_IMAGE" .
ensure_image "$KIND_NODE_IMAGE"
printf '%s\n' 'kind: Cluster' 'apiVersion: kind.x-k8s.io/v1alpha4' 'networking:' '  kubeProxyMode: iptables' >"$temp_dir/kind.yaml"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --config "$temp_dir/kind.yaml" --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"

api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"kind-$KIND_CLUSTER\")].cluster.server}")
case "$api_server" in
	https://0.0.0.0:*) kubectl config set-cluster "kind-$KIND_CLUSTER" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_CIMD_FIXTURE_IMAGE" --name "$KIND_CLUSTER"
kind_node="$KIND_CLUSTER-control-plane"
docker exec "$kind_node" crictl pull minio/minio:RELEASE.2025-04-22T22-12-26Z
docker exec "$kind_node" crictl pull minio/mc:RELEASE.2025-04-16T18-13-26Z

kubectl --context "kind-$KIND_CLUSTER" apply -f deploy/k8s/namespace.yaml
browser_password=correct-horse-browser-staple
browser_phc=$(printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password)
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets --from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=bootstrap-client=correct-horse-battery-staple --from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef --from-literal=bootstrap-user-password-phc="$browser_phc" --from-literal=rhiza-admin-token=goauthy-e2e-admin-token --from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' --from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password --dry-run=client -o yaml | kubectl --context "kind-$KIND_CLUSTER" apply -f -
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" create secret generic cimd-fixture-tls --from-file=tls.crt="$temp_dir/tls.crt" --from-file=tls.key="$temp_dir/tls.key" --dry-run=client -o yaml | kubectl --context "kind-$KIND_CLUSTER" apply -f -
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" create configmap cimd-fixture-ca --from-file=ca.crt="$temp_dir/ca.crt" --dry-run=client -o yaml | kubectl --context "kind-$KIND_CLUSTER" apply -f -

sed "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" "$rendered" | kubectl --context "kind-$KIND_CLUSTER" apply -f -
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" rollout status deployment/goauthy-cimd-fixture --timeout=180s
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() {
	pid=$1
	log=$2
	attempt=0
	while [ "$attempt" -lt 50 ]; do
		attempt=$((attempt + 1))
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && kill -0 "$pid" 2>/dev/null; then return 0; fi
		if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; fi
		sleep 0.1
	done
	cat "$log" >&2
	return 1
}
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/app.log" 2>&1 & app_forward=$!
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/secondary.log" 2>&1 & secondary_forward=$!
fixture_pod=$(kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get pod -l app.kubernetes.io/name=goauthy-cimd-fixture -o jsonpath='{.items[0].metadata.name}')
kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/$fixture_pod" "$((E2E_PORT + 3)):8082" >"$temp_dir/admin.log" 2>&1 & admin_forward=$!
wait_forward "$app_forward" "$temp_dir/app.log"
wait_forward "$secondary_forward" "$temp_dir/secondary.log"
wait_forward "$admin_forward" "$temp_dir/admin.log"
attempt=0
while [ "$attempt" -lt 30 ]; do
	attempt=$((attempt + 1))
	if curl --fail --silent "http://127.0.0.1:$E2E_PORT/livez" >/dev/null && curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/livez" >/dev/null; then break; fi
	sleep 1
done
curl --fail --silent "http://127.0.0.1:$E2E_PORT/livez" >/dev/null
curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/livez" >/dev/null

GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_CIMD_CLIENT_ID='https://cimd.e2e.test/good' GOAUTHY_E2E_CIMD_REDIRECT_URI='https://cimd.e2e.test/callback' GOAUTHY_E2E_CIMD_FIXTURE_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -count=1 ./test/e2e/browser -run '^TestCIMDMetadataDocumentAcrossPods$'
