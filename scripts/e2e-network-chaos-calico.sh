#!/bin/sh
# Runs only against a dedicated kind cluster and always removes it on exit.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

cluster=${KIND_CLUSTER:-goauthy-calico-e2e}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
namespace=goauthy
port=${E2E_PORT:-18080}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
created=false
calico_url=https://raw.githubusercontent.com/projectcalico/calico/v3.32.1/manifests/calico.yaml
calico_sha256=a1df919d9721cf667accdc3e72848911b0cb25cfab7d2478ad0c996302c95744

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$created" = true ]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

for command in docker kind kubectl curl jq grep sed shasum awk go; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
if kind get clusters | grep -qx "$cluster"; then
	echo "refusing to reuse existing kind cluster: $cluster" >&2
	exit 1
fi

cd "$root"
./scripts/e2e-preflight.sh host-capacity
bootstrap_user_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
docker build --tag "$image" .
kind create cluster --name "$cluster" --config deploy/kind-calico/kind.yaml
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
context=kind-$cluster
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='kind-$cluster')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$image" --name "$cluster"

calico_manifest=$temp_dir/calico.yaml
curl --fail --location --silent --show-error "$calico_url" -o "$calico_manifest"
actual_sha256=$(shasum -a 256 "$calico_manifest" | awk '{print $1}')
[ "$actual_sha256" = "$calico_sha256" ] || {
	echo "Calico manifest digest mismatch: got $actual_sha256" >&2
	exit 1
}
# The official manifest tags are replaced only with verified ARM64 digests.
sed -i.bak \
	-e 's#quay.io/calico/cni:v3.32.1#quay.io/calico/cni@sha256:f83ba4048763b8dbfa95f65b5094e8fb08b7326ce8d465111bb9da416ecb6bdb#g' \
	-e 's#quay.io/calico/node:v3.32.1#quay.io/calico/node@sha256:9da8e32d2d6f9405be1985f258842bfc808bbf5aca51091bdef8110fca722a1b#g' \
	-e 's#quay.io/calico/kube-controllers:v3.32.1#quay.io/calico/kube-controllers@sha256:afa3429708de65af587ede22064a7abddf57082edd368066c24781e3b2d30cb5#g' \
	"$calico_manifest"
grep -q 'quay.io/calico/node@sha256:9da8e32d2d6f9405be1985f258842bfc808bbf5aca51091bdef8110fca722a1b' "$calico_manifest" || exit 1
kubectl --context "$context" create -f "$calico_manifest"
kubectl --context "$context" -n kube-system rollout status daemonset/calico-node --timeout=5m
kubectl --context "$context" -n kube-system rollout status deployment/calico-kube-controllers --timeout=5m
kubectl --context "$context" wait --for=condition=Ready nodes --all --timeout=5m
kubectl --context "$context" get crd networkpolicies.crd.projectcalico.org >/dev/null

kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
kubectl --context "$context" -n "$namespace" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=bootstrap-user-password-phc="$bootstrap_user_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e \
	--from-literal=minio-root-password=goauthy-e2e-minio-password \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f -
kubectl --context "$context" apply -k deploy/k8s
kubectl --context "$context" -n "$namespace" rollout status statefulset/minio --timeout=3m
kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/minio-init --timeout=3m
kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=5m

forward_status() {
	pod=$1
	path=$2
	log=$temp_dir/$pod.log
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 pod/$pod "$port":8080 >"$log" 2>&1 &
	forward=$!
	for attempt in $(seq 1 50); do
		grep -q '^Forwarding from 127.0.0.1:' "$log" && break
		kill -0 "$forward" 2>/dev/null || { cat "$log" >&2; return 1; }
		sleep 0.1
	done
	grep -q '^Forwarding from 127.0.0.1:' "$log" || { cat "$log" >&2; return 1; }
	if [ "$path" = /oidc/jwks.json ]; then
		curl --max-time 10 --fail --silent "http://127.0.0.1:$port$path"
	else
		curl --max-time 10 --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$port$path"
	fi
	kill "$forward" >/dev/null 2>&1 || true
	wait "$forward" 2>/dev/null || true
}

wait_status() {
	pod=$1
	want=$2
	for attempt in $(seq 1 60); do
		[ "$(forward_status "$pod" /readyz)" = "$want" ] && return
		sleep 1
	done
	echo "$pod /readyz did not become $want" >&2
	return 1
}

for pod in goauthy-0 goauthy-1 goauthy-2; do
	wait_status "$pod" 204
done
jwks=$(forward_status goauthy-0 /oidc/jwks.json | jq -er '.keys[0].kid')

kubectl --context "$context" apply -f deploy/kind-calico/partition-goauthy-2.yaml
kubectl --context "$context" -n "$namespace" get networkpolicies.crd.projectcalico.org isolate-goauthy-2-peer >/dev/null
# An accepted CR is insufficient: require the intended readiness transition.
wait_status goauthy-0 204
wait_status goauthy-1 204
wait_status goauthy-2 503

kubectl --context "$context" -n "$namespace" delete networkpolicies.crd.projectcalico.org isolate-goauthy-2-peer --wait=true
for pod in goauthy-0 goauthy-1 goauthy-2; do
	wait_status "$pod" 204
done
recovered=$(forward_status goauthy-0 /oidc/jwks.json | jq -er '.keys[0].kid')
[ "$recovered" = "$jwks" ] || { echo "JWKS kid changed after peer recovery" >&2; exit 1; }
echo "Calico network policy partition/recovery passed"
