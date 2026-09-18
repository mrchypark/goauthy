#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${E2E_PORT:=18680}"
: "${KIND_CLUSTER:=goauthy-master-key-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl kustomize go curl grep sed nc; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null && { echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; }

temp_dir=$(mktemp -d)
created=false
forwards=
cleanup() {
	code=$?
	trap - 0 1 2 15
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	if [ "$created" = true ]; then kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true; fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$code"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

for offset in 0 1 2; do
	port=$((E2E_PORT + offset))
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E port $port is already in use" >&2; exit 1; }
done

cat >"$temp_dir/api-key-bootstrap.json" <<'EOF'
[{"name":"retirement-operator","secret":{"Plain":"RetirementOperatorKey0000000000000000000000000000000000000000000"},"access":[{"group":"Secrets","access_rights":["read","create","update","delete"]}]}]
EOF
# The bootstrap secret is deliberately fixed for this isolated test cluster
# and is removed with the cluster.
docker build --tag "$GOAUTHY_IMAGE" "$root"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
created=true
"$root/scripts/e2e-preflight.sh" kind-inotify --cluster "$KIND_CLUSTER"
context=kind-$KIND_CLUSTER
# Some local Docker-backed Kind setups publish the API endpoint as 0.0.0.0,
# but the generated certificate is valid for loopback rather than that
# wildcard address. Match the established Kind E2E convention before any
# kubectl operation performs server-side schema validation.
api_server=$(kubectl config view --raw --minify --context "$context" -o jsonpath='{.clusters[0].cluster.server}')
case "$api_server" in
	https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kubectl --context "$context" apply -f "$root/deploy/k8s/namespace.yaml"
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password")
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=key-a=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=key-b=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password \
	--from-file=api-key-bootstrap="$temp_dir/api-key-bootstrap.json"
kustomize build "$root/deploy/e2e-master-key" | sed -e "s#goauthy:e2e#$GOAUTHY_IMAGE#g" -e "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

start_forwards() {
	for pod in 0 1 2; do
		kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/goauthy-$pod" "$((E2E_PORT + pod)):8080" >"$temp_dir/forward-$pod.log" 2>&1 &
		forwards="$forwards $!"
	done
	for pod in 0 1 2; do
		log="$temp_dir/forward-$pod.log"
		for _ in $(seq 1 120); do
			grep -q '^Forwarding from 127.0.0.1:' "$log" && break
			sleep 1
		done
		grep -q '^Forwarding from 127.0.0.1:' "$log" || { cat "$log" >&2; exit 1; }
	done
}
stop_forwards() {
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	forwards=
}
start_forwards

run_phase() {
	phase=$1
	GOAUTHY_E2E_RETIREMENT_PHASE="$phase" \
	GOAUTHY_E2E_RETIREMENT_URL="http://127.0.0.1:$E2E_PORT" \
	GOAUTHY_E2E_RETIREMENT_API_KEY='retirement-operator$RetirementOperatorKey0000000000000000000000000000000000000000000' \
	GOAUTHY_E2E_RETIREMENT_DCR_TOKEN=0123456789abcdef0123456789abcdef \
	GOAUTHY_E2E_RETIREMENT_STATE_FILE="$temp_dir/node-zero-state" \
	go test -count=1 -v "$root/test/e2e_master_key" -run '^TestMasterKeyRetirementKind$'
}
run_phase prepare
run_phase fence

# Roll every pod to B; startup admission rejects any pod that still selects A.
cat >"$temp_dir/key-b-patch.yaml" <<'EOF'
spec:
  template:
    spec:
      containers:
        - name: goauthy
          env:
            - name: GOAUTHY_ACTIVE_MASTER_KEY_ID
              value: key-b
EOF
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" patch statefulset/goauthy --type strategic --patch-file "$temp_dir/key-b-patch.yaml"
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
[ "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get statefulset/goauthy -o jsonpath='{.spec.template.spec.containers[?(@.name=="goauthy")].env[?(@.name=="GOAUTHY_ACTIVE_MASTER_KEY_ID")].value}')" = key-b ]
start_forwards
run_phase attest

old_boot=$(sed -n 's/^node0_boot=//p' "$temp_dir/node-zero-state")
old_sequence=$(sed -n 's/^node0_sequence=//p' "$temp_dir/node-zero-state")
[ -n "$old_boot" ] && [ -n "$old_sequence" ] || { echo 'missing node-zero attestation evidence' >&2; exit 1; }
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod/goauthy-0 --wait=true --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 --timeout=180s
start_forwards
run_phase after-restart
run_phase ready

# Ready never removes key material; both key files remain in the mounted
# source Secret after the explicit Ready transition.
[ -n "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get secret goauthy-secrets -o jsonpath="{.data['key-a']}")" ]
[ -n "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get secret goauthy-secrets -o jsonpath="{.data['key-b']}")" ]
echo 'exact-three master-key retirement Kind gate passed'
