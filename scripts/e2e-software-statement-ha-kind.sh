#!/bin/sh
# Exercises RFC 7591 software statements across three HA pods and a replacement.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${E2E_PORT:=18880}"
: "${KIND_CLUSTER:=goauthy-software-statement-ha-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl kustomize go grep sed nc seq; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;; esac
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65532 ] || { echo 'E2E_PORT must leave room for three ports (1024..65532)' >&2; exit 1; }
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null && { echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; }

temp_dir=$(mktemp -d)
created=false
forward0=; forward1=; forward2=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward0" "$forward1" "$forward2"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get pods -o wide 2>&1 | sed 's/^/[pods] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true; done
	fi
	if [ "$created" = true ]; then kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true; fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire
for offset in 0 1 2; do
	port=$((E2E_PORT + offset))
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E port $port is already in use" >&2; exit 1; }
done

# The public key is fixed; only the audience varies with the chosen host port.
printf '%s\n' '{"issuers":[{"issuer":"https://publisher.example.test","audience":"http://127.0.0.1:'"$E2E_PORT"'/oidc/register","jwks":{"keys":[{"use":"sig","kty":"OKP","kid":"statement-1","crv":"Ed25519","alg":"EdDSA","x":"ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"}]}}]}' >"$temp_dir/trust.json"
docker build --tag "$GOAUTHY_IMAGE" "$root"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
created=true
"$root/scripts/e2e-preflight.sh" kind-inotify --cluster "$KIND_CLUSTER"
context=kind-$KIND_CLUSTER
api_server=$(kubectl config view --raw --minify --context "$context" -o jsonpath='{.clusters[0].cluster.server}')
case "$api_server" in
	https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kubectl --context "$context" apply -f "$root/deploy/k8s/namespace.yaml"
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password")
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=ha-software-statement-registration-token-0123456789 \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e \
	--from-literal=minio-root-password=goauthy-e2e-minio-password
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-software-statement-trust --from-file=trust.json="$temp_dir/trust.json"
kustomize build "$root/deploy/e2e-software-statement-ha" | sed -e "s#goauthy:e2e#$GOAUTHY_IMAGE#g" -e "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
wait_forward() {
	pid=$1
	log=$2
	port=$3
	for _ in $(seq 1 120); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then return 0; fi
		kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; }
		sleep 1
	done
	cat "$log" >&2
	return 1
}
start_forwards() {
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0.log" 2>&1 & forward0=$!
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/goauthy-1.log" 2>&1 & forward1=$!
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-2 "$((E2E_PORT + 2)):8080" >"$temp_dir/goauthy-2.log" 2>&1 & forward2=$!
	wait_forward "$forward0" "$temp_dir/goauthy-0.log" "$E2E_PORT"
	wait_forward "$forward1" "$temp_dir/goauthy-1.log" "$((E2E_PORT + 1))"
	wait_forward "$forward2" "$temp_dir/goauthy-2.log" "$((E2E_PORT + 2))"
}
stop_forwards() {
	for pid in "$forward0" "$forward1" "$forward2"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	forward0=; forward1=; forward2=
}
run_statement() {
	phase=$1
	GOAUTHY_E2E_SOFTWARE_STATEMENT_URLS="http://127.0.0.1:$E2E_PORT,http://127.0.0.1:$((E2E_PORT + 1)),http://127.0.0.1:$((E2E_PORT + 2))" \
	GOAUTHY_E2E_SOFTWARE_STATEMENT_ISSUER="http://127.0.0.1:$E2E_PORT" \
	GOAUTHY_E2E_SOFTWARE_STATEMENT_PHASE="$phase" \
	GOAUTHY_E2E_SOFTWARE_STATEMENT_STATE_FILE="$temp_dir/registration-response.json" \
	go test -count=1 -v "$root/test/e2e/software_statement_ha" -run '^TestSoftwareStatementHA$'
}

start_forwards
run_statement initial
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
new_uid=
ready=
for _ in $(seq 1 180); do
	new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
	if [ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ]; then
		break
	fi
	sleep 1
done
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'replacement pod did not become Ready' >&2; exit 1; }
echo "goauthy-0 replaced: $old_uid -> $new_uid"
start_forwards
run_statement post-restart
echo 'HA software-statement exact-three gate passed'
