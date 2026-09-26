#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${E2E_PORT:=18980}"
: "${KIND_CLUSTER:=goauthy-metrics-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl kustomize go curl grep nc sed; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65529 ] || { echo 'E2E_PORT must leave room for six ports' >&2; exit 1; }
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
for offset in 0 1 2 3 4 5; do
	port=$((E2E_PORT + offset))
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E port $port is already in use" >&2; exit 1; }
done

docker build --tag "$GOAUTHY_IMAGE" "$root"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
created=true
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
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=metrics-token=metrics-e2e-token \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=versity-root-user=goauthy-e2e --from-literal=versity-root-password=goauthy-e2e-versity-password
kustomize build "$root/deploy/e2e-metrics-ha" | sed -e "s#goauthy:e2e#$GOAUTHY_IMAGE#g" -e "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/versity --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/versity-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

start_forwards() {
	for pod in 0 1 2; do
		kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/goauthy-$pod" "$((E2E_PORT + pod)):8080" >"$temp_dir/app-forward-$pod.log" 2>&1 &
		forwards="$forwards $!"
		kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/goauthy-$pod" "$((E2E_PORT + 3 + pod)):9090" >"$temp_dir/metrics-forward-$pod.log" 2>&1 &
		forwards="$forwards $!"
	done
	for offset in 0 1 2 3 4 5; do
		log=$temp_dir/$(if [ "$offset" -lt 3 ]; then echo app-forward-$offset; else echo metrics-forward-$((offset - 3)); fi).log
		for _ in $(seq 1 120); do grep -q '^Forwarding from 127.0.0.1:' "$log" && break; sleep 1; done
		grep -q '^Forwarding from 127.0.0.1:' "$log" || { cat "$log" >&2; exit 1; }
	done
}
stop_forwards() {
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	forwards=
}
status() { curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' "$@"; }
expect_status() {
	want=$1; shift
	got=$(status "$@")
	[ "$got" = "$want" ] || { echo "unexpected HTTP status=$got want=$want" >&2; exit 1; }
}

start_forwards
for pod in 0 1 2; do
	app="http://127.0.0.1:$((E2E_PORT + pod))"
	metrics="http://127.0.0.1:$((E2E_PORT + 3 + pod))"
	expect_status 204 "$app/readyz"
	expect_status 401 "$metrics/metrics"
	expect_status 401 -H 'Authorization: Bearer wrong' "$metrics/metrics"
	curl --fail --silent --show-error -H 'Authorization: Bearer metrics-e2e-token' "$metrics/metrics" | grep -q '^# HELP '
	expect_status 404 "$app/metrics"
	expect_status 404 "$metrics/livez"
	expect_status 404 "$metrics/oidc/jwks.json"
	expect_status 404 "$metrics/auth/v1/admin"
done

# Replacing one HA pod must preserve the replicated app and its separate
# metrics listener. Stop forwards before deletion so the assertion cannot be
# satisfied by a stale local tunnel.
jwks_before=$(curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/oidc/jwks.json")
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod/goauthy-1 --wait=true --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-1 --timeout=180s
start_forwards
expect_status 204 "http://127.0.0.1:$((E2E_PORT + 1))/readyz"
curl --fail --silent --show-error -H 'Authorization: Bearer metrics-e2e-token' "http://127.0.0.1:$((E2E_PORT + 4))/metrics" | grep -q '^# HELP '
expect_status 404 "http://127.0.0.1:$((E2E_PORT + 4))/livez"
jwks_after=$(curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/oidc/jwks.json")
[ "$jwks_before" = "$jwks_after" ] || { echo 'HA pod replacement changed persisted JWKS' >&2; exit 1; }
echo 'exact-three HA separate metrics listener E2E passed'
