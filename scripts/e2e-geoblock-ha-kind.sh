#!/bin/sh
# Exercises real MaxMind geoblock admission across all three embedded Rhiza
# voters, then verifies an untrusted port-forward cannot spoof forwarding.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"

root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
: "${E2E_PORT:=19980}"
: "${KIND_CLUSTER:=goauthy-geoblock-ha-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
for command in docker kind kubectl kustomize go curl grep sed nc seq sleep; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$KIND_CLUSTER" in
	''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;;
esac
case "$E2E_PORT" in
	''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;;
esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65532 ] || {
	echo 'E2E_PORT must leave room for three ports (1024..65532)' >&2
	exit 1
}
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null && {
	echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2
	exit 1
}

temp_dir=$(mktemp -d)
created=false
forwards=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get pods -o wide 2>&1 | sed 's/^/[pods] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true
		done
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
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || {
		echo "E2E port $port is already in use" >&2
		exit 1
	}
done

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
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=versity-root-user=goauthy-e2e \
	--from-literal=versity-root-password=goauthy-e2e-versity-password
kustomize build "$root/deploy/e2e-geoblock-ha" | sed -e "s#goauthy:e2e#$GOAUTHY_IMAGE#g" -e "s#http://127.0.0.1:19980#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/versity --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/versity-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
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
status() { curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' "$@"; }
expect_status() {
	want=$1
	label=$2
	port=$3
	path=$4
	shift 4
	got=$(status "$@" "http://127.0.0.1:$port$path")
	[ "$got" = "$want" ] || { echo "$label status=$got want $want" >&2; exit 1; }
}

probe_pod() {
	pod=$1
	port=$((E2E_PORT + pod))
	expect_status 204 "pod-$pod-ready" "$port" /readyz
	expect_status 403 "pod-$pod-unknown" "$port" /oidc/jwks.json
	expect_status 200 "pod-$pod-allowed" "$port" /oidc/jwks.json -H 'X-Forwarded-For: 2001:220::1'
	expect_status 403 "pod-$pod-denied" "$port" /oidc/jwks.json -H 'X-Forwarded-For: 149.101.100.1'
	expect_status 403 "pod-$pod-unknown-forwarded" "$port" /oidc/jwks.json -H 'X-Forwarded-For: 214.1.1.1'
	expect_status 200 "pod-$pod-trusted-header" "$port" /oidc/jwks.json -H 'X-Country: KR'
	expect_status 403 "pod-$pod-denied-header" "$port" /oidc/jwks.json -H 'X-Country: US'
	expect_status 403 "pod-$pod-ambiguous-header" "$port" /oidc/jwks.json -H 'X-Country: KR,US'
	expect_status 400 "pod-$pod-malformed-forwarded" "$port" /oidc/jwks.json -H 'Forwarded: for=unknown'
	expect_status 400 "pod-$pod-conflicting-forwarded" "$port" /oidc/jwks.json -H 'Forwarded: for=198.51.100.9' -H 'X-Forwarded-For: 198.51.100.9'
}

start_forwards
for pod in 0 1 2; do probe_pod "$pod"; done

# Replace one voter and repeat the real-reader checks through every pod.
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}')
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod/goauthy-1 --wait=true --timeout=180s
new_uid=
for _ in $(seq 1 180); do
	new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
	if [ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ]; then break; fi
	sleep 1
done
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] || { echo 'replacement pod UID did not change' >&2; exit 1; }
start_forwards
for pod in 0 1 2; do probe_pod "$pod"; done

# Change the trust boundary and roll the StatefulSet. Forwarded client IPs
# must now be rejected on every localhost port-forward as an untrusted source.
stop_forwards
kubectl --context "$context" -n "$K8S_NAMESPACE" patch statefulset/goauthy --type strategic \
	--patch '{"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_TRUSTED_PROXIES","value":"10.0.0.0/8"}]}]}}}}'
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
start_forwards
for pod in 0 1 2; do
	port=$((E2E_PORT + pod))
	expect_status 403 "pod-$pod-untrusted-forwarding" "$port" /oidc/jwks.json -H 'X-Forwarded-For: 2001:220::1'
done

echo 'exact-three HA geoblock MaxMind, malformed, replacement, and untrusted gates passed'
