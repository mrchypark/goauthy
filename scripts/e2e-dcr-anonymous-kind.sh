#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18470}"
: "${KIND_CLUSTER:=goauthy-dcr-anonymous-e2e}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${K8S_NAMESPACE:=goauthy}"
for command in curl docker kind kubectl kustomize go grep jq nc; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;; esac
case "$K8S_NAMESPACE" in goauthy) ;; *) echo 'K8S_NAMESPACE must be goauthy' >&2; exit 1;; esac
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65533 ] || { echo 'E2E_PORT must leave room for three ports (1024..65533)' >&2; exit 1; }
case "$GOAUTHY_IMAGE" in ''|*[!A-Za-z0-9./:_@-]*) echo 'GOAUTHY_IMAGE contains unsupported characters' >&2; exit 1;; esac

temp_dir=$(mktemp -d)
created=false
forward0= forward1= forward2=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward0" "$forward1" "$forward2"; do [ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }; done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get all 2>&1 || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 || true; done
	fi
	[ "$created" != true ] || kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null && { echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; }
for port in "$E2E_PORT" "$((E2E_PORT + 1))" "$((E2E_PORT + 2))"; do ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E host port $port is already in use; choose E2E_PORT" >&2; exit 1; }; done

./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
kind create cluster --name "$KIND_CLUSTER" --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"
context="kind-$KIND_CLUSTER"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
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
	--from-literal=versity-root-user=goauthy-e2e --from-literal=versity-root-password=goauthy-e2e-versity-password
kustomize build deploy/kind-dcr-anonymous | sed "s#__E2E_PORT__#$E2E_PORT#g; s#goauthy:e2e#$GOAUTHY_IMAGE#g" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/versity --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/versity-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() { pid=$1; log=$2; for _ in $(seq 1 120); do grep -q '^Forwarding from 127.0.0.1:' "$log" && kill -0 "$pid" 2>/dev/null && return 0; kill -0 "$pid" 2>/dev/null || { cat "$log" >&2; return 1; }; sleep 1; done; cat "$log" >&2; return 1; }
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0.log" 2>&1 & forward0=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/goauthy-1.log" 2>&1 & forward1=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-2 "$((E2E_PORT + 2)):8080" >"$temp_dir/goauthy-2.log" 2>&1 & forward2=$!
wait_forward "$forward0" "$temp_dir/goauthy-0.log"; wait_forward "$forward1" "$temp_dir/goauthy-1.log"; wait_forward "$forward2" "$temp_dir/goauthy-2.log"
GOAUTHY_E2E_DCR_ANONYMOUS=true GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((E2E_PORT + 2))" go test -count=1 ./test/e2e -run '^TestAnonymousDynamicClientRegistrationAcrossPods$'
cleanup_registration=$(curl --fail --silent --show-error -H 'Content-Type: application/json' -H 'Idempotency-Key: kind-cleanup' -H 'Forwarded: for=198.51.100.99' --data '{"redirect_uris":["https://cleanup.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Kind cleanup"}' "http://127.0.0.1:$E2E_PORT/oidc/register")
cleanup_uri=$(printf '%s' "$cleanup_registration" | jq -er '.registration_client_uri')
cleanup_token=$(printf '%s' "$cleanup_registration" | jq -er '.registration_access_token')
kubectl --context "$context" -n "$K8S_NAMESPACE" set env statefulset/goauthy GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES=0
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
for pid in "$forward0" "$forward1" "$forward2"; do kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; done
forward0= forward1= forward2=
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0-cleanup.log" 2>&1 & forward0=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/goauthy-1-cleanup.log" 2>&1 & forward1=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-2 "$((E2E_PORT + 2)):8080" >"$temp_dir/goauthy-2-cleanup.log" 2>&1 & forward2=$!
wait_forward "$forward0" "$temp_dir/goauthy-0-cleanup.log"; wait_forward "$forward1" "$temp_dir/goauthy-1-cleanup.log"; wait_forward "$forward2" "$temp_dir/goauthy-2-cleanup.log"
cleanup_status=
for _ in $(seq 1 120); do
	cleanup_status=$(curl --silent --output "$temp_dir/cleanup-get.json" --write-out '%{http_code}' -H "Authorization: Bearer $cleanup_token" "$cleanup_uri")
	[ "$cleanup_status" = 401 ] && break
	sleep 0.1
done
[ "$cleanup_status" = 401 ] || { echo "cross-pod startup cleanup management status=$cleanup_status" >&2; cat "$temp_dir/goauthy-0-cleanup.log" "$temp_dir/goauthy-1-cleanup.log" "$temp_dir/goauthy-2-cleanup.log" >&2; exit 1; }
echo 'three-pod anonymous DCR E2E passed'
