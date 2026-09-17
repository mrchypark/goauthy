#!/bin/sh
# Exercises an HTTPS issuer mounted below the root in a disposable three-pod Kind cluster.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18480}"
: "${KIND_CLUSTER:=goauthy-issuer-path-e2e}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${K8S_NAMESPACE:=goauthy}"
for command in docker kind kubectl curl go kustomize openssl grep nc; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;; esac
case "$K8S_NAMESPACE" in goauthy) ;; *) echo 'K8S_NAMESPACE must be goauthy' >&2; exit 1;; esac
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65531 ] || { echo 'E2E_PORT must leave room for three ports (1024..65531)' >&2; exit 1; }
case "$GOAUTHY_IMAGE" in ''|*[!A-Za-z0-9./:_@-]*) echo 'E2E image name contains unsupported characters' >&2; exit 1;; esac
run_suffix=$(openssl rand -hex 6)
cluster="$KIND_CLUSTER-$run_suffix"
[ "${#cluster}" -le 63 ] || { echo 'KIND_CLUSTER base is too long for a per-run cluster name' >&2; exit 1; }
echo "using disposable Kind cluster: $cluster" >&2
if kind get clusters | grep -Fx "$cluster" >/dev/null; then
	echo "refusing to use existing kind cluster: $cluster" >&2
	exit 1
fi

temp_dir=$(mktemp -d)
created=false
forward0=
forward1=
forward2=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward0" "$forward1" "$forward2"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$cluster"; then
		kubectl --context "kind-$cluster" -n "$K8S_NAMESPACE" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "kind-$cluster" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "kind-$cluster" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true
		done
	fi
	[ "$created" != true ] || kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire
for port in "$E2E_PORT" "$((E2E_PORT + 1))" "$((E2E_PORT + 2))"; do
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E host port $port is already in use; choose E2E_PORT" >&2; exit 1; }
done

openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy issuer-path E2E CA' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/goauthy.key" -out "$temp_dir/goauthy.csr" -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1
openssl x509 -req -in "$temp_dir/goauthy.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/goauthy.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1
./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
created=true
kind create cluster --name "$cluster" --wait 120s
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
context="kind-$cluster"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$cluster"
kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
browser_password=correct-horse-browser-staple
browser_phc=$(printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password)
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e \
	--from-literal=minio-root-password=goauthy-e2e-minio-password
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-tls --from-file=tls.crt="$temp_dir/goauthy.crt" --from-file=tls.key="$temp_dir/goauthy.key"
kustomize build deploy/kind-issuer-path | sed "s#__E2E_PORT__#$E2E_PORT#g; s#goauthy:e2e#$GOAUTHY_IMAGE#g" >"$temp_dir/issuer-path.yaml"
kubectl --context "$context" apply -f "$temp_dir/issuer-path.yaml"
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() {
	pid=$1
	log=$2
	for _ in $(seq 1 50); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && kill -0 "$pid" 2>/dev/null; then return 0; fi
		kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; }
		sleep 0.1
	done
	cat "$log" >&2
	return 1
}
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0.log" 2>&1 & forward0=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/goauthy-1.log" 2>&1 & forward1=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-2 "$((E2E_PORT + 2)):8080" >"$temp_dir/goauthy-2.log" 2>&1 & forward2=$!
wait_forward "$forward0" "$temp_dir/goauthy-0.log"
wait_forward "$forward1" "$temp_dir/goauthy-1.log"
wait_forward "$forward2" "$temp_dir/goauthy-2.log"
curl --fail --silent --show-error --cacert "$temp_dir/ca.crt" "https://localhost:$E2E_PORT/readyz" >/dev/null

GOAUTHY_E2E_URL="https://localhost:$E2E_PORT/tenant" \
GOAUTHY_E2E_SECONDARY_URL="https://localhost:$((E2E_PORT + 1))/tenant" \
GOAUTHY_E2E_TERTIARY_URL="https://localhost:$((E2E_PORT + 2))/tenant" \
GOAUTHY_E2E_CA_FILE="$temp_dir/ca.crt" \
GOAUTHY_E2E_SESSION_FILE="$temp_dir/session" \
GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -run '^(TestIssuerPathDiscoveryAndRootIsolation|TestIssuerPathPreReplacement)$' ./test/e2e_issuer_path

old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
kill "$forward0" >/dev/null 2>&1 || true
wait "$forward0" 2>/dev/null || true
forward0=
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
new_uid=
ready=
for _ in $(seq 1 180); do
	new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
	if [ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ]; then break; fi
	sleep 1
done
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'goauthy-0 did not become a new Ready pod' >&2; exit 1; }
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0-restarted.log" 2>&1 & forward0=$!
wait_forward "$forward0" "$temp_dir/goauthy-0-restarted.log"
curl --fail --silent --show-error --cacert "$temp_dir/ca.crt" "https://localhost:$E2E_PORT/readyz" >/dev/null
GOAUTHY_E2E_URL="https://localhost:$E2E_PORT/tenant" GOAUTHY_E2E_SECONDARY_URL="https://localhost:$((E2E_PORT + 1))/tenant" GOAUTHY_E2E_TERTIARY_URL="https://localhost:$((E2E_PORT + 2))/tenant" GOAUTHY_E2E_CA_FILE="$temp_dir/ca.crt" GOAUTHY_E2E_SESSION_FILE="$temp_dir/session" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -run '^TestIssuerPathPostReplacement$' ./test/e2e_issuer_path
