#!/bin/sh
# Deterministic CIMD E2E with an enforcing Cilium CNI.  The deny phase proves
# the workload cannot use its public-IP fixture route until policy is removed.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18080}"
: "${KIND_CLUSTER:=goauthy-cimd-cilium-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${GOAUTHY_CIMD_FIXTURE_IMAGE:=goauthy-cimd-fixture:e2e}"
kind_node_image=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
# Cilium chart v1.20.0, pinned by OCI content digest.  Image digests are in
# deploy/kind-cilium/cilium-values.yaml and are consumed unchanged below.
cilium_chart=oci://quay.io/cilium/charts/cilium@sha256:8009baed89d99fd84f7ee5cfdbf3a1fae8153452132549833956b6aca8b9d738

for command in docker kind kubectl helm curl go kustomize openssl grep; do
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
hubble_forward=
context=kind-$KIND_CLUSTER
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "$context"; then
		kubectl --context "$context" -n "$K8S_NAMESPACE" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "$context" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		kubectl --context "$context" -n "$K8S_NAMESPACE" get ciliumnetworkpolicy 2>&1 | sed 's/^/[cilium-policy] /' || true
		kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium -o wide 2>&1 | sed 's/^/[cilium] /' || true
		kubectl --context "$context" -n kube-system logs deployment/hubble-relay --all-containers=true 2>&1 | sed 's/^/[hubble-relay] /' || true
		for pod in $(kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
			kubectl --context "$context" -n kube-system logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true
		done
		kubectl --context "$context" -n "$K8S_NAMESPACE" logs deployment/goauthy-cimd-fixture --all-containers=true 2>&1 | sed 's/^/[fixture] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "$context" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true
		done
		if [ -n "$admin_forward" ] && kill -0 "$admin_forward" 2>/dev/null; then
			curl --silent "http://127.0.0.1:$((E2E_PORT + 3))/admin/state" 2>&1 | sed 's/^/[fixture-state] /' || true
		fi
	fi
	for pid in "$app_forward" "$secondary_forward" "$admin_forward" "$hubble_forward"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	if [ "$created" = true ] && { [ "$status" -eq 0 ] || [ "${KEEP_CLUSTER_ON_FAILURE:-false}" != true ]; }; then
		kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
	elif [ "$created" = true ]; then
		echo "kept failed Cilium CIMD cluster for diagnosis: $KIND_CLUSTER" >&2
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

rendered=$temp_dir/cimd.yaml
kustomize build deploy/e2e-cimd >"$rendered"
for contract in CIMD_FIXTURE_TLS_CERT_FILE CIMD_FIXTURE_TLS_KEY_FILE CIMD_FIXTURE_CLIENT_ID CIMD_FIXTURE_REDIRECT_URI GOAUTHY_CIMD_ENABLED SSL_CERT_FILE cimd.e2e.test; do
	grep -Fq "$contract" "$rendered" || { echo "CIMD overlay missing render contract: $contract" >&2; exit 1; }
done

openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy CIMD E2E Test CA' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/tls.key" -out "$temp_dir/tls.csr" -subj '/CN=cimd.e2e.test' -addext 'subjectAltName=DNS:cimd.e2e.test' >/dev/null 2>&1
openssl x509 -req -in "$temp_dir/tls.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/tls.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1

./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
docker build --target cimd-fixture --tag "$GOAUTHY_CIMD_FIXTURE_IMAGE" .
ensure_image "$kind_node_image"
kind create cluster --name "$KIND_CLUSTER" --image "$kind_node_image" --config deploy/kind-cilium/kind.yaml --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"

api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$context\")].cluster.server}")
case "$api_server" in
	https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
esac
helm upgrade --install cilium "$cilium_chart" --kube-context "$context" --namespace kube-system --create-namespace --values deploy/kind-cilium/cilium-values.yaml --set hubble.relay.enabled=true --wait --timeout 5m
kubectl --context "$context" -n kube-system rollout status daemonset/cilium --timeout=5m
kubectl --context "$context" -n kube-system rollout status deployment/cilium-operator --timeout=5m
kubectl --context "$context" -n kube-system rollout status deployment/hubble-relay --timeout=5m
kubectl --context "$context" wait --for=condition=Ready nodes --all --timeout=5m
kubectl --context "$context" get crd ciliumnetworkpolicies.cilium.io >/dev/null

kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_CIMD_FIXTURE_IMAGE" --name "$KIND_CLUSTER"
for node in $(kind get nodes --name "$KIND_CLUSTER"); do
	docker exec "$node" crictl pull minio/minio:RELEASE.2025-04-22T22-12-26Z
	docker exec "$node" crictl pull minio/mc:RELEASE.2025-04-16T18-13-26Z
done

kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
browser_password=correct-horse-browser-staple
browser_phc=$(printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password)
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets --from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=bootstrap-client=correct-horse-battery-staple --from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef --from-literal=bootstrap-user-password-phc="$browser_phc" --from-literal=rhiza-admin-token=goauthy-e2e-admin-token --from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' --from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password --dry-run=client -o yaml | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic cimd-fixture-tls --from-file=tls.crt="$temp_dir/tls.crt" --from-file=tls.key="$temp_dir/tls.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" create configmap cimd-fixture-ca --from-file=ca.crt="$temp_dir/ca.crt" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
sed "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" "$rendered" | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/goauthy-cimd-fixture --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
kubectl --context "$context" -n kube-system get configmap kube-proxy -o jsonpath='{.data.config\.conf}' | grep -Eq '^mode:[[:space:]]*iptables[[:space:]]*$' || { echo 'kube-proxy is not in iptables mode' >&2; exit 1; }
for node in $(kind get nodes --name "$KIND_CLUSTER"); do
	docker exec "$node" iptables-save -t nat | grep -Eq '8\.8\.8\.8/32.*--dport 443.*KUBE-' || { echo "missing externalIP NAT rule on $node" >&2; exit 1; }
done

wait_forward() {
	pid=$1 log=$2 attempt=0
	while [ "$attempt" -lt 50 ]; do
		attempt=$((attempt + 1))
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && kill -0 "$pid" 2>/dev/null; then return 0; fi
		if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; fi
		sleep 0.1
	done
	cat "$log" >&2; return 1
}
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/app.log" 2>&1 & app_forward=$!
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/secondary.log" 2>&1 & secondary_forward=$!
fixture_pod=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod -l app.kubernetes.io/name=goauthy-cimd-fixture -o jsonpath='{.items[0].metadata.name}')
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/$fixture_pod" "$((E2E_PORT + 3)):8082" >"$temp_dir/admin.log" 2>&1 & admin_forward=$!
wait_forward "$app_forward" "$temp_dir/app.log"
wait_forward "$secondary_forward" "$temp_dir/secondary.log"
wait_forward "$admin_forward" "$temp_dir/admin.log"
for attempt in $(seq 1 30); do
	if curl --fail --silent "http://127.0.0.1:$E2E_PORT/livez" >/dev/null && curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/livez" >/dev/null; then break; fi
	sleep 1
done
curl --fail --silent "http://127.0.0.1:$E2E_PORT/livez" >/dev/null
curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/livez" >/dev/null

policy_revision() {
	kubectl --context "$context" -n "$K8S_NAMESPACE" get ciliumendpoint "$1" -o jsonpath="{.status.policy.realized['policy-revision']}"
}
wait_policy_revision() {
	pod=$1 before=$2 attempt=0
	while [ "$attempt" -lt 60 ]; do
		attempt=$((attempt + 1))
		now=$(policy_revision "$pod")
		[ -n "$now" ] && [ "$now" != "$before" ] && return 0
		sleep 1
	done
	echo "Cilium policy revision for $pod did not advance from $before" >&2
	return 1
}
authorize() {
	port=$1 client_id=$2 state=$3 headers=$temp_dir/authorize-$state.headers
	curl --silent --show-error --output "$temp_dir/authorize-$state.body" --dump-header "$headers" --write-out '%{http_code}' --get "http://127.0.0.1:$port/oidc/authorize" --data-urlencode 'response_type=code' --data-urlencode "client_id=$client_id" --data-urlencode 'redirect_uri=https://cimd.e2e.test/callback' --data-urlencode 'code_challenge=0123456789012345678901234567890123456789012' --data-urlencode 'code_challenge_method=S256' --data-urlencode 'scope=goauthy.read' --data-urlencode "state=$state" --data-urlencode 'prompt=none'
}
expect_login_required() {
	port=$1 client_id=$2 state=$3 status=$(authorize "$port" "$client_id" "$state")
	case "$status" in 302|303) ;; *) echo "CIMD $state status=$status, want login_required redirect" >&2; return 1 ;; esac
	grep -Eq '^Location: .*error=login_required([&[:space:]]|$)' "$temp_dir/authorize-$state.headers" || { echo "CIMD $state missing login_required redirect" >&2; return 1; }
	grep -Eq "^Location: .*state=$state([&[:space:]]|$)" "$temp_dir/authorize-$state.headers" || { echo "CIMD $state missing state" >&2; return 1; }
}
fixture_requests() {
	curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 3))/admin/state" | sed -n 's/.*"requests"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p'
}
for pod in goauthy-0 goauthy-1 goauthy-2 "$fixture_pod"; do
	revision=
	for attempt in $(seq 1 60); do
		revision=$(policy_revision "$pod")
		[ -n "$revision" ] && break
		sleep 1
	done
	[ -n "${revision:-}" ] || { echo "Cilium endpoint $pod has no realized policy revision" >&2; exit 1; }
done

# Seed one cache entry, then reset only the fixture counter.  A Cilium deny
# must block a distinct metadata URL while the pre-existing cache still works.
curl --fail --silent -X POST "http://127.0.0.1:$((E2E_PORT + 3))/admin/reset" -o /dev/null
expect_login_required "$E2E_PORT" 'https://cimd.e2e.test/allow' cimd-cilium-allow
[ "$(fixture_requests)" = 1 ] || { echo 'CIMD allow did not fetch exactly once' >&2; exit 1; }
curl --fail --silent -X POST "http://127.0.0.1:$((E2E_PORT + 3))/admin/reset" -o /dev/null
allow_revision_0=$(policy_revision goauthy-0)
allow_revision_1=$(policy_revision goauthy-1)
# The fixture counter is a state assertion, not a timing assertion.  With the
# deny policy active, a fresh valid metadata URL must not reach it.
kubectl --context "$context" apply -f deploy/e2e-cimd-cilium/deny-cimd-egress.yaml
wait_policy_revision goauthy-0 "$allow_revision_0"
wait_policy_revision goauthy-1 "$allow_revision_1"
curl --fail --silent "http://127.0.0.1:$E2E_PORT/readyz" >/dev/null
curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/readyz" >/dev/null
expect_login_required "$((E2E_PORT + 1))" 'https://cimd.e2e.test/allow' cimd-cilium-cached
[ "$(fixture_requests)" = 0 ] || { echo 'CIMD cached allow reached fixture while deny active' >&2; exit 1; }
denied_status=$(authorize "$((E2E_PORT + 1))" 'https://cimd.e2e.test/deny' cimd-cilium-deny)
[ "$denied_status" = 400 ] || { echo "Cilium CIMD deny status=$denied_status, want 400" >&2; exit 1; }
grep -q '^Location:' "$temp_dir/authorize-cimd-cilium-deny.headers" && { echo 'CIMD deny unexpectedly redirected' >&2; exit 1; }
[ "$(fixture_requests)" = 0 ] || { echo 'Cilium deny reached fixture' >&2; exit 1; }
if command -v hubble >/dev/null; then
	kubectl --context "$context" -n kube-system port-forward --address=127.0.0.1 service/hubble-relay "$((E2E_PORT + 4)):80" >"$temp_dir/hubble.log" 2>&1 &
	hubble_forward=$!
	if wait_forward "$hubble_forward" "$temp_dir/hubble.log"; then
		hubble observe --server "127.0.0.1:$((E2E_PORT + 4))" --last 20 -t drop >"$temp_dir/hubble-deny.txt" 2>&1 || true
	fi
	kill "$hubble_forward" >/dev/null 2>&1 || true
	wait "$hubble_forward" 2>/dev/null || true
	hubble_forward=
fi
deny_revision_0=$(policy_revision goauthy-0)
deny_revision_1=$(policy_revision goauthy-1)
kubectl --context "$context" -n "$K8S_NAMESPACE" delete ciliumnetworkpolicy deny-cimd-public-egress --wait=true
wait_policy_revision goauthy-0 "$deny_revision_0"
wait_policy_revision goauthy-1 "$deny_revision_1"
curl --fail --silent "http://127.0.0.1:$E2E_PORT/readyz" >/dev/null
curl --fail --silent "http://127.0.0.1:$((E2E_PORT + 1))/readyz" >/dev/null
curl --fail --silent -X POST "http://127.0.0.1:$((E2E_PORT + 3))/admin/reset" -o /dev/null
expect_login_required "$E2E_PORT" 'https://cimd.e2e.test/recovery' cimd-cilium-recovery
[ "$(fixture_requests)" = 1 ] || { echo 'CIMD recovery did not fetch exactly once' >&2; exit 1; }

GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_CIMD_CLIENT_ID='https://cimd.e2e.test/good' GOAUTHY_E2E_CIMD_REDIRECT_URI='https://cimd.e2e.test/callback' GOAUTHY_E2E_CIMD_FIXTURE_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -count=1 ./test/e2e/browser -run '^TestCIMDMetadataDocumentAcrossPods$'
echo "Cilium CIMD policy enforcement and cross-pod E2E passed"
