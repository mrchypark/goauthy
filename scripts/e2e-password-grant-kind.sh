#!/bin/sh
# Exercises the OAuth2 password grant through a Kind cluster.
set -eu

for command in docker kind kubectl kustomize go curl jq nc; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
cluster=${KIND_CLUSTER:-goauthy-password-grant-e2e}
port=${E2E_PORT:-18080}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
backchannel_image=${GOAUTHY_BACKCHANNEL_SINK_IMAGE:-goauthy-backchannel-sink:e2e}
namespace=${K8S_NAMESPACE:-goauthy}
temp=$(mktemp -d)
forward=
secondary_forward=
tertiary_forward=
quaternary_forward=
created=false

cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward" "$secondary_forward" "$tertiary_forward" "$quaternary_forward"; do
		[ -z "$pid" ] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
	done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$cluster"; then
		kubectl --context "kind-$cluster" -n "$namespace" get pods 2>&1 | sed 's/^/[pods] /' >&2 || true
		kubectl --context "kind-$cluster" -n "$namespace" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' >&2 || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "kind-$cluster" -n "$namespace" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" >&2 || true
		done
	fi
	[ "$created" != true ] || kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	rm -rf "$temp"
	exit "$status"
}
trap cleanup 0 1 2 15

kind get clusters | grep -Fx "$cluster" >/dev/null && { echo "refusing to use existing kind cluster: $cluster" >&2; exit 1; }
./scripts/e2e-preflight.sh host-capacity
for offset in 0 1 2 3; do
	check_port=$((port + offset))
	nc -z 127.0.0.1 "$check_port" >/dev/null 2>&1 && { echo "E2E host port $check_port is already in use; choose E2E_PORT" >&2; exit 1; }
done

docker build --tag "$image" .
docker build --target backchannel-sink --tag "$backchannel_image" .
kind create cluster --name "$cluster" --wait 120s; created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
kind load docker-image "$image" --name "$cluster"
kind load docker-image "$backchannel_image" --name "$cluster"

kubectl --context "kind-$cluster" apply -f deploy/k8s/namespace.yaml
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
kubectl --context "kind-$cluster" -n "$namespace" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e \
	--from-literal=minio-root-password=goauthy-e2e-minio-password

backchannel_uri=http://goauthy-backchannel-sink.goauthy.svc.cluster.local:8081/backchannel
kubectl --context "kind-$cluster" -n "$namespace" create configmap goauthy-backchannel \
	--from-literal=logout-uri="$backchannel_uri" \
	--from-literal=allow-private=true \
	--from-literal=allow-http=true \
	--from-literal=retry-base=1s \
	--from-literal=ca-file="" \
	--from-literal=tls-cert-file="" \
	--from-literal=tls-key-file="" \
	--dry-run=client -o yaml | kubectl --context "kind-$cluster" apply -f -

kustomize build deploy/k8s | sed -e "s#image: goauthy:e2e\$#image: $image#" -e "s#image: goauthy-backchannel-sink:e2e\$#image: $backchannel_image#" -e "s#http://127.0.0.1:18080#http://127.0.0.1:$port#g" | kubectl --context "kind-$cluster" apply -f -
sed "s#image: goauthy-backchannel-sink:e2e\$#image: $backchannel_image#" deploy/k8s/backchannel-sink.yaml | kubectl --context "kind-$cluster" -n "$namespace" apply -f -

kubectl --context "kind-$cluster" -n "$namespace" rollout status statefulset/minio --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" rollout status deployment/goauthy-backchannel-sink --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() (
	pid=$1; log=$2; port=$3
	for _ in $(seq 1 50); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then return 0; fi
		kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; }
		sleep 0.1
	done
	cat "$log" >&2; return 1
)

kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-0 "$port:8080" >"$temp/forward.log" 2>&1 & forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-1 "$((port + 1)):8080" >"$temp/secondary-forward.log" 2>&1 & secondary_forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-2 "$((port + 2)):8080" >"$temp/tertiary-forward.log" 2>&1 & tertiary_forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 service/goauthy-backchannel-sink "$((port + 3)):8081" >"$temp/quaternary-forward.log" 2>&1 & quaternary_forward=$!
wait_forward "$forward" "$temp/forward.log" "$port"
wait_forward "$secondary_forward" "$temp/secondary-forward.log" "$((port + 1))"
wait_forward "$tertiary_forward" "$temp/tertiary-forward.log" "$((port + 2))"
wait_forward "$quaternary_forward" "$temp/quaternary-forward.log" "$((port + 3))"

for attempt in $(seq 1 30); do
	curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null && \
	curl --fail --silent "http://127.0.0.1:$((port + 1))/readyz" >/dev/null && \
	curl --fail --silent "http://127.0.0.1:$((port + 2))/readyz" >/dev/null && break
	sleep 1
done

GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
GOAUTHY_E2E_BROWSER_USERNAME=admin \
GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
GOAUTHY_E2E_BACKCHANNEL_SINK_URL="http://127.0.0.1:$((port + 3))" \
GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef \
go test -count=1 -v -timeout=2m ./test/e2e -run '^TestPasswordGrantAcrossPods$'

GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
GOAUTHY_E2E_BROWSER_USERNAME=admin \
GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
GOAUTHY_E2E_BACKCHANNEL_SINK_URL="http://127.0.0.1:$((port + 3))" \
GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef \
go test -count=1 -v -timeout=2m ./test/e2e -run '^TestDCRBackchannelLogoutAcrossPods$'

echo 'Password grant and DCR backchannel Kind E2E passed'
