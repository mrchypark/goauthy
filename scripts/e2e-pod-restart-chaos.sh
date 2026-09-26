#!/bin/sh
# Verifies OAuth state survives replacement of one pod in a dedicated kind cluster.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

cluster=${KIND_CLUSTER:-goauthy-restart-chaos-e2e}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
namespace=goauthy
port=${E2E_PORT:-18080}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
created=false
forward=

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$forward" ]; then kill "$forward" >/dev/null 2>&1 || true; wait "$forward" 2>/dev/null || true; fi
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$cluster"; then
		kubectl --context "kind-$cluster" -n "$namespace" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "kind-$cluster" -n "$namespace" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			kubectl --context "kind-$cluster" -n "$namespace" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod current] /" || true
			kubectl --context "kind-$cluster" -n "$namespace" logs "pod/$pod" --all-containers=true 2>&1 | grep -Ei 'rhiza|savepoint|sync' | sed "s/^/[$pod rhiza] /" || true
			kubectl --context "kind-$cluster" -n "$namespace" logs "pod/$pod" --all-containers=true --previous 2>&1 | grep -Ei 'rhiza|savepoint|sync' | sed "s/^/[$pod previous-rhiza] /" || true
		done
	fi
	if [ "$created" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

case "$cluster" in
	goauthy-restart-chaos-e2e|goauthy-restart-chaos-e2e-*) ;;
	*) echo "KIND_CLUSTER must start with goauthy-restart-chaos-e2e" >&2; exit 1 ;;
esac
for command in docker kind kubectl curl go jq grep; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
if kind get clusters | grep -qx "$cluster"; then
	echo "refusing to reuse existing kind cluster: $cluster" >&2
	exit 1
fi

cd "$root"
./scripts/e2e-preflight.sh host-capacity
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
docker build --tag "$image" .
kind create cluster --name "$cluster" --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
context=kind-$cluster
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$image" --name "$cluster"
kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
kubectl --context "$context" -n "$namespace" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=versity-root-user=goauthy-e2e \
	--from-literal=versity-root-password=goauthy-e2e-versity-password \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f -
kubectl --context "$context" apply -k deploy/k8s
kubectl --context "$context" -n "$namespace" rollout status statefulset/versity --timeout=3m
kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/versity-init --timeout=3m
kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=3m
restart_counts=$(kubectl --context "$context" -n "$namespace" get pods -l app.kubernetes.io/name=goauthy -o jsonpath='{range .items[*]}{range .status.initContainerStatuses[*]}{.restartCount}{"\n"}{end}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}')
if [ -z "$restart_counts" ] || printf '%s\n' "$restart_counts" | grep -qv '^0$'; then
	echo "goauthy baseline contains container restarts" >&2
	exit 1
fi

with_pod() {
	pod=$1
	shift
	log=$temp_dir/$pod-forward.log
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 "pod/$pod" "$port:8080" >"$log" 2>&1 &
	forward=$!
	for _ in $(seq 1 50); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log"; then break; fi
		kill -0 "$forward" 2>/dev/null || { cat "$log" >&2; return 1; }
		sleep 0.1
	done
	grep -q '^Forwarding from 127.0.0.1:' "$log" || { cat "$log" >&2; return 1; }
	set +e
	"$@" "http://127.0.0.1:$port"
	status=$?
	set -e
	kill "$forward" >/dev/null 2>&1 || true
	wait "$forward" 2>/dev/null || true
	forward=
	return "$status"
}

issue_token() {
	base=$1
	curl --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" | jq -er '.access_token'
}

assert_active() {
	token=$1
	base=$2
	payload=$(curl --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token=$token" "$base/oidc/introspect")
	[ "$(printf '%s' "$payload" | jq -er '.active')" = true ]
	[ "$(printf '%s' "$payload" | jq -er '.client_id')" = goauthy-dev ]
	[ "$(printf '%s' "$payload" | jq -er '.scope')" = goauthy.read ]
}

token=$(with_pod goauthy-0 issue_token)
with_pod goauthy-1 assert_active "$token"
with_pod goauthy-2 assert_active "$token"

kubectl --context "$context" -n "$namespace" delete pod goauthy-2 --wait=true
with_pod goauthy-0 assert_active "$token"
with_pod goauthy-1 assert_active "$token"
kubectl --context "$context" -n "$namespace" wait --for=condition=Ready pod/goauthy-2 --timeout=180s
kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
with_pod goauthy-2 assert_active "$token"
echo "pod restart OAuth consistency passed"
