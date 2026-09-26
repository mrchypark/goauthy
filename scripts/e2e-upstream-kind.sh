#!/bin/sh
# Exercises a real TLS upstream provider through a disposable three-pod Kind cluster.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18080}"
: "${KIND_CLUSTER:=goauthy-upstream-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${GOAUTHY_UPSTREAM_FIXTURE_IMAGE:=goauthy-upstream-fixture:e2e}"
: "${GOAUTHY_SMTP_SINK_IMAGE:=goauthy-smtp-sink:e2e}"

for command in docker kind kubectl curl go kustomize openssl grep nc; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;; esac
case "$K8S_NAMESPACE" in goauthy) ;; *) echo 'K8S_NAMESPACE must be goauthy' >&2; exit 1;; esac
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65533 ] || { echo 'E2E_PORT must leave room for two additional ports (1024..65533)' >&2; exit 1; }
for image in "$GOAUTHY_IMAGE" "$GOAUTHY_UPSTREAM_FIXTURE_IMAGE" "$GOAUTHY_SMTP_SINK_IMAGE"; do case "$image" in ''|*[!A-Za-z0-9./:_@-]*) echo 'E2E image names contain unsupported characters' >&2; exit 1;; esac; done
if kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null; then echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; fi

temp_dir=$(mktemp -d)
created=false
app_forward=
secondary_forward=
fixture_forward=
image_container=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$app_forward" "$secondary_forward" "$fixture_forward"; do
		[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	done
	[ -z "$image_container" ] || docker rm -f "$image_container" >/dev/null 2>&1 || true
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true; done
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs deployment/upstream-fixture --all-containers=true 2>&1 | sed 's/^/[fixture] /' || true
	fi
	[ "$created" != true ] || kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

for port in "$E2E_PORT" "$((E2E_PORT + 1))" "$((E2E_PORT + 2))"; do ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E host port $port is already in use; choose E2E_PORT" >&2; exit 1; }; done

openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy Upstream E2E Test CA' >/dev/null 2>&1
make_leaf() {
	name=$1
	sans=$2
	openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/$name.key" -out "$temp_dir/$name.csr" -subj '/CN=localhost' -addext "subjectAltName=$sans" >/dev/null 2>&1
	openssl x509 -req -in "$temp_dir/$name.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/$name.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1
}
make_leaf goauthy 'DNS:localhost'
make_leaf upstream-fixture 'DNS:localhost,DNS:upstream-fixture.goauthy.svc,DNS:upstream-fixture.goauthy.svc.cluster.local,DNS:github.com,DNS:api.github.com'

./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
docker build --target upstream-fixture --tag "$GOAUTHY_UPSTREAM_FIXTURE_IMAGE" .
docker build --target smtp-sink --tag "$GOAUTHY_SMTP_SINK_IMAGE" .
image_container=$(docker create "$GOAUTHY_IMAGE")
docker cp "$image_container:/etc/ssl/certs/ca-certificates.crt" "$temp_dir/public-ca.crt"
docker rm "$image_container" >/dev/null
image_container=
cp "$temp_dir/public-ca.crt" "$temp_dir/ca-certificates.crt"
awk '1' "$temp_dir/ca.crt" >>"$temp_dir/ca-certificates.crt"

object_store_image=versity/versitygw:v1.8.0
s3_client_image=curlimages/curl:8.16.0
for fixture_image in "$object_store_image" "$s3_client_image"; do
	docker image inspect "$fixture_image" >/dev/null 2>&1 || docker pull "$fixture_image"
done
docker image save --output "$temp_dir/s3-images.tar" "$object_store_image" "$s3_client_image"


kind create cluster --name "$KIND_CLUSTER" --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"
context="kind-$KIND_CLUSTER"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_UPSTREAM_FIXTURE_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_SMTP_SINK_IMAGE" --name "$KIND_CLUSTER"
kind_node="$KIND_CLUSTER-control-plane"
platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$GOAUTHY_IMAGE")
# Stream S3 fixture images archive into the Kind node; docker cp cannot write below
# Kind's mounted /tmp, so we pipe through docker exec -i cat.
docker exec -i "$kind_node" sh -ec 'umask 077; cat > "$1"' sh /tmp/goauthy-s3-images.tar <"$temp_dir/s3-images.tar"
docker exec "$kind_node" test -s /tmp/goauthy-s3-images.tar
docker exec "$kind_node" ctr --namespace=k8s.io images import --platform "$platform" /tmp/goauthy-s3-images.tar

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
	--from-literal=versity-root-user=goauthy-e2e \
	--from-literal=versity-root-password=goauthy-e2e-versity-password \
	--from-literal=password-reset-key=0123456789abcdef0123456789abcdef \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-tls --from-file=tls.crt="$temp_dir/goauthy.crt" --from-file=tls.key="$temp_dir/goauthy.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic upstream-fixture-tls --from-file=tls.crt="$temp_dir/upstream-fixture.crt" --from-file=tls.key="$temp_dir/upstream-fixture.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
printf '%s\n' '{"providers":[{"id":"fixture","issuer":"https://upstream-fixture.goauthy.svc.cluster.local","auth_endpoint":"https://localhost:__FIXTURE_PORT__/authorize","token_endpoint":"https://upstream-fixture.goauthy.svc.cluster.local/token","jwks":"https://upstream-fixture.goauthy.svc.cluster.local/jwks","client_id":"goauthy-upstream-e2e","client_secret_file":"/run/upstream-secret/client-secret","callback_uri":"https://localhost:__E2E_PORT__/upstream/fixture/callback","scopes":["openid","profile"]},{"id":"github","kind":"github","client_id":"goauthy-upstream-e2e","client_secret_file":"/run/upstream-secret/client-secret","callback_uri":"https://localhost:__E2E_PORT__/upstream/github/callback","scopes":["read:user"]}]}' >"$temp_dir/providers.json"
sed -i.bak "s/__E2E_PORT__/$E2E_PORT/g; s/__FIXTURE_PORT__/$((E2E_PORT + 2))/g" "$temp_dir/providers.json"
rm -f "$temp_dir/providers.json.bak"
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic upstream-provider-secret --from-literal=client-secret=goauthy-upstream-e2e-secret --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create configmap upstream-providers --from-file=providers.json="$temp_dir/providers.json" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create configmap upstream-ca --from-file=ca-certificates.crt="$temp_dir/ca-certificates.crt" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kustomize build --load-restrictor LoadRestrictionsNone deploy/kind-upstream >"$temp_dir/upstream.yaml"
sed -i.bak "s#goauthy:e2e#$GOAUTHY_IMAGE#g; s#goauthy-upstream-fixture:e2e#$GOAUTHY_UPSTREAM_FIXTURE_IMAGE#g; s#goauthy-smtp-sink:e2e#$GOAUTHY_SMTP_SINK_IMAGE#g; s#__E2E_PORT__#$E2E_PORT#g" "$temp_dir/upstream.yaml"
rm -f "$temp_dir/upstream.yaml.bak"
kubectl --context "$context" apply -f "$temp_dir/upstream.yaml"
fixture_cluster_ip=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get service/upstream-fixture -o jsonpath='{.spec.clusterIP}')
case "$fixture_cluster_ip" in
	''|None|*[!0-9.]*) echo 'upstream-fixture service did not receive a ClusterIP' >&2; exit 1;;
esac
kubectl --context "$context" -n "$K8S_NAMESPACE" patch statefulset/goauthy --type=merge -p "{\"spec\":{\"template\":{\"spec\":{\"hostAliases\":[{\"ip\":\"$fixture_cluster_ip\",\"hostnames\":[\"github.com\",\"api.github.com\"]}]}}}}"
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/versity --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/versity-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/goauthy-smtp-sink --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/upstream-fixture --timeout=180s
if [ "${GOAUTHY_UPSTREAM_MANAGED_E2E:-}" = "1" ]; then
    kubectl --context "$context" -n "$K8S_NAMESPACE" set env deployment/upstream-fixture ALLOW_MANAGED_CALLBACKS=1
    kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/upstream-fixture --timeout=180s
fi
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() {
	pid=$1 log=$2
	for _ in $(seq 1 50); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && kill -0 "$pid" 2>/dev/null; then return 0; fi
		kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; }
		sleep 0.1
	done
	cat "$log" >&2; return 1
}
start_forwards() {
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0.log" 2>&1 & app_forward=$!
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-1 "$((E2E_PORT + 1)):8080" >"$temp_dir/goauthy-1.log" 2>&1 & secondary_forward=$!
	fixture_pod=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod -l app.kubernetes.io/name=upstream-fixture -o jsonpath='{.items[0].metadata.name}')
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/$fixture_pod" "$((E2E_PORT + 2)):8443" >"$temp_dir/fixture.log" 2>&1 & fixture_forward=$!
	wait_forward "$app_forward" "$temp_dir/goauthy-0.log"
	wait_forward "$secondary_forward" "$temp_dir/goauthy-1.log"
	wait_forward "$fixture_forward" "$temp_dir/fixture.log"
}
stop_app_forward() { [ -z "$app_forward" ] || { kill "$app_forward" >/dev/null 2>&1 || true; wait "$app_forward" 2>/dev/null || true; app_forward=; }; }
start_forwards
curl --fail --silent --show-error --cacert "$temp_dir/ca.crt" "https://localhost:$E2E_PORT/readyz" >/dev/null
curl --fail --silent --show-error --cacert "$temp_dir/ca.crt" "https://localhost:$((E2E_PORT + 1))/readyz" >/dev/null

run_e2e() {
	GOAUTHY_UPSTREAM_E2E_URL="https://localhost:$E2E_PORT" GOAUTHY_UPSTREAM_E2E_SECONDARY_URL="https://localhost:$((E2E_PORT + 1))" GOAUTHY_UPSTREAM_FIXTURE_URL="https://localhost:$((E2E_PORT + 2))" GOAUTHY_UPSTREAM_GITHUB_FIXTURE_URL="https://localhost:$((E2E_PORT + 2))" GOAUTHY_UPSTREAM_E2E_CA_FILE="$temp_dir/ca.crt" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_UPSTREAM_MANAGED_E2E="${GOAUTHY_UPSTREAM_MANAGED_E2E:-}" go test -count=1 ./test/e2e_upstream "$@"
}
run_e2e
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
stop_app_forward
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 --timeout=180s
new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'goauthy-0 did not become a new Ready pod' >&2; exit 1; }
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/goauthy-0-restarted.log" 2>&1 & app_forward=$!
wait_forward "$app_forward" "$temp_dir/goauthy-0-restarted.log"
curl --fail --silent --show-error --cacert "$temp_dir/ca.crt" "https://localhost:$E2E_PORT/readyz" >/dev/null
# loginpolicy.DefaultAttemptWindow is 60s; successful logins consume the
# shared per-IP quota, which survives pod replacement. Cross a full window.
sleep 60
run_e2e
