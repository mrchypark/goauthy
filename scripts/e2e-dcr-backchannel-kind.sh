#!/bin/sh
# Exercises DCR-registered clients with backchannel logout across Kind HA pods.
set -eu

for command in docker kind kubectl kustomize go curl jq nc; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
cluster=${KIND_CLUSTER:-goauthy-dcr-backchannel-e2e}
port=${E2E_PORT:-18080}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
backchannel_image=${GOAUTHY_BACKCHANNEL_SINK_IMAGE:-goauthy-backchannel-sink:e2e}
smtp_image=${GOAUTHY_SMTP_SINK_IMAGE:-goauthy-smtp-sink:e2e}
namespace=${K8S_NAMESPACE:-goauthy}
temp=$(mktemp -d)
forward=
secondary_forward=
tertiary_forward=
quaternary_forward=
smtp_forward=
created=false

cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward" "$secondary_forward" "$tertiary_forward" "$quaternary_forward" "$smtp_forward"; do
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
port_offsets='0 1 2 3'
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" = 1 ] && port_offsets="$port_offsets 4"
for offset in $port_offsets; do
	check_port=$((port + offset))
	nc -z 127.0.0.1 "$check_port" >/dev/null 2>&1 && { echo "E2E host port $check_port is already in use; choose E2E_PORT" >&2; exit 1; }
done

# Prepare fixture images before the rollout timeout starts. A file avoids
# streaming Docker export through a second Docker process.
object_store_image=versity/versitygw:v1.8.0
s3_client_image=curlimages/curl:8.16.0
for fixture_image in "$object_store_image" "$s3_client_image"; do
	docker image inspect "$fixture_image" >/dev/null 2>&1 || docker pull "$fixture_image"
done
docker image save --output "$temp/s3-images.tar" "$object_store_image" "$s3_client_image"

docker build --tag "$image" .
docker build --target backchannel-sink --tag "$backchannel_image" .
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || docker build --target smtp-sink --tag "$smtp_image" .
kind create cluster --name "$cluster" --wait 120s; created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
context="kind-$cluster"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$image" --name "$cluster"
kind load docker-image "$backchannel_image" --name "$cluster"
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || kind load docker-image "$smtp_image" --name "$cluster"
platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
# Dory docker cp can write below Kind's mounted /tmp; stream through the node
# mount namespace so containerd sees the archive.
docker exec -i "$cluster-control-plane" sh -ec 'umask 077; cat > "$1"' sh /tmp/goauthy-s3-images.tar <"$temp/s3-images.tar"
# Verify the completed stream before asking containerd to open it.
docker exec "$cluster-control-plane" test -s /tmp/goauthy-s3-images.tar
docker exec "$cluster-control-plane" ctr --namespace=k8s.io images import --platform "$platform" /tmp/goauthy-s3-images.tar


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

if [ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" = 1 ]; then
	sed "s#image: goauthy-smtp-sink:e2e\$#image: $smtp_image#" deploy/k8s/login-location-smtp.yaml | kubectl --context "kind-$cluster" -n "$namespace" apply -f -
	printf '%s' '{"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_OPEN_USER_REG","value":"true"},{"name":"GOAUTHY_USER_REG_DOMAIN_RESTRICTION","value":"goauthy.e2e"},{"name":"GOAUTHY_PASSWORD_RECOVERY_ENABLED","value":"true"},{"name":"GOAUTHY_POW_DIFFICULTY","value":"10"},{"name":"GOAUTHY_PASSWORD_RESET_KEY_FILE","value":"/run/secrets/password-reset-key"},{"name":"GOAUTHY_SMTP_HOST","value":"goauthy-login-location-smtp.goauthy.svc.cluster.local"},{"name":"GOAUTHY_SMTP_PORT","value":"1025"},{"name":"GOAUTHY_SMTP_FROM","value":"support@goauthy.e2e"},{"name":"GOAUTHY_SMTP_ALLOW_INSECURE","value":"true"},{"name":"GOAUTHY_EMAIL_TEMPLATE_LANG","value":"en"},{"name":"GOAUTHY_BOOTSTRAP_USER_EMAIL","value":"admin@goauthy.e2e"}],"volumeMounts":[{"name":"password-reset-key","mountPath":"/run/secrets/password-reset-key","subPath":"password-reset-key","readOnly":true}]}],"volumes":[{"name":"password-reset-key","secret":{"secretName":"goauthy-login-location","defaultMode":288,"items":[{"key":"password-reset-key","path":"password-reset-key"}]}}]}}}}' >"$temp/login-location-statefulset-patch.json"
	kubectl --context "kind-$cluster" -n "$namespace" patch statefulset/goauthy --type=strategic --patch-file "$temp/login-location-statefulset-patch.json"
fi

if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then
	printf '%s' '{"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED","value":"true"}]}]}}}}' >"$temp/token-events-statefulset-patch.json"
	kubectl --context "kind-$cluster" -n "$namespace" patch statefulset/goauthy --type=strategic --patch-file "$temp/token-events-statefulset-patch.json"
fi

if [ "${GOAUTHY_E2E_EVENT_NOTIFICATIONS:-0}" = 1 ]; then
	[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" = 1 ] || { echo 'event notifications require the SMTP fixture (GOAUTHY_E2E_LOGIN_LOCATION=1)' >&2; exit 1; }
	kubectl --context "kind-$cluster" -n "$namespace" set env statefulset/goauthy GOAUTHY_EVENT_NOTIFICATION_TARGETS=email GOAUTHY_EVENT_EMAIL_TO=events@goauthy.e2e GOAUTHY_EVENT_NOTIFICATION_EMAIL_LEVEL=info
	export GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((port + 4))" GOAUTHY_EVENT_EMAIL_TO=events@goauthy.e2e
fi

kubectl --context "kind-$cluster" -n "$namespace" rollout status statefulset/minio --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" rollout status deployment/goauthy-backchannel-sink --timeout=180s
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || kubectl --context "kind-$cluster" -n "$namespace" rollout status deployment/goauthy-login-location-smtp --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
kubectl --context "kind-$cluster" -n "$namespace" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

wait_forward() (
	pid=$1; log=$2; port=$3
	for _ in $(seq 1 120); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log" && nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then return 0; fi
		kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; cat "$log" >&2; return 1; }
		sleep 1
	done
	cat "$log" >&2; return 1
)

kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-0 "$port:8080" >"$temp/forward.log" 2>&1 & forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-1 "$((port + 1)):8080" >"$temp/secondary-forward.log" 2>&1 & secondary_forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-2 "$((port + 2)):8080" >"$temp/tertiary-forward.log" 2>&1 & tertiary_forward=$!
kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 service/goauthy-backchannel-sink "$((port + 3)):8081" >"$temp/quaternary-forward.log" 2>&1 & quaternary_forward=$!
if [ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" = 1 ]; then
	kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 service/goauthy-login-location-smtp "$((port + 4)):8082" >"$temp/smtp-forward.log" 2>&1 & smtp_forward=$!
fi
wait_forward "$forward" "$temp/forward.log" "$port"
wait_forward "$secondary_forward" "$temp/secondary-forward.log" "$((port + 1))"
wait_forward "$tertiary_forward" "$temp/tertiary-forward.log" "$((port + 2))"
wait_forward "$quaternary_forward" "$temp/quaternary-forward.log" "$((port + 3))"
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || wait_forward "$smtp_forward" "$temp/smtp-forward.log" "$((port + 4))"

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
go test -count=1 -v -timeout=2m ./test/e2e -run '^TestDCR(BackchannelLogoutAcrossPods|PasswordBackchannelURIUpdateRemovalAcrossPods)$'
if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then
	GOAUTHY_E2E_TOKEN_EVENTS=1 \
	GOAUTHY_E2E_TOKEN_EVENT_FILE="$temp/token-events.json" \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
	GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssuedEvents$'
	GOAUTHY_E2E_TOKEN_EVENTS=1 \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
	GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssued(UserEvents|DeviceEvents)$'
fi
[ "${GOAUTHY_E2E_THEME:-0}" != 1 ] || GOAUTHY_E2E_THEME=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemeLive$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClient(Logo|Favicon)Live$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_LOGO_STATE_FILE="$temp/logo-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientLogoPersistPrepare$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_FAVICON_STATE_FILE="$temp/favicon-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientFaviconPersistPrepare$'
[ "${GOAUTHY_E2E_THEME:-0}" != 1 ] || GOAUTHY_E2E_THEME=1 GOAUTHY_E2E_THEME_STATE_FILE="$temp/theme-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemePersistPrepare$'
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || GOAUTHY_E2E_LOGIN_LOCATION=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((port + 4))" go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestLoginLocationRevokeLive$'
[ "${GOAUTHY_E2E_UPSTREAM_REGISTRY:-0}" != 1 ] || GOAUTHY_E2E_UPSTREAM_REGISTRY=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUpstreamRegistryLive$'

# Pod replacement resilience: kill pod-0 and re-run
old_uid=$(kubectl --context "kind-$cluster" -n "$namespace" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
kill "$forward" 2>/dev/null || true; wait "$forward" 2>/dev/null || true; forward=
kubectl --context "kind-$cluster" -n "$namespace" delete pod goauthy-0 --wait=true --timeout=180s
new_uid=
ready=
for _ in $(seq 1 180); do
	new_uid=$(kubectl --context "kind-$cluster" -n "$namespace" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
	ready=$(kubectl --context "kind-$cluster" -n "$namespace" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
	[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] && break
	sleep 1
done
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'replacement pod did not become Ready' >&2; exit 1; }
echo "goauthy-0 replaced: $old_uid -> $new_uid"

kubectl --context "kind-$cluster" -n "$namespace" port-forward --address=127.0.0.1 pod/goauthy-0 "$port:8080" >"$temp/forward-replacement.log" 2>&1 & forward=$!
wait_forward "$forward" "$temp/forward-replacement.log" "$port"

GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
GOAUTHY_E2E_BROWSER_USERNAME=admin \
GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
GOAUTHY_E2E_BACKCHANNEL_SINK_URL="http://127.0.0.1:$((port + 3))" \
GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef \
go test -count=1 -v -timeout=2m ./test/e2e -run '^TestDCR(BackchannelLogoutAcrossPods|PasswordBackchannelURIUpdateRemovalAcrossPods)$'
if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then
	GOAUTHY_E2E_TOKEN_EVENTS=1 \
	GOAUTHY_E2E_TOKEN_EVENT_FILE="$temp/token-events.json" \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
	GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssuedEventsPersisted$'
	GOAUTHY_E2E_TOKEN_EVENTS=1 \
	GOAUTHY_E2E_TOKEN_EVENT_FILE="$temp/token-events.json" \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
	GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssuedEvents$'
	GOAUTHY_E2E_TOKEN_EVENTS=1 \
	GOAUTHY_E2E_URL="http://127.0.0.1:$port" \
	GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" \
	GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" \
	GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssued(UserEvents|DeviceEvents)$'
fi
[ "${GOAUTHY_E2E_THEME:-0}" != 1 ] || GOAUTHY_E2E_THEME=1 GOAUTHY_E2E_THEME_STATE_FILE="$temp/theme-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemePersistVerify$'
[ "${GOAUTHY_E2E_THEME:-0}" != 1 ] || GOAUTHY_E2E_THEME=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemeLive$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClient(Logo|Favicon)Live$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_LOGO_STATE_FILE="$temp/logo-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientLogoPersistVerify$'
[ "${GOAUTHY_E2E_LOGO:-0}" != 1 ] || GOAUTHY_E2E_LOGO=1 GOAUTHY_E2E_FAVICON_STATE_FILE="$temp/favicon-state.json" GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientFaviconPersistVerify$'
[ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" != 1 ] || GOAUTHY_E2E_LOGIN_LOCATION=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((port + 4))" go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestLoginLocationRevokeLive$'
[ "${GOAUTHY_E2E_UPSTREAM_REGISTRY:-0}" != 1 ] || GOAUTHY_E2E_UPSTREAM_REGISTRY=1 GOAUTHY_E2E_URL="http://127.0.0.1:$port" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((port + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((port + 2))" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef go test -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUpstreamRegistryLive$'

echo 'DCR backchannel Kind E2E with pod replacement passed'
