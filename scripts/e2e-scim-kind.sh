#!/bin/sh
# Exercises SCIM create/delete delivery through a disposable three-pod Rhiza Kind cluster.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

: "${E2E_PORT:=18680}"
: "${KIND_CLUSTER:=goauthy-scim-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:e2e}"
: "${GOAUTHY_SCIM_FIXTURE_IMAGE:=goauthy-scim-fixture:e2e}"
: "${GOAUTHY_SMTP_IMAGE:=goauthy-smtp-sink:e2e}"
for command in docker kind kubectl curl go kustomize openssl grep nc jq; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1;; esac
case "$K8S_NAMESPACE" in goauthy) ;; *) echo 'K8S_NAMESPACE must be goauthy' >&2; exit 1;; esac
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65530 ] || { echo 'E2E_PORT must leave room for five additional ports (1024..65530)' >&2; exit 1; }
scim_failure_events=${GOAUTHY_SCIM_FAILURE_EVENTS:-0}
case "$scim_failure_events" in
	0|1)
		failure_test=TestSCIMFailureEvents
		persistence_test=TestSCIMFailureEventPersisted
		failure_flag=GOAUTHY_E2E_SCIM_FAILURE_EVENTS
		persistence_flag=GOAUTHY_E2E_SCIM_FAILURE_EVENT_PERSISTENCE
		;;
	resources)
		failure_test=TestSCIMResourceFailureEvents
		persistence_test=TestSCIMResourceFailureEventsPersisted
		failure_flag=GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS
		persistence_flag=GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS_PERSISTENCE
		;;
	*) echo 'GOAUTHY_SCIM_FAILURE_EVENTS must be 0, 1 or resources' >&2; exit 1;;
esac
for image in "$GOAUTHY_IMAGE" "$GOAUTHY_SCIM_FIXTURE_IMAGE" "$GOAUTHY_SMTP_IMAGE"; do case "$image" in ''|*[!A-Za-z0-9./:_@-]*) echo 'E2E image names contain unsupported characters' >&2; exit 1;; esac; done
if kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null; then echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; fi

temp_dir=$(mktemp -d)
cluster_created=false
forward0=
forward1=
forward2=
smtp_forward=
fixture_admin_forward=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in "$forward0" "$forward1" "$forward2" "$smtp_forward" "$fixture_admin_forward"; do [ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }; done
	if [ "$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$KIND_CLUSTER"; then
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get all 2>&1 | sed 's/^/[resources] /' || true
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
		for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs "pod/$pod" --all-containers=true 2>&1 | sed "s/^/[$pod] /" || true; done
		kubectl --context "kind-$KIND_CLUSTER" -n "$K8S_NAMESPACE" logs deployment/goauthy-scim-fixture --all-containers=true 2>&1 | sed 's/^/[fixture] /' || true
	fi
	if [ "$cluster_created" = true ] && kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null; then kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true; fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 15
e2e_port_lock_acquire
for port in "$E2E_PORT" "$((E2E_PORT + 1))" "$((E2E_PORT + 2))" "$((E2E_PORT + 3))" "$((E2E_PORT + 4))"; do ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E host port $port is already in use; choose E2E_PORT" >&2; exit 1; }; done

openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy SCIM E2E Test CA' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/fixture.key" -out "$temp_dir/fixture.csr" -subj '/CN=goauthy-scim-fixture.goauthy.svc.cluster.local' -addext 'subjectAltName=DNS:goauthy-scim-fixture.goauthy.svc,DNS:goauthy-scim-fixture.goauthy.svc.cluster.local' >/dev/null 2>&1
openssl x509 -req -in "$temp_dir/fixture.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/fixture.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1

./scripts/e2e-preflight.sh host-capacity
docker build --tag "$GOAUTHY_IMAGE" .
docker build --target scim-fixture --tag "$GOAUTHY_SCIM_FIXTURE_IMAGE" .
docker build --target smtp-sink --tag "$GOAUTHY_SMTP_IMAGE" .
kind create cluster --name "$KIND_CLUSTER" --wait 120s
cluster_created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$KIND_CLUSTER"
context="kind-$KIND_CLUSTER"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$context')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_SCIM_FIXTURE_IMAGE" --name "$KIND_CLUSTER"
kind load docker-image "$GOAUTHY_SMTP_IMAGE" --name "$KIND_CLUSTER"
kind_node="$KIND_CLUSTER-control-plane"
docker exec "$kind_node" crictl pull minio/minio:RELEASE.2025-04-22T22-12-26Z
docker exec "$kind_node" crictl pull minio/mc:RELEASE.2025-04-16T18-13-26Z

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
	--from-literal=minio-root-password=goauthy-e2e-minio-password \
	--from-literal=password-reset-key=0123456789abcdef0123456789abcdef \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-scim-fixture-tls --from-file=tls.crt="$temp_dir/fixture.crt" --from-file=tls.key="$temp_dir/fixture.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-scim-provider-token --from-literal=fixture-token=goauthy-scim-e2e-token --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-scim-provider-ca --from-file=fixture-ca.crt="$temp_dir/ca.crt" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
printf '%s\n' '{"providers":[{"id":"fixture","base_url":"https://goauthy-scim-fixture.goauthy.svc.cluster.local/scim/v2","token_file":"/run/scim-provider-token/fixture-token","ca_file":"/run/scim-provider-ca/fixture-ca.crt","sync_delete_users":true}]}' >"$temp_dir/providers.json"
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-scim-providers --from-file=providers.json="$temp_dir/providers.json" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

kustomize build --load-restrictor LoadRestrictionsNone deploy/e2e-scim >"$temp_dir/scim.yaml"
sed -i.bak "s#goauthy:e2e#$GOAUTHY_IMAGE#g; s#goauthy-scim-fixture:e2e#$GOAUTHY_SCIM_FIXTURE_IMAGE#g; s#goauthy-smtp-sink:e2e#$GOAUTHY_SMTP_IMAGE#g; s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" "$temp_dir/scim.yaml"
rm -f "$temp_dir/scim.yaml.bak"
kubectl --context "$context" apply -f "$temp_dir/scim.yaml"
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/goauthy-smtp-sink --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status deployment/goauthy-scim-fixture --timeout=180s
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
set_forward() {
	case "$1" in forward0) forward0=$2;; forward1) forward1=$2;; forward2) forward2=$2;; smtp_forward) smtp_forward=$2;; fixture_admin_forward) fixture_admin_forward=$2;; esac
}
start_forward() {
	name=$1 port=$2 target=$3 log=$4
	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "$target" "$port" >"$log" 2>&1 &
	forwarded_pid=$!
	set_forward "$name" "$forwarded_pid"
	if ! wait_forward "$forwarded_pid" "$log"; then stop_forward "$name"; return 1; fi
}
stop_forward() {
	case "$1" in forward0) pid=$forward0;; forward1) pid=$forward1;; forward2) pid=$forward2;; smtp_forward) pid=$smtp_forward;; fixture_admin_forward) pid=$fixture_admin_forward;; *) echo "unknown forward: $1" >&2; return 1;; esac
	[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	set_forward "$1" ''
}
start_forwards() {
	start_forward forward0 "$E2E_PORT:8080" pod/goauthy-0 "$temp_dir/goauthy-0.log"
	start_forward forward1 "$((E2E_PORT + 1)):8080" pod/goauthy-1 "$temp_dir/goauthy-1.log"
	start_forward forward2 "$((E2E_PORT + 2)):8080" pod/goauthy-2 "$temp_dir/goauthy-2.log"
	start_forward smtp_forward "$((E2E_PORT + 3)):8082" service/goauthy-smtp-sink "$temp_dir/smtp.log"
	fixture_pod=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod -l app.kubernetes.io/name=goauthy-scim-fixture -o jsonpath='{.items[0].metadata.name}')
	[ -n "$fixture_pod" ] || { echo 'SCIM fixture pod not found' >&2; exit 1; }
	start_forward fixture_admin_forward "$((E2E_PORT + 4)):8083" "pod/$fixture_pod" "$temp_dir/fixture-admin.log"
}
wait_fixture() {
	want=$1
	subject=$(cat "$temp_dir/scim-subject")
	[ -n "$subject" ] || { echo 'SCIM subject state is empty' >&2; return 1; }
	for _ in $(seq 1 90); do
		state=$(curl --fail --silent --show-error "http://127.0.0.1:$((E2E_PORT + 4))/admin/state")
	case "$want" in
			created) remote_id=$(printf '%s' "$state" | jq -er --arg subject "$subject" '[.users[] | select(.externalId == $subject)] | if length == 1 then .[0].id else error("expected one remote user") end' 2>/dev/null) && printf '%s\n' "$remote_id" >"$temp_dir/scim-remote-id" && chmod 600 "$temp_dir/scim-remote-id" && return 0;;
			group-created|group-empty)
				group_id=$(cat "$temp_dir/scim-group") || return 1
				expected=$(printf '%s' "$state" | jq -c --arg subject "$subject" --arg want "$want" '[.users[] | select(.externalId == "bootstrap-admin" or ($want == "group-created" and .externalId == $subject)) | .id] | sort')
				printf '%s' "$state" | jq -e --arg group_id "$group_id" --argjson expected "$expected" '([.groups[] | select(.externalId == ("group:" + $group_id))] | length == 1) and (([.groups[] | select(.externalId == ("group:" + $group_id))][0].members | map(.value) | sort) == $expected)' >/dev/null && return 0;;
		deleted) remote_id=$(cat "$temp_dir/scim-remote-id") && printf '%s' "$state" | jq -e --arg subject "$subject" --arg remote_id "$remote_id" '([.users[] | select(.externalId == $subject)] | length == 0) and any(.calls[]; .method == "DELETE" and .path == ("/scim/v2/Users/" + $remote_id))' >/dev/null && return 0;;
		esac
		sleep 1
	done
	echo "timed out waiting for SCIM fixture $want state: $state" >&2
	return 1
}
run_phase() {
	phase=$1 primary=$2 secondary=$3
	GOAUTHY_E2E_SCIM_PHASE="$phase" GOAUTHY_E2E_URL="http://127.0.0.1:$primary" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$secondary" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 4))" GOAUTHY_E2E_SCIM_GROUP_STATE_FILE="$temp_dir/scim-group" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_SCIM_STATE_FILE="$temp_dir/scim-subject" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -count=1 ./test/e2e/browser -run '^TestSCIMUserDeletionAcrossPods$'
}
start_forwards
run_failure_events() {
	env "$failure_flag=1" GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE="$temp_dir/scim-failure-event.json" GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((E2E_PORT + 2))" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 4))" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -timeout=28m -v -count=1 ./test/e2e/browser -run "^$failure_test\$"
	stop_forward forward0
	old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	[ -n "$old_uid" ] || { echo 'goauthy-0 UID is empty' >&2; return 1; }
	kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
	kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
	kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
	new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
	[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'goauthy-0 did not become a new Ready pod' >&2; return 1; }
	start_forward forward0 "$E2E_PORT:8080" pod/goauthy-0 "$temp_dir/goauthy-0-failure-replaced.log"
	env "$persistence_flag=1" GOAUTHY_E2E_SCIM_FAILURE_EVENT_STATE="$temp_dir/scim-failure-event.json" GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_TERTIARY_URL="http://127.0.0.1:$((E2E_PORT + 2))" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 4))" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -timeout=2m -v -count=1 ./test/e2e/browser -run "^$persistence_test\$"
}
if [ "$scim_failure_events" != 0 ]; then
	run_failure_events
	echo 'Kind SCIM failure event and persistence E2E passed'
	exit 0
fi
GOAUTHY_E2E_SCIM_CREATE_WAKE=1 GOAUTHY_E2E_URL="http://127.0.0.1:$E2E_PORT" GOAUTHY_E2E_SECONDARY_URL="http://127.0.0.1:$((E2E_PORT + 1))" GOAUTHY_E2E_SCIM_ADMIN_URL="http://127.0.0.1:$((E2E_PORT + 4))" GOAUTHY_E2E_SMTP_SINK_URL="http://127.0.0.1:$((E2E_PORT + 3))" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" go test -v -count=1 ./test/e2e/browser -run '^TestSCIMAdminCreateWake$'
run_phase create "$E2E_PORT" "$((E2E_PORT + 1))"
stop_forward forward0
stop_forward forward1
stop_forward forward2
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout restart statefulset/goauthy
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
start_forward forward0 "$E2E_PORT:8080" pod/goauthy-0 "$temp_dir/goauthy-0-restarted.log"
start_forward forward1 "$((E2E_PORT + 1)):8080" pod/goauthy-1 "$temp_dir/goauthy-1-restarted.log"
start_forward forward2 "$((E2E_PORT + 2)):8080" pod/goauthy-2 "$temp_dir/goauthy-2-restarted.log"
wait_fixture created
wait_fixture group-created
run_phase delete "$((E2E_PORT + 2))" "$((E2E_PORT + 1))"
old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
[ -n "$old_uid" ] || { echo 'goauthy-0 UID is empty' >&2; exit 1; }
stop_forward forward0
kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ -n "$new_uid" ] && [ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'goauthy-0 did not become a new Ready pod' >&2; exit 1; }
start_forward forward0 "$E2E_PORT:8080" pod/goauthy-0 "$temp_dir/goauthy-0-replaced.log"
wait_fixture deleted
wait_fixture group-empty
run_phase verify-deleted "$E2E_PORT" "$((E2E_PORT + 1))"
echo 'Kind SCIM E2E passed'
