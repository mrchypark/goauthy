#!/bin/sh
# Exercises exactly three HA pods racing to create one Generate API-key secret.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${E2E_PORT:=19994}"
: "${KIND_CLUSTER:=goauthy-generated-bootstrap-e2e}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:generated-bootstrap-e2e}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
: "${GOAUTHY_E2E_GENERATED_EXPIRY:=0}"
: "${GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS:=300}"
: "${GOAUTHY_E2E_GENERATED_QUORUM:=0}"

for command in cmp curl date docker go grep jq kind kubectl kustomize nc rm sed seq sleep; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be decimal' >&2; exit 1;; esac
[ "$E2E_PORT" -ge 1024 ] && [ "$E2E_PORT" -le 65532 ] || { echo 'E2E_PORT must leave three valid ports' >&2; exit 1; }
[ "$K8S_NAMESPACE" = goauthy ] || { echo 'K8S_NAMESPACE must be goauthy for this fixed manifest' >&2; exit 1; }
case "$GOAUTHY_E2E_GENERATED_EXPIRY" in 0|1) ;; *) echo 'GOAUTHY_E2E_GENERATED_EXPIRY must be 0 or 1' >&2; exit 1;; esac
case "$GOAUTHY_E2E_GENERATED_QUORUM" in 0|1) ;; *) echo 'GOAUTHY_E2E_GENERATED_QUORUM must be 0 or 1' >&2; exit 1;; esac
[ "$GOAUTHY_E2E_GENERATED_EXPIRY" = 0 ] || [ "$GOAUTHY_E2E_GENERATED_QUORUM" = 0 ] || { echo 'generated expiry and quorum profiles are mutually exclusive' >&2; exit 1; }
case "$GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS" in ''|*[!0-9]*) echo 'GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS must be decimal' >&2; exit 1;; esac
[ "$GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS" -ge 180 ] && [ "$GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS" -le 900 ] || { echo 'generated expiry TTL must be between 180 and 900 seconds' >&2; exit 1; }
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null 2>&1 && { echo "refusing to use existing kind cluster: $KIND_CLUSTER" >&2; exit 1; }

. "$root/scripts/e2e-port-lock.sh"
e2e_port_lock_acquire
temp_dir=$(mktemp -d)
created=false
forwards=
cleanup() {
	status=$?
	trap - 0 1 2 15
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	[ "$created" = true ] && kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15

for offset in 0 1 2; do
	port=$((E2E_PORT + offset))
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "E2E port $port is already in use" >&2; exit 1; }
done

# This must precede all Docker and Kind work; it intentionally stops this E2E
# without building an image when the host cannot safely hold a cluster.
(
	cd "$root"
	./scripts/e2e-preflight.sh host-capacity
)

umask 077
generated_ttl=0
[ "$GOAUTHY_E2E_GENERATED_EXPIRY" = 0 ] || generated_ttl=$GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS
expiry_floor=0
# The first winner cannot expire before this pre-deployment clock floor plus
# the configured TTL. Keep that lower bound independent of rollout duration.
[ "$GOAUTHY_E2E_GENERATED_EXPIRY" = 0 ] || expiry_floor=$(date +%s)
printf '%s\n' '[{"name":"generated-reader","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]' >"$temp_dir/api-key-bootstrap.json"
browser_phc=$(printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password")

docker build --tag "$GOAUTHY_IMAGE" "$root"
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s
created=true
"$root/scripts/e2e-preflight.sh" kind-inotify --cluster "$KIND_CLUSTER"
context=kind-$KIND_CLUSTER
api_server=$(kubectl config view --raw --minify --context "$context" -o jsonpath='{.clusters[0].cluster.server}')
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$GOAUTHY_IMAGE" --name "$KIND_CLUSTER"
kubectl --context "$context" apply -f "$root/deploy/k8s/namespace.yaml"
kubectl --context "$context" -n "$K8S_NAMESPACE" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=minio-root-user=goauthy-e2e --from-literal=minio-root-password=goauthy-e2e-minio-password \
	--from-file=api-key-bootstrap="$temp_dir/api-key-bootstrap.json"
kustomize build "$root/deploy/e2e-generated-bootstrap" | sed -e "s#goauthy:e2e#$GOAUTHY_IMAGE#g" -e "s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" -e '/name: GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS/{n;s#value: "0"#value: "'"$generated_ttl"'"#;}' | kubectl --context "$context" apply -f -
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/minio --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=complete job/minio-init --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s

retrieve() {
	pod=$1
	output=$2
	kubectl --context "$context" -n "$K8S_NAMESPACE" exec "pod/$pod" -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output"
	jq -e 'length == 1 and .[0].kind == "api-key" and .[0].id == "generated-reader" and .[0].field == "token" and (. [0].value | startswith("generated-reader$"))' "$output" >/dev/null
}
for pod in 0 1 2; do retrieve "goauthy-$pod" "$temp_dir/entries-$pod.json"; done
cmp "$temp_dir/entries-0.json" "$temp_dir/entries-1.json"
cmp "$temp_dir/entries-0.json" "$temp_dir/entries-2.json"
# Scan both the externally presented name$secret token and its raw secret. A
# log containing either form is a credential disclosure.
jq -r '.[0].value, (.[0].value | split("$")[1])' "$temp_dir/entries-0.json" >"$temp_dir/token-patterns"

assert_no_token_in_logs() {
	pod=$1
	name=$2
	shift 2
	kubectl --context "$context" -n "$K8S_NAMESPACE" logs "pod/$pod" "$@" >"$temp_dir/$name.log"
	if grep -F -f "$temp_dir/token-patterns" "$temp_dir/$name.log" >/dev/null; then
		echo 'generated API-key token appeared in a pod log' >&2
		exit 1
	fi
}
start_forwards() {
	for pod in 0 1 2; do
		kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 "pod/goauthy-$pod" "$((E2E_PORT + pod)):8080" >"$temp_dir/forward-$pod.log" 2>&1 &
		forwards="$forwards $!"
	done
	for pod in 0 1 2; do
		log=$temp_dir/forward-$pod.log
		for _ in $(seq 1 120); do grep -q '^Forwarding from 127.0.0.1:' "$log" && break; sleep 1; done
		grep -q '^Forwarding from 127.0.0.1:' "$log" || { sed -n '1,80p' "$log" >&2; exit 1; }
	done
}
stop_forwards() {
	for pid in $forwards; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in $forwards; do wait "$pid" 2>/dev/null || true; done
	forwards=
}
authorize_all() {
	for pod in 0 1 2; do
		config=$temp_dir/curl-$pod.conf
		jq -jr '.[0].value' "$temp_dir/entries-0.json" | sed 's/^/header = "Authorization: API-Key /; s/$/"/' >"$config"
		curl --fail --silent --show-error --config "$config" "http://127.0.0.1:$((E2E_PORT + pod))/auth/v1/api_keys/generated-reader/test" >"$temp_dir/auth-$pod.json"
		jq -e '.name == "generated-reader"' "$temp_dir/auth-$pod.json" >/dev/null
	done
}

expired_retrieval() {
	pod=$1
	output=$temp_dir/expired-$pod.json
	err=$temp_dir/expired-$pod.err
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get "pod/$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
	[ "$ready" = True ] || { echo 'pod was not Ready during generated export expiry check' >&2; return 2; }
	if kubectl --context "$context" -n "$K8S_NAMESPACE" exec "pod/$pod" -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output" 2>"$err"; then
		return 1
	else
		exec_status=$?
	fi
	[ "$exec_status" -eq 1 ] || { echo 'generated export retrieval returned a transport error' >&2; return 2; }
	[ ! -s "$output" ] || { echo 'expired generated export retrieval emitted plaintext' >&2; return 2; }
	grep -F 'goauthy-bootstrap-secrets: generated bootstrap secret container expired' "$err" >/dev/null && return 0
	grep -F 'goauthy-bootstrap-secrets: read API-key bootstrap file: open /var/lib/goauthy/generated-bootstrap.secrets: no such file or directory' "$err" >/dev/null && return 0
	echo 'generated export retrieval failed unexpectedly; refusing to treat a transport error as expiry' >&2
	return 2
}

wait_expired_exports() {
	# The winner is created before readiness. Add one worker interval after the
	# latest possible deadline so the authenticated purge loop can remove it.
	deadline=$(( $(date +%s) + generated_ttl + 90 ))
	while [ "$(date +%s)" -le "$deadline" ]; do
		expired=0
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			if expired_retrieval "$pod"; then
				[ "$(date +%s)" -ge $((expiry_floor + generated_ttl)) ] || { echo 'generated export expired before its original deadline floor' >&2; return 2; }
				expired=$((expired + 1))
			else
				status=$?
				[ "$status" -eq 1 ] || return "$status"
			fi
		done
		[ "$expired" -eq 3 ] && return 0
		sleep 1
	done
	echo 'generated exports did not expire by the bounded wall-clock deadline' >&2
	return 1
}

absent_retrieval() {
	pod=$1
	output=$temp_dir/after-restart-$pod.json
	err=$temp_dir/after-restart-$pod.err
	ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get "pod/$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
	[ "$ready" = True ] || { echo 'pod was not Ready during post-restart export check' >&2; return 2; }
	if kubectl --context "$context" -n "$K8S_NAMESPACE" exec "pod/$pod" -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output" 2>"$err"; then
		echo 'generated export was recreated after expiry restart' >&2
		return 2
	else
		exec_status=$?
	fi
	[ "$exec_status" -eq 1 ] || { echo 'post-restart generated export retrieval returned a transport error' >&2; return 2; }
	[ ! -s "$output" ] || { echo 'post-restart generated export retrieval emitted plaintext' >&2; return 2; }
	grep -F 'goauthy-bootstrap-secrets: read API-key bootstrap file: open /var/lib/goauthy/generated-bootstrap.secrets: no such file or directory' "$err" >/dev/null && return 0
	grep -F 'goauthy-bootstrap-secrets: generated bootstrap secret container expired' "$err" >/dev/null && return 1
	echo 'post-restart generated export retrieval failed unexpectedly' >&2
	return 2
}

wait_absent_exports() {
	deadline=$(( $(date +%s) + 90 ))
	while [ "$(date +%s)" -le "$deadline" ]; do
		absent=0
		for pod in goauthy-0 goauthy-1 goauthy-2; do
			if absent_retrieval "$pod"; then
				absent=$((absent + 1))
			else
				status=$?
				[ "$status" -eq 1 ] || return "$status"
			fi
		done
		[ "$absent" -eq 3 ] && return 0
		sleep 1
	done
	echo 'expired generated exports were not purged after restart' >&2
	return 1
}

start_forwards
authorize_all
stop_forwards
for pod in 0 1 2; do assert_no_token_in_logs "goauthy-$pod" "before-replacement-$pod"; done

if [ "$GOAUTHY_E2E_GENERATED_QUORUM" = 1 ]; then
	members_before=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get secret goauthy-secrets -o jsonpath='{.data.rhiza-members}')
	survivor_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	removed_uid_1=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}')
	removed_uid_2=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-2 -o jsonpath='{.metadata.uid}')
	kubectl --context "$context" -n "$K8S_NAMESPACE" scale statefulset/goauthy --replicas=1
	kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=delete pod/goauthy-1 pod/goauthy-2 --timeout=180s
	current_survivor_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	[ "$survivor_uid" = "$current_survivor_uid" ] || { echo 'quorum survivor was replaced while scaling down' >&2; exit 1; }

	kubectl --context "$context" -n "$K8S_NAMESPACE" port-forward --address=127.0.0.1 pod/goauthy-0 "$E2E_PORT:8080" >"$temp_dir/forward-survivor.log" 2>&1 &
	forwards="$forwards $!"
	for _ in $(seq 1 120); do grep -q '^Forwarding from 127.0.0.1:' "$temp_dir/forward-survivor.log" && break; sleep 1; done
	grep -q '^Forwarding from 127.0.0.1:' "$temp_dir/forward-survivor.log" || { sed -n '1,80p' "$temp_dir/forward-survivor.log" >&2; exit 1; }
	live_status=$(curl --silent --show-error --connect-timeout 1 --max-time 3 --output "$temp_dir/quorum-livez" --write-out '%{http_code}' "http://127.0.0.1:$E2E_PORT/livez") || { echo 'quorum survivor liveness request had a transport failure' >&2; exit 1; }
	[ "$live_status" = 204 ] || { echo 'quorum survivor liveness did not return HTTP 204' >&2; exit 1; }
	ready_status=$(curl --silent --show-error --connect-timeout 1 --max-time 3 --output "$temp_dir/quorum-readyz" --write-out '%{http_code}' "http://127.0.0.1:$E2E_PORT/readyz") || { echo 'quorum readiness request had a transport failure' >&2; exit 1; }
	[ "$ready_status" = 503 ] || { echo 'quorum survivor readiness did not return HTTP 503' >&2; exit 1; }
	quorum_auth_status=$(curl --silent --show-error --connect-timeout 1 --max-time 3 --config "$temp_dir/curl-0.conf" --output "$temp_dir/quorum-api-key" --write-out '%{http_code}' "http://127.0.0.1:$E2E_PORT/auth/v1/api_keys/generated-reader/test") || { echo 'quorum API-key request had a transport failure' >&2; exit 1; }
	case "$quorum_auth_status" in 401|503) ;; *) echo 'quorum API-key request did not return HTTP 401 or 503' >&2; exit 1;; esac
	stop_forwards
	assert_no_token_in_logs goauthy-0 quorum-outage-0

	kubectl --context "$context" -n "$K8S_NAMESPACE" scale statefulset/goauthy --replicas=3
	kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
	kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
	[ "$members_before" = "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get secret goauthy-secrets -o jsonpath='{.data.rhiza-members}')" ] || { echo 'Rhiza membership changed during quorum profile' >&2; exit 1; }
	[ "$removed_uid_1" != "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}')" ] || { echo 'quorum recovery did not replace pod goauthy-1' >&2; exit 1; }
	[ "$removed_uid_2" != "$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-2 -o jsonpath='{.metadata.uid}')" ] || { echo 'quorum recovery did not replace pod goauthy-2' >&2; exit 1; }
	for pod in 0 1 2; do retrieve "goauthy-$pod" "$temp_dir/entries-quorum-restored-$pod.json"; done
	cmp "$temp_dir/entries-0.json" "$temp_dir/entries-quorum-restored-0.json"
	cmp "$temp_dir/entries-0.json" "$temp_dir/entries-quorum-restored-1.json"
	cmp "$temp_dir/entries-0.json" "$temp_dir/entries-quorum-restored-2.json"
	start_forwards
	authorize_all
	stop_forwards
	for pod in 0 1 2; do assert_no_token_in_logs "goauthy-$pod" "after-quorum-restore-$pod"; done
elif [ "$GOAUTHY_E2E_GENERATED_EXPIRY" = 0 ]; then
	old_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	kubectl --context "$context" -n "$K8S_NAMESPACE" delete pod goauthy-0 --wait=true --timeout=180s
	for _ in $(seq 1 180); do
		new_uid=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
		ready=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
		[ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] && break
		sleep 1
	done
	[ "$new_uid" != "$old_uid" ] && [ "$ready" = True ] || { echo 'pod-0 replacement did not become Ready' >&2; exit 1; }
	retrieve goauthy-0 "$temp_dir/entries-replacement.json"
	cmp "$temp_dir/entries-0.json" "$temp_dir/entries-replacement.json"
	start_forwards
	authorize_all
	stop_forwards
	for pod in 0 1 2; do assert_no_token_in_logs "goauthy-$pod" "after-replacement-$pod"; done
else
	wait_expired_exports
	start_forwards
	authorize_all
	stop_forwards
	for pod in 0 1 2; do assert_no_token_in_logs "goauthy-$pod" "after-expiry-$pod"; done

	before_uid_0=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	before_uid_1=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}')
	before_uid_2=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-2 -o jsonpath='{.metadata.uid}')
	kubectl --context "$context" -n "$K8S_NAMESPACE" rollout restart statefulset/goauthy
	kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=300s
	kubectl --context "$context" -n "$K8S_NAMESPACE" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
	after_uid_0=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-0 -o jsonpath='{.metadata.uid}')
	after_uid_1=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-1 -o jsonpath='{.metadata.uid}')
	after_uid_2=$(kubectl --context "$context" -n "$K8S_NAMESPACE" get pod goauthy-2 -o jsonpath='{.metadata.uid}')
	[ "$before_uid_0" != "$after_uid_0" ] && [ "$before_uid_1" != "$after_uid_1" ] && [ "$before_uid_2" != "$after_uid_2" ] || { echo 'roll restart did not replace every generated-bootstrap pod' >&2; exit 1; }
	# The initialized tombstone is immutable: a full restart must not re-export
	# or replace the original API key after the first deadline.
	wait_absent_exports
	start_forwards
	authorize_all
	stop_forwards
	for pod in 0 1 2; do assert_no_token_in_logs "goauthy-$pod" "after-expiry-restart-$pod"; done
fi

case "$GOAUTHY_E2E_GENERATED_QUORUM:$GOAUTHY_E2E_GENERATED_EXPIRY" in
	1:0) echo 'exact-three generated-bootstrap quorum Kind E2E passed' ;;
	0:1) echo 'exact-three generated-bootstrap expiry Kind E2E passed' ;;
	0:0) echo 'exact-three generated-bootstrap Kind E2E passed' ;;
esac
