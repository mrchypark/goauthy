#!/bin/sh
# Runs only against a dedicated kind cluster and always removes it on exit.
set -eu
umask 077
# shellcheck disable=SC1091 # path is resolved from this script, not the current directory
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

cluster=${KIND_CLUSTER:-goauthy-cilium-e2e}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
backend=${GOAUTHY_NETWORK_CHAOS_BACKEND:-cilium}
namespace=goauthy
port=${E2E_PORT:-18080}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
created=false
policy_created=false
tc_owned=false
context=
kind_node=
sandbox_pid=
sandbox_id=
sandbox_netns=
target_uid=
target_pod=

failure_diagnostics() {
	[ -n "$context" ] || return 0
	kubectl --context "$context" -n "$namespace" get pods -o json 2>/dev/null |
		jq -c '[.items[] | {pod:.metadata.name, phase:.status.phase, reason:(.status.reason // ""), containers:[.status.containerStatuses[]? | {name,ready,restartCount,reason:(.state.waiting.reason // .state.terminated.reason // ""),exitCode:(.state.terminated.exitCode // null)}]}]' >&2 || true
}

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$status" -ne 0 ]; then failure_diagnostics; fi
	if [ "$policy_created" = true ] && [ -n "$context" ]; then
		kubectl --context "$context" -n "$namespace" delete ciliumnetworkpolicy/isolate-goauthy-2-peer --ignore-not-found --wait=true >/dev/null 2>&1 || true
	fi
	if [ "$tc_owned" = true ] && [ -n "$kind_node" ] && [ -n "$sandbox_pid" ]; then
		tc_exec qdisc del dev eth0 clsact >/dev/null 2>&1 || true
	fi
	if [ "$created" = true ]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

for command in docker kind kubectl helm curl jq grep go; do
	command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }
done
case "$backend" in cilium|tc) ;; *) echo "GOAUTHY_NETWORK_CHAOS_BACKEND must be cilium or tc" >&2; exit 1;; esac
case "$backend/$cluster" in
	cilium/goauthy-cilium-e2e*|tc/goauthy-tc-network-e2e*) ;;
	*) echo "refusing non-dedicated $backend cluster name: $cluster" >&2; exit 1 ;;
esac
if kind get clusters | grep -qx "$cluster"; then
	echo "refusing to reuse existing kind cluster: $cluster" >&2
	exit 1
fi

cd "$root"
./scripts/e2e-preflight.sh host-capacity
bootstrap_user_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
generated_bootstrap_config=$temp_dir/generated-api-keys.json
printf '%s\n' '[{"name":"generated-reader","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]' >"$generated_bootstrap_config"
docker build --tag "$image" .
if [ "$backend" = cilium ]; then
	kind create cluster --name "$cluster" --config deploy/kind-cilium/kind.yaml
else
	kind create cluster --name "$cluster" --image kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5 --wait 120s
fi
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
context=kind-$cluster
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='kind-$cluster')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$image" --name "$cluster"

if [ "$backend" = cilium ]; then
	helm upgrade --install cilium oci://quay.io/cilium/charts/cilium \
		--kube-context "$context" \
		--version 1.20.0 --namespace kube-system --create-namespace \
		--values deploy/kind-cilium/cilium-values.yaml --wait --timeout 5m
	kubectl --context "$context" -n kube-system rollout status daemonset/cilium --timeout=5m
	kubectl --context "$context" -n kube-system rollout status deployment/cilium-operator --timeout=5m
	kubectl --context "$context" get crd ciliumnetworkpolicies.cilium.io >/dev/null
fi
kubectl --context "$context" wait --for=condition=Ready nodes --all --timeout=5m

kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
kubectl --context "$context" -n "$namespace" create secret generic goauthy-secrets \
	--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
	--from-literal=bootstrap-client=correct-horse-battery-staple \
	--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
	--from-literal=bootstrap-user-password-phc="$bootstrap_user_phc" \
	--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
	--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
	--from-literal=versity-root-user=goauthy-e2e \
	--from-literal=versity-root-password=goauthy-e2e-versity-password \
	--from-file=api-key-bootstrap="$generated_bootstrap_config" \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f -
base_manifest=$temp_dir/base-manifest.yaml
rendered_manifest=$temp_dir/rendered-manifest.yaml
kubectl kustomize deploy/e2e-generated-bootstrap >"$base_manifest"
awk -v image="$image" '
	$0 == "---" { stateful = 0; goauthy = 0 }
	$0 == "kind: StatefulSet" { stateful = 1 }
	stateful && $0 == "  name: goauthy" { goauthy = 1 }
	goauthy && $0 == "        image: goauthy:e2e" { replacements++; sub(/goauthy:e2e/, image) }
	{ print }
	END { if (replacements != 1) exit 1 }
' "$base_manifest" >"$rendered_manifest" || { echo 'failed to render exactly one GoAuthy image replacement' >&2; exit 1; }
grep -Fqx "        image: $image" "$rendered_manifest" || { echo 'rendered GoAuthy image invariant failed' >&2; exit 1; }
awk '
	$0 == "        - name: GOAUTHY_API_KEY_BOOTSTRAP_FILE" { key = 1 }
	key && $0 == "          value: /run/secrets/api-key-bootstrap" { bootstrap_file = 1; key = 0 }
	$0 == "        - name: GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE" { generated = 1 }
	generated && $0 == "          value: /var/lib/goauthy/generated-bootstrap.secrets" { generated_file = 1; generated = 0 }
	$0 == "        - name: GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS" { ttl = 1 }
	ttl && $0 == "          value: \"0\"" { ttl_zero = 1; ttl = 0 }
	END { exit !(bootstrap_file && generated_file && ttl_zero) }
' "$rendered_manifest" || { echo 'generated API-key bootstrap manifest invariant failed' >&2; exit 1; }
kubectl --context "$context" apply -f "$rendered_manifest"
kubectl --context "$context" -n "$namespace" rollout status statefulset/versity --timeout=3m
kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/versity-init --timeout=3m
kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=5m
[ "$backend" != cilium ] || kubectl --context "$context" -n "$namespace" get ciliumendpoint goauthy-2 >/dev/null

with_pod() (
	set -eu
	pod=$1
	callback=$2
	shift 2
	log=$temp_dir/$pod-forward.log
	forward=
	# shellcheck disable=SC2329 # invoked by the EXIT/signal trap below
	stop_forward() {
		if [ -n "$forward" ]; then
			kill "$forward" >/dev/null 2>&1 || true
			wait "$forward" 2>/dev/null || true
		fi
	}
	trap stop_forward 0 1 2 15
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 "pod/$pod" "$port":8080 >"$log" 2>&1 &
	forward=$!
	for _ in $(seq 1 50); do
		grep -q '^Forwarding from 127.0.0.1:' "$log" && break
		kill -0 "$forward" 2>/dev/null || { echo "port-forward exited for $pod" >&2; exit 1; }
		sleep 0.1
	done
	grep -q '^Forwarding from 127.0.0.1:' "$log" || { echo "port-forward did not become ready for $pod" >&2; exit 1; }
	"$callback" "http://127.0.0.1:$port" "$@"
)

ready_status() {
	base=$1
	curl --max-time 10 --silent --output /dev/null --write-out '%{http_code}' "$base/readyz"
}

jwks_kid() {
	base=$1
	curl --max-time 30 --fail --silent --show-error "$base/oidc/jwks.json" | jq -er '.keys[0].kid'
}

issue_token() {
	base=$1
	output=$2
	curl --max-time 30 --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" | jq -ejr '.access_token | strings | select(length > 0)' >"$output"
	test -s "$output"
}

assert_active() {
	base=$1
	token_file=$2
	payload=$(curl --max-time 30 --fail --silent --show-error -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token@$token_file" \
		"$base/oidc/introspect")
	printf '%s' "$payload" | jq -e '.active == true and .client_id == "goauthy-dev" and .scope == "goauthy.read"' >/dev/null
}

assert_partition_write_failure() {
	base=$1
	output=$2
	errors=$3
	if status=$(curl --max-time 70 --silent --show-error --output "$output" --write-out '%{http_code}' \
		-u goauthy-dev:correct-horse-battery-staple -H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" 2>"$errors"); then :; else
		echo 'isolated voter OAuth write had a transport failure or timeout' >&2
		return 1
	fi
	case "$status" in 500|503) ;; *) echo "isolated voter OAuth write returned HTTP $status" >&2; return 1;; esac
	jq -e 'type == "object" and (.error == "server_error" or .error == "temporarily_unavailable") and (has("access_token") | not)' "$output" >/dev/null || {
		echo "isolated voter OAuth write returned an invalid structured error for HTTP $status" >&2
		return 1
	}
}

retrieve_generated_bootstrap() {
	pod=$1
	output=$2
	kubectl --context "$context" -n "$namespace" exec "pod/$pod" -c goauthy -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output"
	jq -e 'length == 1 and .[0].kind == "api-key" and .[0].id == "generated-reader" and .[0].field == "token" and (. [0].value | type == "string" and test("^generated-reader\\$[A-Za-z0-9]{64}$"))' "$output" >/dev/null
}

assert_generated_key() {
	base=$1
	config=$2
	output=$3
	curl --fail --silent --show-error --max-time 30 --config "$config" "$base/auth/v1/api_keys/generated-reader/test" >"$output"
	jq -e '.name == "generated-reader"' "$output" >/dev/null
}

assert_generated_clients_read() {
	base=$1
	config=$2
	output=$3
	curl --fail --silent --show-error --max-time 30 --config "$config" "$base/auth/v1/clients/goauthy-dev/scopes" >"$output"
	jq -e '.client_id == "goauthy-dev" and (.allowed_scopes | type == "array") and (.default_scopes | type == "array")' "$output" >/dev/null
}

assert_generated_clients_update_denied() {
	base=$1
	config=$2
	output=$3
	errors=$4
	if status=$(curl --max-time 30 --silent --show-error --output "$output" --write-out '%{http_code}' --config "$config" \
		-X PUT -H 'Content-Type: application/json' --data '{"allowed_scopes":' \
		"$base/auth/v1/clients/goauthy-dev/scopes" 2>"$errors"); then :; else
		echo 'generated API-key denied Clients update had a transport failure or timeout' >&2
		return 1
	fi
	[ "$status" = 403 ] || { echo "generated API-key Clients update returned HTTP $status" >&2; return 1; }
	if grep -F 'goauthy-dev' "$output" >/dev/null; then
		echo 'generated API-key Clients update returned client data' >&2
		return 1
	fi
}

assert_generated_clients_read_unauthorized() {
	base=$1
	config=$2
	output=$3
	errors=$4
	if status=$(curl --max-time 30 --silent --show-error --output "$output" --write-out '%{http_code}' --config "$config" \
		"$base/auth/v1/clients/goauthy-dev/scopes" 2>"$errors"); then :; else
		echo 'isolated voter generated API-key Clients read had a transport failure or timeout' >&2
		return 1
	fi
	[ "$status" = 401 ] || { echo "isolated voter generated API-key Clients read returned HTTP $status" >&2; return 1; }
	if grep -F 'goauthy-dev' "$output" >/dev/null; then
		echo 'isolated voter generated API-key Clients read returned protected data' >&2
		return 1
	fi
}

assert_generated_key_unauthorized() {
	base=$1
	config=$2
	output=$3
	errors=$4
	if status=$(curl --max-time 30 --silent --show-error --output "$output" --write-out '%{http_code}' --config "$config" \
		"$base/auth/v1/api_keys/generated-reader/test" 2>"$errors"); then :; else
		echo 'isolated voter generated API-key self-test had a transport failure or timeout' >&2
		return 1
	fi
	[ "$status" = 401 ] || { echo "isolated voter generated API-key self-test returned HTTP $status" >&2; return 1; }
	if [ -s "$output" ]; then
		echo 'isolated voter generated API-key self-test returned key data' >&2
		return 1
	fi
}

assert_generated_log_redaction() {
	pod=$1
	patterns=$2
	output=$3
	kubectl --context "$context" -n "$namespace" logs "pod/$pod" -c goauthy >"$output"
	if grep -F -f "$patterns" "$output" >/dev/null; then
		echo 'generated API-key token appeared in a pod log' >&2
		return 1
	fi
}

wait_status() {
	pod=$1
	want=$2
	for _ in $(seq 1 60); do
		if status=$(with_pod "$pod" ready_status); then [ "$status" = "$want" ] && return; fi
		sleep 1
	done
	echo "$pod /readyz did not become $want" >&2
	return 1
}

assert_no_pvc_application() {
	kubectl --context "$context" -n "$namespace" get statefulset/goauthy -o json >"$temp_dir/no-pvc-statefulset.json"
	jq -e '(.spec.volumeClaimTemplates // [] | length) == 0 and ([.spec.template.spec.volumes[] | select(.name == "data" and has("emptyDir"))] | length) == 1 and ([.spec.template.spec.volumes[] | select(has("persistentVolumeClaim"))] | length) == 0' "$temp_dir/no-pvc-statefulset.json" >/dev/null
	for pod in goauthy-0 goauthy-1 goauthy-2; do
		kubectl --context "$context" -n "$namespace" get "pod/$pod" -o json >"$temp_dir/no-pvc-$pod.json"
		jq -e '([.spec.volumes[] | select(.name == "data" and has("emptyDir"))] | length) == 1 and ([.spec.volumes[] | select(has("persistentVolumeClaim"))] | length) == 0' "$temp_dir/no-pvc-$pod.json" >/dev/null
	done
}

assert_running_app_image() {
	for pod in goauthy-0 goauthy-1 goauthy-2; do
		kubectl --context "$context" -n "$namespace" get "pod/$pod" -o json |
			jq -e --arg image "$image" '[.spec.containers[] | select(.name == "goauthy") | .image] == [$image] and ([.status.containerStatuses[] | select(.name == "goauthy" and .state.running != null)] | length) == 1' >/dev/null || {
			echo "$pod is not running the requested GoAuthy image" >&2
			return 1
		}
	done
}

snapshot_identity() {
	pod=$1
	container=$2
	output=$3
	kubectl --context "$context" -n "$namespace" get "pod/$pod" -o json |
		jq -er --arg container "$container" '[.metadata.uid, ([.status.containerStatuses[]? | select(.name == $container and .state.running != null and (.containerID | test("^containerd://[0-9a-f]+$"))) | .containerID] | if length == 1 then .[0] else error("missing running container identity") end)] | @tsv' >"$output"
}

assert_same_identity() {
	before=$1
	after=$2
	label=$3
	cmp "$before" "$after" || { echo "$label identity changed during peer partition" >&2; return 1; }
}

assert_versity_available() {
	kubectl --context "$context" -n "$namespace" wait --for=condition=ready pod/versity-0 --timeout=60s
	kubectl --context "$context" -n "$namespace" get endpointslice -l kubernetes.io/service-name=versity -o json |
		jq -e 'any(.items[].endpoints[]?; .conditions.ready == true)' >/dev/null
}

tc_exec() {
	validate_tc_sandbox || return 1
	docker exec "$kind_node" nsenter -t "$sandbox_pid" -n -- tc "$@"
}

validate_tc_sandbox() {
	[ -n "$target_uid" ] && [ -n "$sandbox_id" ] && [ -n "$sandbox_pid" ] && [ -n "$sandbox_netns" ] || {
		echo 'missing owned pod sandbox identity' >&2
		return 1
	}
	live_uid=$(kubectl --context "$context" -n "$namespace" get "pod/$target_pod" -o jsonpath='{.metadata.uid}') || return 1
	[ "$live_uid" = "$target_uid" ] || {
		echo 'isolated pod identity changed before tc operation' >&2
		return 1
	}
	current_sandbox=$(docker exec "$kind_node" crictl pods -o json | jq -er --arg id "$sandbox_id" --arg uid "$target_uid" '[.items[] | select(.id == $id and .metadata.uid == $uid and .state == "SANDBOX_READY") | .id] | if length == 1 then .[0] else error("owned sandbox no longer ready") end') || return 1
	[ "$current_sandbox" = "$sandbox_id" ] || { echo 'isolated pod sandbox mapping changed before tc operation' >&2; return 1; }
	current_pid=$(docker exec "$kind_node" crictl inspectp -o json "$sandbox_id" | jq -er '.info.pid | tonumber | select(. > 1)') || return 1
	[ "$current_pid" = "$sandbox_pid" ] || { echo 'isolated pod sandbox PID changed before tc operation' >&2; return 1; }
	docker exec "$kind_node" test -r "/proc/$sandbox_pid/ns/net" || return 1
	current_netns=$(docker exec "$kind_node" readlink "/proc/$sandbox_pid/ns/net") || return 1
	host_netns=$(docker exec "$kind_node" readlink /proc/1/ns/net) || return 1
	[ "$current_netns" = "$sandbox_netns" ] && [ "$current_netns" != "$host_netns" ] || {
		echo 'refusing changed, host, or empty network namespace' >&2
		return 1
	}
}

resolve_tc_sandbox() {
	target_pod=goauthy-2
	target_uid=$(kubectl --context "$context" -n "$namespace" get "pod/$target_pod" -o jsonpath='{.metadata.uid}') || return 1
	target_node=$(kubectl --context "$context" -n "$namespace" get "pod/$target_pod" -o jsonpath='{.spec.nodeName}') || return 1
	case "$target_uid/$target_node" in */|/*) echo 'missing isolated pod identity or node' >&2; return 1;; esac
	kind_nodes=$(kind get nodes --name "$cluster") || return 1
	[ "$(printf '%s\n' "$kind_nodes" | sed '/^$/d' | wc -l | tr -d ' ' )" -eq 1 ] || { echo 'tc backend requires exactly one Kind node' >&2; return 1; }
	kind_node=$kind_nodes
	[ "$target_node" = "$kind_node" ] || { echo 'isolated pod is not on the owned Kind node' >&2; return 1; }
	snapshot_identity "$target_pod" goauthy "$temp_dir/$target_pod-tc-live" || return 1
	assert_same_identity "$temp_dir/$target_pod-before" "$temp_dir/$target_pod-tc-live" "$target_pod" || return 1
	sandbox_id=$(docker exec "$kind_node" crictl pods -o json | jq -er --arg uid "$target_uid" '[.items[] | select(.metadata.uid == $uid and .state == "SANDBOX_READY") | .id] | if length == 1 then .[0] else error("expected exactly one ready pod sandbox") end') || return 1
	case "$sandbox_id" in *[!0-9a-f]*|'') echo 'invalid isolated pod sandbox ID' >&2; return 1;; esac
	sandbox_pid=$(docker exec "$kind_node" crictl inspectp -o json "$sandbox_id" | jq -er '.info.pid | tonumber | select(. > 1)') || return 1
	case "$sandbox_pid" in *[!0-9]*|'') echo 'invalid isolated pod sandbox PID' >&2; return 1;; esac
	docker exec "$kind_node" test -r "/proc/$sandbox_pid/ns/net" || return 1
	host_netns=$(docker exec "$kind_node" readlink /proc/1/ns/net) || return 1
	sandbox_netns=$(docker exec "$kind_node" readlink "/proc/$sandbox_pid/ns/net") || return 1
	[ -n "$sandbox_netns" ] && [ "$sandbox_netns" != "$host_netns" ] || { echo 'refusing host or empty network namespace' >&2; return 1; }
	validate_tc_sandbox || return 1
}

add_tc_partition() {
	resolve_tc_sandbox
	qdisc_before=$(tc_exec qdisc show dev eth0) || return 1
	if printf '%s\n' "$qdisc_before" | grep -Eq '(^|[[:space:]])clsact([[:space:]]|$)'; then
		echo 'refusing preexisting clsact qdisc in isolated pod network namespace' >&2
		return 1
	fi
	tc_exec qdisc add dev eth0 clsact
	tc_owned=true
	preference=1
	for direction in ingress egress; do
		for protocol in tcp udp; do
			for field in src_port dst_port; do
				tc_exec filter add dev eth0 "$direction" protocol ip pref "$preference" flower ip_proto "$protocol" "$field" 8444 action drop
				preference=$((preference + 1))
			done
		done
	done
}

assert_tc_drop_counters() {
	tc_exec -s filter show dev eth0 ingress >"$temp_dir/tc-ingress-stats"
	tc_exec -s filter show dev eth0 egress >"$temp_dir/tc-egress-stats"
	filter_count=$(awk '/action order [0-9][0-9]*: gact action drop/ { count++ } END { print count + 0 }' "$temp_dir/tc-ingress-stats" "$temp_dir/tc-egress-stats")
	[ "$filter_count" -eq 8 ] || { echo 'tc partition did not install eight owned drop filters' >&2; return 1; }
	awk '
		$1 == "Sent" { for (i = 1; i <= NF; i++) if ($i == "pkt" && $(i - 1) ~ /^[1-9][0-9]*$/) found = 1 }
		END { exit !found }
	' "$temp_dir/tc-ingress-stats" "$temp_dir/tc-egress-stats" || { echo 'tc partition filters did not observe peer traffic' >&2; return 1; }
}

apply_partition() {
	if [ "$backend" = cilium ]; then
		kubectl --context "$context" apply -f deploy/kind-cilium/partition-goauthy-2.yaml
		policy_created=true
		kubectl --context "$context" -n "$namespace" get ciliumnetworkpolicy isolate-goauthy-2-peer >/dev/null
	else
		add_tc_partition
	fi
}

remove_partition() {
	if [ "$backend" = cilium ]; then
		kubectl --context "$context" -n "$namespace" delete ciliumnetworkpolicy isolate-goauthy-2-peer --wait=true
		policy_created=false
	else
		tc_exec qdisc del dev eth0 clsact
		qdisc_after=$(tc_exec qdisc show dev eth0) || return 1
		if printf '%s\n' "$qdisc_after" | grep -Eq '(^|[[:space:]])clsact([[:space:]]|$)'; then
			echo 'owned tc clsact qdisc remained after recovery' >&2
			return 1
		fi
		tc_owned=false
	fi
}

for pod in goauthy-0 goauthy-1 goauthy-2; do
	wait_status "$pod" 204
done
assert_no_pvc_application
assert_running_app_image
for ordinal in 0 1 2; do
	pod=goauthy-$ordinal
	snapshot_identity "$pod" goauthy "$temp_dir/$pod-before"
	baseline_kid=$(with_pod "$pod" jwks_kid)
	printf '%s\n' "$baseline_kid" >"$temp_dir/$pod-kid-before"
done
snapshot_identity versity-0 versity "$temp_dir/versity-before"
assert_versity_available
with_pod goauthy-0 issue_token "$temp_dir/baseline-token"
for ordinal in 0 1 2; do with_pod "goauthy-$ordinal" assert_active "$temp_dir/baseline-token"; done
for ordinal in 0 1 2; do retrieve_generated_bootstrap "goauthy-$ordinal" "$temp_dir/generated-$ordinal.json"; done
for ordinal in 1 2; do
	cmp -s "$temp_dir/generated-0.json" "$temp_dir/generated-$ordinal.json" || {
		echo 'generated API-key exports differ between ready voters' >&2
		exit 1
	}
done
jq -r '.[0].value, (.[0].value | split("$")[1])' "$temp_dir/generated-0.json" >"$temp_dir/generated-token-patterns"
jq -jr '.[0].value' "$temp_dir/generated-0.json" | sed 's/^/header = "Authorization: API-Key /; s/$/"/' >"$temp_dir/generated-auth.conf"
for ordinal in 0 1 2; do
	with_pod "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/generated-auth-$ordinal.json"
	with_pod "goauthy-$ordinal" assert_generated_clients_read "$temp_dir/generated-auth.conf" "$temp_dir/generated-clients-$ordinal.json"
	with_pod "goauthy-$ordinal" assert_generated_clients_update_denied "$temp_dir/generated-auth.conf" "$temp_dir/generated-update-$ordinal.json" "$temp_dir/generated-update-$ordinal.err"
	assert_generated_log_redaction "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/generated-log-$ordinal"
done

apply_partition
wait_status goauthy-0 204
wait_status goauthy-1 204
wait_status goauthy-2 503
if [ "$backend" = tc ]; then assert_tc_drop_counters; fi

for issuer in 0 1; do
	with_pod "goauthy-$issuer" issue_token "$temp_dir/majority-token-$issuer"
	for verifier in 0 1; do with_pod "goauthy-$verifier" assert_active "$temp_dir/majority-token-$issuer"; done
done
for ordinal in 0 1; do
	with_pod "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/majority-generated-auth-$ordinal.json"
	with_pod "goauthy-$ordinal" assert_generated_clients_read "$temp_dir/generated-auth.conf" "$temp_dir/majority-generated-clients-$ordinal.json"
	with_pod "goauthy-$ordinal" assert_generated_clients_update_denied "$temp_dir/generated-auth.conf" "$temp_dir/majority-generated-update-$ordinal.json" "$temp_dir/majority-generated-update-$ordinal.err"
done
with_pod goauthy-2 assert_partition_write_failure "$temp_dir/minority-write.json" "$temp_dir/minority-write.err"
with_pod goauthy-2 assert_generated_key_unauthorized "$temp_dir/generated-auth.conf" "$temp_dir/minority-generated-auth.json" "$temp_dir/minority-generated-auth.err"
with_pod goauthy-2 assert_generated_clients_read_unauthorized "$temp_dir/generated-auth.conf" "$temp_dir/minority-generated-clients.json" "$temp_dir/minority-generated-clients.err"

remove_partition
for pod in goauthy-0 goauthy-1 goauthy-2; do
	wait_status "$pod" 204
done
assert_no_pvc_application
for token in "$temp_dir/baseline-token" "$temp_dir/majority-token-0" "$temp_dir/majority-token-1"; do
	for verifier in 0 1 2; do with_pod "goauthy-$verifier" assert_active "$token"; done
done
for issuer in 0 1 2; do
	with_pod "goauthy-$issuer" issue_token "$temp_dir/recovered-token-$issuer"
	for verifier in 0 1 2; do with_pod "goauthy-$verifier" assert_active "$temp_dir/recovered-token-$issuer"; done
done
for ordinal in 0 1 2; do
	pod=goauthy-$ordinal
	retrieve_generated_bootstrap "$pod" "$temp_dir/recovered-generated-$ordinal.json"
	cmp -s "$temp_dir/generated-0.json" "$temp_dir/recovered-generated-$ordinal.json" || {
		echo 'generated API-key export changed during peer partition' >&2
		exit 1
	}
	with_pod "$pod" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/recovered-generated-auth-$ordinal.json"
	with_pod "$pod" assert_generated_clients_read "$temp_dir/generated-auth.conf" "$temp_dir/recovered-generated-clients-$ordinal.json"
	with_pod "$pod" assert_generated_clients_update_denied "$temp_dir/generated-auth.conf" "$temp_dir/recovered-generated-update-$ordinal.json" "$temp_dir/recovered-generated-update-$ordinal.err"
	assert_generated_log_redaction "$pod" "$temp_dir/generated-token-patterns" "$temp_dir/recovered-generated-log-$ordinal"
	recovered_kid=$(with_pod "$pod" jwks_kid)
	cmp "$temp_dir/$pod-kid-before" - <<EOF
$recovered_kid
EOF
	snapshot_identity "$pod" goauthy "$temp_dir/$pod-after"
	assert_same_identity "$temp_dir/$pod-before" "$temp_dir/$pod-after" "$pod"
done
snapshot_identity versity-0 versity "$temp_dir/versity-after"
assert_same_identity "$temp_dir/versity-before" "$temp_dir/versity-after" versity-0
echo "network peer partition OAuth/no-PVC recovery passed"
