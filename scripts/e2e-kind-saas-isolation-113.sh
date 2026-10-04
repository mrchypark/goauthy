#!/bin/sh
set -eu
umask 077

# Run inside the task-state-owned cluster wrapper; that wrapper provisions and
# removes the cluster on success or failure.
: "${KIND_CLUSTER:?set KIND_CLUSTER to the owned qualification cluster}"
: "${GOAUTHY_IMAGE:?set GOAUTHY_IMAGE to the immutable candidate image reference}"
: "${GOAUTHY_CANDIDATE_SOURCE:?set GOAUTHY_CANDIDATE_SOURCE to the reviewed source SHA}"
: "${GOAUTHY_E2E_BROWSER_PASSWORD:?set the local synthetic bootstrap password}"
: "${GOAUTHY_E2E_CLIENT_SECRET:?set the local synthetic bootstrap client secret}"
: "${ISOLATION113_EVIDENCE_DIR:?set an absolute task-state directory for local evidence}"
# The released-image path requires an immutable @sha256 reference. The
# manual-CI source-build path instead requires the wrapper-supplied OCI
# manifest digest and binds it to the imported node image below.
case "$GOAUTHY_IMAGE" in
	*@sha256:*) ;;
	*) [ "${GOAUTHY_LOCAL_CANDIDATE:-0}" = 1 ] || { echo 'GOAUTHY_IMAGE must be an immutable @sha256 reference' >&2; exit 1; } ;;
esac
. "$(dirname -- "$0")/e2e-kind-saas-isolation-113-node-pins.sh"

namespace=goauthy
fixture_image=goauthy-saas-isolation-fixture:e2e
driver_image=goauthy-saas-isolation-driver:e2e
fixture_host=api-key-fixture.e2e.test
fixture_token=goauthy-isolation113-synthetic-key
context=kind-$KIND_CLUSTER
sampler_pid=
forward_pid=
failure_capture_done=false
runner_completed=false

capture_failure_state() {
	[ "$failure_capture_done" = true ] && return 0
	failure_capture_done=true
	capture_dir=$ISOLATION113_EVIDENCE_DIR/failure-capture
	mkdir -p "$capture_dir" || return 0
	chmod 700 "$capture_dir" || return 0
	{
		printf 'captured_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf 'cluster=%s\nnamespace=%s\n' "$KIND_CLUSTER" "$namespace"
	} >"$capture_dir/capture-status.txt" 2>/dev/null || return 0
	capture_one() {
		capture_name=$1
		shift
		case $capture_name in
			cri-*)
				if timeout --signal=TERM --kill-after=1s 8s "$@" >"$capture_dir/$capture_name" 2>"$capture_dir/$capture_name.stderr"; then capture_rc=0; else capture_rc=$?; fi
				;;
			*)
				if "$@" >"$capture_dir/$capture_name" 2>"$capture_dir/$capture_name.stderr"; then capture_rc=0; else capture_rc=$?; fi
				;;
		esac
		printf '%s_exit=%s\n' "$capture_name" "$capture_rc" >>"$capture_dir/capture-status.txt" 2>/dev/null || true
	}
	capture_one pods.json kubectl --request-timeout=5s --context "$context" -n "$namespace" get pods -o json
	capture_one jobs.json kubectl --request-timeout=5s --context "$context" -n "$namespace" get jobs -o json
	capture_one events.json kubectl --request-timeout=5s --context "$context" -n "$namespace" get events --sort-by=.metadata.creationTimestamp -o json
	# One raw CRI snapshot on failure; the live sampler already tracks current IDs.
	capture_one cri-stats-all.json docker exec "${KIND_CLUSTER}-control-plane" crictl stats --all -o json
	capture_one cri-containers-all.json docker exec "${KIND_CLUSTER}-control-plane" crictl ps --all -o json
	for index in 0 1 2; do
		capture_one "goauthy-$index-current.log" kubectl --request-timeout=5s --context "$context" -n "$namespace" logs "pod/goauthy-$index" -c goauthy --timestamps
		capture_one "goauthy-$index-previous.log" kubectl --request-timeout=5s --context "$context" -n "$namespace" logs "pod/goauthy-$index" -c goauthy --previous --timestamps
	done
	capture_one versity-current.log kubectl --request-timeout=5s --context "$context" -n "$namespace" logs pod/versity-0 -c versity --timestamps
	capture_one versity-previous.log kubectl --request-timeout=5s --context "$context" -n "$namespace" logs pod/versity-0 -c versity --previous --timestamps
	if ! jq -se 'length == 3 and all(.[]; (.items | type) == "array")' "$capture_dir/pods.json" "$capture_dir/jobs.json" "$capture_dir/events.json" >/dev/null 2>&1 ||
		! jq -e '.stats | type == "array"' "$capture_dir/cri-stats-all.json" >/dev/null 2>&1 ||
		! jq -e '.containers | type == "array"' "$capture_dir/cri-containers-all.json" >/dev/null 2>&1; then
		echo 'capture_json_validation=failed' >>"$capture_dir/capture-status.txt" 2>/dev/null || true
	else
		echo 'capture_json_validation=passed' >>"$capture_dir/capture-status.txt" 2>/dev/null || true
	fi
	chmod 600 "$capture_dir"/* 2>/dev/null || true
}

for tool in docker kind kubectl kustomize openssl go curl nc tar jq timeout; do
	command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
case "$ISOLATION113_EVIDENCE_DIR" in /*) ;; *) echo 'ISOLATION113_EVIDENCE_DIR must be absolute' >&2; exit 1;; esac
case "$ISOLATION113_EVIDENCE_DIR" in "$PWD"/*) echo 'evidence directory must be outside the repository' >&2; exit 1;; esac
test ! -e "$ISOLATION113_EVIDENCE_DIR" || { echo 'evidence directory already exists; refusing to overwrite' >&2; exit 1; }
kind get clusters | grep -Fx "$KIND_CLUSTER" >/dev/null || { echo "owned Kind cluster not found: $KIND_CLUSTER" >&2; exit 1; }
docker image inspect "$GOAUTHY_IMAGE" >/dev/null
if [ "${GOAUTHY_LOCAL_CANDIDATE:-0}" = 1 ]; then
	: "${GOAUTHY_CANDIDATE_MANIFEST_DIGEST:?set GOAUTHY_CANDIDATE_MANIFEST_DIGEST for a local source-build candidate}"
	printf '%s' "$GOAUTHY_CANDIDATE_MANIFEST_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo 'GOAUTHY_CANDIDATE_MANIFEST_DIGEST must be a sha256 digest' >&2; exit 1; }
	candidate_manifest_digest=$GOAUTHY_CANDIDATE_MANIFEST_DIGEST
else
	candidate_manifest_digest=${GOAUTHY_IMAGE##*@}
fi
candidate_config_blob=$(docker image save "$GOAUTHY_IMAGE" | tar -xOf - manifest.json | jq -er '.[0].Config | select(test("^blobs/sha256/[0-9a-f]{64}$"))')
candidate_config_digest=sha256:${candidate_config_blob##*/}
runner_source_head=$(git rev-parse --verify HEAD)
[ -z "$(git status --porcelain --untracked-files=all)" ] || { echo 'helper images require a clean committed checkout' >&2; exit 1; }
if [ "${GOAUTHY_LOCAL_CANDIDATE:-0}" = 1 ]; then
	# The candidate and the helper images are built from the same reviewed
	# checkout. Keep the two heads as separate evidence fields but fail closed
	# if a source build is requested for a source other than the checkout HEAD.
	[ "$GOAUTHY_CANDIDATE_SOURCE" = "$runner_source_head" ] ||
		{ echo 'source-build candidate source does not match the helper checkout HEAD' >&2; exit 1; }
fi
for port in 18443 18444 18445; do
	! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "metrics port already in use: $port" >&2; exit 1; }
done

temp_dir=$(mktemp -d)
chmod 700 "$temp_dir"
image_container=
fixture_manifest_digest=
fixture_config_digest=
driver_manifest_digest=
driver_config_digest=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ "$runner_completed" != true ] && [ "$failure_capture_done" != true ]; then capture_failure_state || true; fi
	[ -z "$sampler_pid" ] || { kill -TERM "$sampler_pid" >/dev/null 2>&1 || true; wait "$sampler_pid" 2>/dev/null || true; }
	[ -z "$forward_pid" ] || { kill -TERM "$forward_pid" >/dev/null 2>&1 || true; wait "$forward_pid" 2>/dev/null || true; }
	[ -z "$image_container" ] || docker rm "$image_container" >/dev/null 2>&1 || true
	rm -rf "$temp_dir"
	exit "$status"
}
trap cleanup 0 1 2 15

mkdir -p "$ISOLATION113_EVIDENCE_DIR"
printf '%s\n' "$runner_source_head" >"$ISOLATION113_EVIDENCE_DIR/helper-source-head.txt"

docker buildx build --load --metadata-file "$ISOLATION113_EVIDENCE_DIR/fixture-build-metadata.json" -f deploy/e2e-saas-isolation-113/Dockerfile --target fixture -t "$fixture_image" .
docker buildx build --load --metadata-file "$ISOLATION113_EVIDENCE_DIR/driver-build-metadata.json" -f deploy/e2e-saas-isolation-113/Dockerfile --target driver -t "$driver_image" .
fixture_manifest_digest=$(jq -er '
	."containerimage.digest" as $digest
	| ."containerimage.descriptor" as $descriptor
	| select(($digest|type)=="string" and ($digest|test("^sha256:[0-9a-f]{64}$")))
	| select($descriptor.mediaType=="application/vnd.oci.image.manifest.v1+json" and $descriptor.digest==$digest)
	| select(($descriptor.platform.os|type)=="string" and ($descriptor.platform.architecture|type)=="string")
	| $digest
' "$ISOLATION113_EVIDENCE_DIR/fixture-build-metadata.json")
fixture_loaded_digest=$(docker image inspect --format '{{.Id}}' "$fixture_image")
fixture_config_blob=$(docker image save "$fixture_image" | tar -xOf - manifest.json | jq -er '.[0].Config | select(type=="string" and test("^blobs/sha256/[0-9a-f]{64}$"))')
fixture_config_digest=sha256:${fixture_config_blob##*/}
if jq -e 'has("containerimage.config.digest")' "$ISOLATION113_EVIDENCE_DIR/fixture-build-metadata.json" >/dev/null; then
	fixture_metadata_config_digest=$(jq -er '."containerimage.config.digest" | select(type=="string" and test("^sha256:[0-9a-f]{64}$"))' "$ISOLATION113_EVIDENCE_DIR/fixture-build-metadata.json")
	[ "$fixture_metadata_config_digest" = "$fixture_config_digest" ] || { echo 'fixture BuildKit config digest differs from the saved image archive' >&2; exit 1; }
fi
driver_manifest_digest=$(jq -er '
	."containerimage.digest" as $digest
	| ."containerimage.descriptor" as $descriptor
	| select(($digest|type)=="string" and ($digest|test("^sha256:[0-9a-f]{64}$")))
	| select($descriptor.mediaType=="application/vnd.oci.image.manifest.v1+json" and $descriptor.digest==$digest)
	| select(($descriptor.platform.os|type)=="string" and ($descriptor.platform.architecture|type)=="string")
	| $digest
' "$ISOLATION113_EVIDENCE_DIR/driver-build-metadata.json")
driver_loaded_digest=$(docker image inspect --format '{{.Id}}' "$driver_image")
driver_config_blob=$(docker image save "$driver_image" | tar -xOf - manifest.json | jq -er '.[0].Config | select(type=="string" and test("^blobs/sha256/[0-9a-f]{64}$"))')
driver_config_digest=sha256:${driver_config_blob##*/}
if jq -e 'has("containerimage.config.digest")' "$ISOLATION113_EVIDENCE_DIR/driver-build-metadata.json" >/dev/null; then
	driver_metadata_config_digest=$(jq -er '."containerimage.config.digest" | select(type=="string" and test("^sha256:[0-9a-f]{64}$"))' "$ISOLATION113_EVIDENCE_DIR/driver-build-metadata.json")
	[ "$driver_metadata_config_digest" = "$driver_config_digest" ] || { echo 'driver BuildKit config digest differs from the saved image archive' >&2; exit 1; }
fi
[ "$fixture_loaded_digest" = "$fixture_manifest_digest" ] || [ "$fixture_loaded_digest" = "$fixture_config_digest" ] || { echo 'fixture loaded image ID matches neither BuildKit digest' >&2; exit 1; }
[ "$driver_loaded_digest" = "$driver_manifest_digest" ] || [ "$driver_loaded_digest" = "$driver_config_digest" ] || { echo 'driver loaded image ID matches neither BuildKit digest' >&2; exit 1; }
jq -n \
	--arg source_head "$runner_source_head" \
	--arg fixture_ref "$fixture_image" --arg fixture_manifest "$fixture_manifest_digest" --arg fixture_config "$fixture_config_digest" --arg fixture_loaded "$fixture_loaded_digest" \
	--arg driver_ref "$driver_image" --arg driver_manifest "$driver_manifest_digest" --arg driver_config "$driver_config_digest" --arg driver_loaded "$driver_loaded_digest" \
	'{source_head:$source_head,fixture:{image_ref:$fixture_ref,manifest_digest:$fixture_manifest,config_digest:$fixture_config,loaded_image_id:$fixture_loaded},driver:{image_ref:$driver_ref,manifest_digest:$driver_manifest,config_digest:$driver_config,loaded_image_id:$driver_loaded}}' \
	>"$ISOLATION113_EVIDENCE_DIR/helper-image-pins.json"

record_container_pins() {
	container_name=$1
	image_ref=$2
	manifest_digest=$3
	config_digest=$4
	expected_count=$5
	node_pins=$6
	jq -ce --arg container "$container_name" --arg ref "$image_ref" --arg manifest "$manifest_digest" --arg config "$config_digest" --argjson count "$expected_count" --argjson node_pins "$node_pins" -f scripts/e2e-kind-saas-isolation-runtime-pins.jq
}

printf 'candidate_source=%s\ncandidate_image=%s\ncandidate_manifest_digest=%s\ncandidate_config_digest=%s\n' "$GOAUTHY_CANDIDATE_SOURCE" "$GOAUTHY_IMAGE" "$candidate_manifest_digest" "$candidate_config_digest" >&2
prestart_spec=$(kubectl --context "$context" -n "$namespace" get statefulset goauthy -o json | jq -ce --arg image "$GOAUTHY_IMAGE" '
	select(.spec.replicas==0 and ([.spec.template.spec.containers[]|select(.name=="goauthy" and .image==$image)]|length)==1)
	| {name:.metadata.name,replicas:.spec.replicas,goauthyImage:([.spec.template.spec.containers[]|select(.name=="goauthy")|.image][0])}
') || { echo 'baseline GoAuthy StatefulSet must be present at zero replicas with the selected immutable candidate image' >&2; exit 1; }
printf '%s\n' "$prestart_spec" | tee "$ISOLATION113_EVIDENCE_DIR/pod-image-pins-before.txt" >&2
printf 'candidate_source=%s\ncandidate_image=%s\n' "$GOAUTHY_CANDIDATE_SOURCE" "$GOAUTHY_IMAGE"
printf 'candidate_config_digest=%s\n' "$candidate_config_digest"

openssl genrsa -out "$temp_dir/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -sha256 -key "$temp_dir/ca.key" -out "$temp_dir/ca.crt" -days 1 -subj '/CN=GoAuthy Isolation113 Local CA' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/fixture.key" -out "$temp_dir/fixture.csr" -subj "/CN=$fixture_host" -addext "subjectAltName=DNS:$fixture_host" >/dev/null 2>&1
openssl x509 -req -in "$temp_dir/fixture.csr" -CA "$temp_dir/ca.crt" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/fixture.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1
image_container=$(docker create "$GOAUTHY_IMAGE")
docker cp "$image_container:/etc/ssl/certs/ca-certificates.crt" "$temp_dir/roots.crt"
docker rm "$image_container" >/dev/null
image_container=
cat "$temp_dir/roots.crt" "$temp_dir/ca.crt" >"$temp_dir/ca-certificates.crt"

kind load docker-image "$fixture_image" "$driver_image" --name "$KIND_CLUSTER"
node_image_pin_snapshot "$fixture_image" "$fixture_config_digest" "$temp_dir/fixture-node-pins.json"
node_image_pin_snapshot "$driver_image" "$driver_config_digest" "$temp_dir/driver-node-pins.json"
jq '. + {fixture: (.fixture + {node_pins: $fixture_node_pins}), driver: (.driver + {node_pins: $driver_node_pins})}' \
	--argjson fixture_node_pins "$(cat "$temp_dir/fixture-node-pins.json")" \
	--argjson driver_node_pins "$(cat "$temp_dir/driver-node-pins.json")" \
	"$ISOLATION113_EVIDENCE_DIR/helper-image-pins.json" >"$temp_dir/helper-image-pins.json" ||
	{ echo 'failed to record verified helper node pins' >&2; exit 1; }
mv "$temp_dir/helper-image-pins.json" "$ISOLATION113_EVIDENCE_DIR/helper-image-pins.json"
kubectl --context "$context" -n "$namespace" create configmap isolation113-ca --from-file=ca-certificates.crt="$temp_dir/ca-certificates.crt" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$namespace" create secret generic isolation113-fixture-tls --from-file=tls.crt="$temp_dir/fixture.crt" --from-file=tls.key="$temp_dir/fixture.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
umask 077
printf '%s' "$fixture_token" >"$temp_dir/token"
kubectl --context "$context" -n "$namespace" create secret generic isolation113-token --from-file=token="$temp_dir/token" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$namespace" create secret generic isolation113-driver \
	--from-literal=username=admin \
	--from-literal=password="$GOAUTHY_E2E_BROWSER_PASSWORD" \
	--from-literal=client-secret="$GOAUTHY_E2E_CLIENT_SECRET" \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kustomize build deploy/kind-saas-isolation-113 | sed \
	-e "s#image: goauthy:e2e\$#image: $GOAUTHY_IMAGE#" >"$temp_dir/profile.yaml"
[ "$(grep -Fc "image: $GOAUTHY_IMAGE" "$temp_dir/profile.yaml")" -eq 1 ] || { echo 'rendered profile must retain the selected immutable GoAuthy image' >&2; exit 1; }
! grep -F 'image: goauthy:e2e' "$temp_dir/profile.yaml" >/dev/null || { echo 'rendered profile still contains the mutable GoAuthy base image' >&2; exit 1; }
kubectl --context "$context" apply -f "$temp_dir/profile.yaml"
kubectl --context "$context" -n "$namespace" get statefulset goauthy -o json | jq -e '
	.spec.template.spec.containers[] | select(.name=="goauthy") | .env as $env
	| ([$env[]|select(.name=="GOAUTHY_CONNECTIONS_RESOURCE")|.value] == ["https://goauthy.connections.local.test"])
	and ([$env[]|select(.name=="GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES")|.value] as $raw | ($raw|length)==1 and (($raw[0]|fromjson|index("https://api.example.test/v1"))!=null) and (($raw[0]|fromjson|index("https://goauthy.connections.local.test"))!=null))
' >/dev/null || { echo 'GoAuthy connection-use resource profile is not configured or does not preserve allowed resources' >&2; exit 1; }
kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=240s
kubectl --context "$context" -n "$namespace" wait --for=condition=Ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s
kubectl --context "$context" -n "$namespace" get pods -l app.kubernetes.io/name=goauthy -o json |
	record_container_pins sidecarfixture "$fixture_image" "$fixture_manifest_digest" "$fixture_config_digest" 3 "$(cat "$temp_dir/fixture-node-pins.json")" >"$ISOLATION113_EVIDENCE_DIR/fixture-runtime-image-pins.json"
node_image_pin_snapshot "$GOAUTHY_IMAGE" "$candidate_config_digest" "$temp_dir/candidate-node-pins.json" ||
	{ echo 'candidate node pin snapshot failed' >&2; exit 1; }
candidate_node_digests=$(jq -er '.runtime_digests | join(" ")' "$temp_dir/candidate-node-pins.json")
cp "$temp_dir/candidate-node-pins.json" "$ISOLATION113_EVIDENCE_DIR/candidate-node-pins.json"
if [ "${GOAUTHY_LOCAL_CANDIDATE:-0}" = 1 ]; then
	# Strong payload binding: the canonical runtime reference must resolve to
	# the exact OCI manifest digest produced by the source build, not merely a
	# matching config digest. The manifest and config are recorded separately.
	assert_candidate_manifest_binding "$ISOLATION113_EVIDENCE_DIR/candidate-node-pins.json" "$candidate_manifest_digest" ||
		{ echo 'source-build candidate node manifest digest does not match the built OCI manifest digest' >&2; exit 1; }
fi
authorize_url='http://127.0.0.1:18443/oidc/authorize?client_id=goauthy-dev&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A5555%2Fcallback&scope=goauthy.read%20offline_access&state=isolation113-functional-readiness&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256'
readiness_deadline=$(( $(date +%s) + 60 ))
readiness_evidence=$ISOLATION113_EVIDENCE_DIR/authorize-readiness.tsv
: >"$readiness_evidence"
for pod in goauthy-0 goauthy-1 goauthy-2; do
	kubectl --context "$context" -n "$namespace" port-forward --address 127.0.0.1 "pod/$pod" 18443:8080 >"$temp_dir/authorize-port-forward.log" 2>&1 &
	forward_pid=$!
	status=000
	while [ "$(date +%s)" -lt "$readiness_deadline" ]; do
		status=$(curl -sS -o /dev/null -w '%{http_code}' --header 'Host: goauthy-client.goauthy.svc.cluster.local:8080' --max-time 2 "$authorize_url" 2>/dev/null || true)
		[ "$status" = 200 ] && break
		sleep 1
	done
	kill -TERM "$forward_pid" >/dev/null 2>&1 || true
	wait "$forward_pid" 2>/dev/null || true
	forward_pid=
	[ "$status" = 200 ] || { echo "authorize endpoint did not become functional on $pod within the shared 60-second startup window (last HTTP status: $status)" >&2; exit 1; }
	printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pod" "$status" >>"$readiness_evidence"
done
start_ms=$(( $(date +%s) * 1000 + 30000 ))
kubectl --context "$context" -n "$namespace" create configmap isolation113-run --from-literal=start-unix-ms="$start_ms" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

printf '%s\n' "$prestart_spec" >"$ISOLATION113_EVIDENCE_DIR/pod-image-pins-before.txt"
ready_after=$(kubectl --context "$context" -n "$namespace" get pods -l app.kubernetes.io/name=goauthy -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase} {.status.containerStatuses[?(@.name=="goauthy")].ready} {.status.containerStatuses[?(@.name=="goauthy")].imageID} {.spec.containers[?(@.name=="goauthy")].image}{"\n"}{end}')
printf '%s\n' "$ready_after" | tee "$ISOLATION113_EVIDENCE_DIR/pod-image-pins-after.txt" >&2
assert_candidate_pods "$ready_after" "$candidate_node_digests" || { echo 'post-overlay app image references or runtime digests differ from the selected immutable candidate' >&2; exit 1; }
printf '%s\n' "$ready_after" >"$ISOLATION113_EVIDENCE_DIR/pod-image-pins.txt"

sample_output=$ISOLATION113_EVIDENCE_DIR/container-samples.jsonl
echo 'stage=three-member fixture overlay ready; launching bounded IAM/API-key diagnostic'
kubectl create --dry-run=client -f deploy/kind-saas-isolation-113/driver-job.yaml -o json | jq -e '
	[.spec.template.spec.containers[]|select(.name=="driver").env[]|select(.name=="GOAUTHY_E2E_ISOLATION113_FIXTURE_URL")|.value] == ["https://api-key-fixture.e2e.test/healthy"]
' >/dev/null || { echo 'driver fixture URL is missing or does not use portless HTTPS' >&2; exit 1; }
kubectl --context "$context" -n "$namespace" apply -f deploy/kind-saas-isolation-113/driver-job.yaml
kube_ips=
for _ in $(seq 1 50); do
	kube_ips=$(kubectl --context "$context" -n "$namespace" get pods -l job-name=isolation113-driver -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}' 2>/dev/null || true)
	[ "$(printf '%s\n' "$kube_ips" | awk 'NF {n++} END {print n+0}')" -ge 3 ] && break
	sleep 1
done
[ "$(printf '%s\n' "$kube_ips" | awk 'NF {print}' | sort -u | awk 'END {print NR+0}')" -eq 3 ] || { echo 'expected three distinct driver pod IPs' >&2; exit 1; }
./scripts/e2e-kind-saas-isolation-sample.sh "$KIND_CLUSTER" "$namespace" "$sample_output" >"$ISOLATION113_EVIDENCE_DIR/sampler.log" 2>&1 &
sampler_pid=$!
job_status=0
kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/isolation113-driver --timeout=220s || job_status=$?
if [ "$job_status" -ne 0 ]; then capture_failure_state; fi
driver_pods=$(kubectl --context "$context" -n "$namespace" get pods -l job-name=isolation113-driver -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
driver_pod_count=$(printf '%s\n' "$driver_pods" | awk 'NF {n++} END {print n+0}')
[ "$driver_pod_count" -eq 3 ] || { echo "expected logs from three driver pods, found $driver_pod_count" >&2; job_status=1; }
if node_image_pin_snapshot "$driver_image" "$driver_config_digest" "$temp_dir/driver-node-pins.json"; then
	jq '. + {driver: (.driver + {node_pins: $driver_node_pins})}' \
		--argjson driver_node_pins "$(cat "$temp_dir/driver-node-pins.json")" \
		"$ISOLATION113_EVIDENCE_DIR/helper-image-pins.json" >"$temp_dir/helper-image-pins.json" &&
		mv "$temp_dir/helper-image-pins.json" "$ISOLATION113_EVIDENCE_DIR/helper-image-pins.json" ||
		{ echo 'failed to record refreshed driver node pins' >&2; job_status=1; }
else
	echo 'refreshed driver node pin snapshot failed' >&2
	job_status=1
fi
if ! kubectl --context "$context" -n "$namespace" get pods -l job-name=isolation113-driver -o json |
  record_container_pins driver "$driver_image" "$driver_manifest_digest" "$driver_config_digest" 3 "$(cat "$temp_dir/driver-node-pins.json")" >"$ISOLATION113_EVIDENCE_DIR/driver-runtime-image-pins.json"; then
	echo 'driver runtime image pins are missing or differ from the native build' >&2
	job_status=1
fi
: >"$ISOLATION113_EVIDENCE_DIR/driver.log"
for pod in $driver_pods; do
	driver_log="$ISOLATION113_EVIDENCE_DIR/driver-$pod.log"
	if kubectl --context "$context" -n "$namespace" logs "pod/$pod" --all-containers=true >"$driver_log" 2>&1; then
		[ -s "$driver_log" ] || { echo "driver log is empty: $pod" >&2; job_status=1; }
		cat "$driver_log" >>"$ISOLATION113_EVIDENCE_DIR/driver.log"
	else
		echo "failed to collect driver log: $pod" >&2
		job_status=1
	fi
done
[ -s "$ISOLATION113_EVIDENCE_DIR/driver.log" ] || { echo 'combined driver log is empty' >&2; job_status=1; }
validate_driver_log() {
	awk '
		/isolation113 phase=/ {
			p=r=o=s=x=""; for (i=1;i<=NF;i++) {split($i,a,"="); if(a[1]=="phase")p=a[2]; if(a[1]=="route")r=a[2]; if(a[1]=="outcome")o=a[2]; if(a[1]=="status")s=a[2]; if(a[1]=="operation")x=a[2]}
			if(r=="iam"&&o=="success")iam[p]++; if(r=="api-key")api[p,x]++; if(r=="api-key"&&x=="account"&&o=="success"&&s=="200")ok[p]++
		}
		END {exit !(iam["baseline"]==6&&iam["mixed"]==6&&iam["recovery"]==4&&api["mixed","slow-headers"]==2&&api["mixed","slow-body"]==2&&api["mixed","failure"]==1&&api["mixed","account"]==1&&api["recovery","account"]==4&&ok["mixed"]==1&&ok["recovery"]==4)}' "$1"
}
for pod in $driver_pods; do
	validate_driver_log "$ISOLATION113_EVIDENCE_DIR/driver-$pod.log" || { echo "driver diagnostic evidence invalid: $pod" >&2; job_status=1; capture_failure_state; }
done
sampler_status=0
if kill -TERM "$sampler_pid" >/dev/null 2>&1; then
	if wait "$sampler_pid" 2>/dev/null; then :; else sampler_status=$?; fi
else
	if wait "$sampler_pid" 2>/dev/null; then sampler_status=1; else sampler_status=$?; fi
fi
sampler_pid=
[ "$sampler_status" -eq 0 ] || { echo "resource sampler exited unexpectedly: status=$sampler_status" >&2; job_status=1; }
[ -s "$sample_output" ] || { echo 'resource sample file is missing or empty' >&2; job_status=1; }
if [ -s "$sample_output" ]; then
	jq -s -e '
		def valid_counter: type=="number" and isfinite and .>=0 and floor==. and .<=9007199254740991;
		def expected: ["goauthy-0/goauthy","goauthy-0/sidecarfixture","goauthy-1/goauthy","goauthy-1/sidecarfixture","goauthy-2/goauthy","goauthy-2/sidecarfixture"];
		length>0 and
		all(.[];
			(.hostTimestampUTC|type)=="string" and (.hostTimestampUTC|length)>0 and
			.namespace=="goauthy" and
			(.pod as $pod | (["goauthy-0","goauthy-1","goauthy-2"]|index($pod)) != null) and
			(.container=="goauthy" or .container=="sidecarfixture") and
			(.containerID|type)=="string" and (.containerID|length)>0 and
			(.cpuUsageCoreNanoSeconds|valid_counter) and
			(.memoryWorkingSetBytes|valid_counter) and
			(.unavailable|type)=="array" and
			([.unavailable[]|select(.!="rss-not-exposed")]|length)==0 and
			(if .memoryRSSBytes==null then (.unavailable|index("rss-not-exposed"))!=null else (.memoryRSSBytes|valid_counter) and (.unavailable|index("rss-not-exposed"))==null end)
		) and
		(group_by(.hostTimestampUTC)|all(.[];
			length==6 and ([.[]|.pod+"/"+.container]|unique|sort)==expected and
			([.[]|.containerID]|unique|length)==6
		))
	' "$sample_output" >/dev/null || { echo 'resource samples contain unavailable/invalid counters or an incomplete six-container timestamp batch' >&2; job_status=1; }
fi

for index in 0 1 2; do
	port=$((18443 + index))
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 "pod/goauthy-$index" "$port:443" >"$ISOLATION113_EVIDENCE_DIR/metrics-forward-$index.log" 2>&1 &
	forward_pid=$!
	metrics_ok=false
	metrics_drained=false
	for _ in $(seq 1 50); do
		if curl --silent --show-error --fail --connect-timeout 1 --max-time 2 --cacert "$temp_dir/ca.crt" --resolve "$fixture_host:$port:127.0.0.1" "https://$fixture_host:$port/metrics" >"$ISOLATION113_EVIDENCE_DIR/fixture-metrics-$index.json" 2>/dev/null && jq -e '. as $metrics | type=="object" and (["healthy","slow-headers","slow-body","fail"]|all(.[];. as $route|($metrics[$route]|type=="object" and ((.started|type)=="number") and ((.active|type)=="number") and ((.completed|type)=="number"))))' "$ISOLATION113_EVIDENCE_DIR/fixture-metrics-$index.json" >/dev/null 2>&1; then
			metrics_ok=true
			if jq -e 'all(.[]; .active == 0 and .completed == .started)' "$ISOLATION113_EVIDENCE_DIR/fixture-metrics-$index.json" >/dev/null 2>&1; then metrics_drained=true; break; fi
		fi
		sleep 0.2
	done
	kill -TERM "$forward_pid" >/dev/null 2>&1 || true
	wait "$forward_pid" 2>/dev/null || true
	[ "$metrics_ok" = true ] || { echo "fixture metrics are missing or invalid for goauthy-$index" >&2; job_status=1; }
	[ "$metrics_drained" = true ] || { echo "fixture requests did not naturally drain on goauthy-$index" >&2; job_status=1; }
	forward_pid=
done
jq -s -e 'length==3 and ([.[].healthy.started]|add)>=15 and ([.[]."slow-headers".started]|add)>=6 and ([.[]."slow-body".started]|add)>=6 and ([.[].fail.started]|add)>=3 and all(.[];all(.[];.active==0 and .completed==.started))' "$ISOLATION113_EVIDENCE_DIR/fixture-metrics-0.json" "$ISOLATION113_EVIDENCE_DIR/fixture-metrics-1.json" "$ISOLATION113_EVIDENCE_DIR/fixture-metrics-2.json" >/dev/null || { echo 'aggregate fixture counts or natural drain did not meet expectations' >&2; job_status=1; }

echo "candidate_source=$GOAUTHY_CANDIDATE_SOURCE"
echo "container_samples=$sample_output"
echo "driver_log=$ISOLATION113_EVIDENCE_DIR/driver.log"
echo "fixture_metrics=$ISOLATION113_EVIDENCE_DIR/fixture-metrics-{0,1,2}.json"
if [ "$job_status" -ne 0 ]; then
	capture_failure_state || true
	exit "$job_status"
fi
runner_completed=true
