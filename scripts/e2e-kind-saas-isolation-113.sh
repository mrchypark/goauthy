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

startup_only=${GOAUTHY_113_STARTUP_ONLY:-0}
case "$startup_only" in
	0|1) ;;
	*) echo 'GOAUTHY_113_STARTUP_ONLY must be 0 or 1' >&2; exit 1 ;;
esac

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
job_status=0
object_store_pre_identity_0=
object_store_pre_identity_1=
object_store_pre_identity_2=
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

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

# Bounded native per-pod authentication-stage capture. Reuses the existing
# per-pod port-forward pattern to read the GoAuthy metrics listener on
# 127.0.0.1:9090 inside each pod network namespace. The raw exposition body is
# briefly held in a private 0600 file under the 0700 run temp directory, fed
# to the strict privacy-safe extractor, and deleted immediately after; the raw
# body is never logged or uploaded and only the extractor's bounded JSON is
# written to the evidence directory. A missing endpoint, a rejected series, or
# a wired-but-unobserved stage is a hard failure for the run.
object_store_pod_identity() {
	object_store_identity_index=$1
	kubectl --request-timeout=5s --context "$context" -n "$namespace" get "pod/goauthy-$object_store_identity_index" -o json 2>/dev/null |
		jq -er '
			def counter: type == "number" and isfinite and . >= 0 and floor == . and . <= 9007199254740991;
			.metadata.uid as $uid |
			[.status.containerStatuses[]? | select(.name == "goauthy")] as $containers |
			if (($uid | type) == "string" and ($uid | length) > 0 and ($containers | length) == 1 and ($containers[0].restartCount | counter))
			then [$uid, ($containers[0].restartCount | tostring)] | @tsv
			else error("identity unavailable") end
		' 2>/dev/null
}

# Best-effort native counter snapshot. Pod identity is compared only in shell
# memory; neither the UID nor restart count is written to evidence or logs.
# The raw response is held only in a shell variable and only the selected
# fixed counters are written to the evidence directory.
capture_object_store_snapshot() {
	object_store_phase=$1
	object_store_index=$2
	object_store_port=$3
	case "$object_store_phase:$object_store_index" in
		pre:0|pre:1|pre:2|post:0|post:1|post:2) ;;
		*) return 0 ;;
	esac
	object_store_output=$ISOLATION113_EVIDENCE_DIR/object-store-$object_store_phase-$object_store_index.json
	object_store_before=$(object_store_pod_identity "$object_store_index" 2>/dev/null) || object_store_before=
	object_store_fetch_ok=true
	object_store_raw=$(curl --silent --show-error --fail --connect-timeout 1 --max-time 2 \
		--header "Authorization: Bearer $metrics_token" \
		"http://127.0.0.1:$object_store_port/metrics/object-store" 2>/dev/null) || {
		object_store_raw=
		object_store_fetch_ok=false
	}
	object_store_after=$(object_store_pod_identity "$object_store_index" 2>/dev/null) || object_store_after=
	object_store_stable=true
	object_store_reason=
	if [ -z "$object_store_before" ] || [ -z "$object_store_after" ]; then
		object_store_stable=false
		object_store_reason=identity-unknown
	elif [ "$object_store_before" != "$object_store_after" ]; then
		object_store_stable=false
		object_store_reason=identity-unstable
	fi
	if [ "$object_store_stable" = true ]; then
		case "$object_store_phase:$object_store_index" in
			pre:0) object_store_pre_identity_0=$object_store_before ;;
			pre:1) object_store_pre_identity_1=$object_store_before ;;
			pre:2) object_store_pre_identity_2=$object_store_before ;;
			post:0) [ -n "$object_store_pre_identity_0" ] && [ "$object_store_pre_identity_0" = "$object_store_before" ] || { object_store_stable=false; object_store_reason=identity-unstable; } ;;
			post:1) [ -n "$object_store_pre_identity_1" ] && [ "$object_store_pre_identity_1" = "$object_store_before" ] || { object_store_stable=false; object_store_reason=identity-unstable; } ;;
			post:2) [ -n "$object_store_pre_identity_2" ] && [ "$object_store_pre_identity_2" = "$object_store_before" ] || { object_store_stable=false; object_store_reason=identity-unstable; } ;;
		esac
	fi
	if [ "$object_store_stable" = true ] && [ "$object_store_fetch_ok" = true ]; then
		if object_store_counters=$(printf '%s' "$object_store_raw" | jq -es --argjson pod "$object_store_index" '
			def counter: type == "number" and isfinite and . >= 0 and floor == . and . <= 9007199254740991;
			def expected_keys: [
				"replay_grouping_enabled","uploads","gets","lists","heads","deletes","failures",
				"bytes_uploaded","bytes_downloaded","s3_http_requests","s3_http_failures",
				"http_requests","http_failures","http_get_requests","http_put_requests",
				"http_head_requests","http_delete_requests","http_other_requests",
				"condition_conflicts","dedup_hits","sdk_retries","transport_failures",
				"http_4xx_unexpected","http_5xx","observed_request_identities",
				"observed_request_repeats","request_grouping_unknown",
				"replay_tracker_capacity_misses","replay_identity_capacity_misses",
				"replay_incomplete_operations","replay_tracked_operations_active","replay_open_readers"
			];
		if length != 1 then error("expected one object") else .[0] as $stats |
			if ($stats | type) != "object" or (($stats | keys | sort) != (expected_keys | sort))
			then error("unknown or missing keys")
			elif ([$stats[] | select((. | counter) | not)] | length) != 0
			then error("invalid counter")
			else {
				schema_version: 1, available: true, reason: null, pod_index: $pod,
				incarnation_stable: true,
				counters: {
					http_requests: $stats.http_requests,
					http_failures: $stats.http_failures,
					sdk_retries: $stats.sdk_retries,
					transport_failures: $stats.transport_failures,
					condition_conflicts: $stats.condition_conflicts,
					dedup_hits: $stats.dedup_hits,
					http_4xx_unexpected: $stats.http_4xx_unexpected,
					http_5xx: $stats.http_5xx
				}
			} end end
		' 2>/dev/null); then
			printf '%s\n' "$object_store_counters" >"$object_store_output" 2>/dev/null || true
			return 0
		else
			object_store_reason=capture-invalid
		fi
	elif [ "$object_store_stable" = true ]; then
		object_store_reason=capture-unavailable
	fi
	jq -n --argjson pod "$object_store_index" --arg reason "$object_store_reason" \
		'{schema_version:1,available:false,reason:$reason,pod_index:$pod,incarnation_stable:false,counters:null}' \
		>"$object_store_output" 2>/dev/null || true
	return 0
}

collect_auth_stage_metrics() {
	auth_phase=$1
	for auth_index in 0 1 2; do
		auth_port=$((19090 + auth_index))
		auth_raw=$temp_dir/auth-stage-$auth_phase-$auth_index.raw
		auth_out=$ISOLATION113_EVIDENCE_DIR/auth-stage-$auth_phase-$auth_index.json
		: >"$auth_raw"
		kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 "pod/goauthy-$auth_index" "$auth_port:9090" >"$temp_dir/auth-forward-$auth_phase-$auth_index.log" 2>&1 &
		forward_pid=$!
		auth_ok=false
		for _ in $(seq 1 50); do
			if curl --silent --show-error --fail --connect-timeout 1 --max-time 2 --header "Authorization: Bearer $metrics_token" "http://127.0.0.1:$auth_port/metrics" >"$auth_raw" 2>/dev/null; then
				auth_ok=true
				break
			fi
			sleep 0.2
		done
		capture_object_store_snapshot "$auth_phase" "$auth_index" "$auth_port" || true
		kill -TERM "$forward_pid" >/dev/null 2>&1 || true
		wait "$forward_pid" 2>/dev/null || true
		forward_pid=
		if [ "$auth_ok" != true ]; then
			echo "auth stage metrics endpoint did not respond on goauthy-$auth_index" >&2
			job_status=1
			rm -f "$auth_raw"
			continue
		fi
		auth_captured_ms=$(( $(date +%s) * 1000 ))
		if ! "$script_dir/collect-saas-isolation-113-auth-stage.sh" "$auth_index" "$auth_captured_ms" <"$auth_raw" >"$auth_out"; then
			echo "auth stage metrics were rejected on goauthy-$auth_index ($auth_phase)" >&2
			job_status=1
			: >"$auth_out"
		fi
		rm -f "$auth_raw"
		if [ "$auth_phase" = post ] && [ -s "$auth_out" ] && ! jq -e '[.stages[] | select(.count > 0)] | length > 0' "$auth_out" >/dev/null 2>&1; then
			echo "auth stage metrics were wired but no known stage was observed on goauthy-$auth_index" >&2
			job_status=1
		fi
	done
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
for port in 18443 18444 18445 19090 19091 19092; do
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
# Dedicated synthetic bearer token for the native per-pod metrics listener. It
# is generated for this run, mounted read-only into the GoAuthy container, and
# never written to any evidence artifact or log.
metrics_token=$(openssl rand -hex 32)
printf '%s' "$metrics_token" >"$temp_dir/metrics-token"
kubectl --context "$context" -n "$namespace" create secret generic isolation113-metrics-token --from-file=token="$temp_dir/metrics-token" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
kubectl --context "$context" -n "$namespace" create secret generic isolation113-driver \
	--from-literal=username=admin \
	--from-literal=password="$GOAUTHY_E2E_BROWSER_PASSWORD" \
	--from-literal=client-secret="$GOAUTHY_E2E_CLIENT_SECRET" \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null
profile_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# Enable the application's native metrics listener on the pod loopback only,
# with the run-scoped token file, so each pod can be scraped through the
# existing per-pod port-forward pattern. This adds no public endpoint, no
# sidecar, and no workload change beyond the observability listener. The
# secret is mounted 0400; the profile sets pod fsGroup 65532 and the GoAuthy
# container runs as runAsGroup 65532, so the kubelet grants the matching group
# read access and the listener can open the token file. No access is relaxed.
#
# The listener is composed into the rendered profile through a temporary
# overlay BEFORE the first apply. It must not be applied as a post-apply
# spec.template mutation: the GoAuthy StatefulSet keeps cluster member identity
# in the `data` emptyDir (deploy/k8s/statefulset.yaml), which is bound to the
# Pod lifetime. Changing spec.template after the StatefulSet exists rolls the
# Pods, discards that ephemeral state, and a voter that already registered
# returns with its local identity absent, aborting startup on the voter state
# continuity guard. Composing first keeps one apply and no post-apply
# template mutation.
mkdir -p "$temp_dir/metrics-overlay"
# kustomize rejects an absolute resource outside the overlay root ("new root
# cannot be absolute"), and load restrictions stay at their defaults. Reference
# the canonical profile relatively instead: ascend one level per component of
# the overlay's physical path (pwd -P resolves symlinked temp parents such as
# /var -> /private/var, which would otherwise miscount the ascent).
overlay_dir=$(CDPATH='' cd -P -- "$temp_dir/metrics-overlay" && pwd)
overlay_depth=$(printf '%s' "$overlay_dir" | awk -F/ '{ print NF-1 }')
overlay_up=$(awk -v depth="$overlay_depth" 'BEGIN { prefix = ""; for (i = 0; i < depth; i++) prefix = prefix "../"; printf "%s", prefix }')
profile_base="$overlay_up${profile_root#/}/deploy/kind-saas-isolation-113"
cat >"$temp_dir/metrics-overlay/metrics-enable-patch.json" <<'JSON'
{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"goauthy","namespace":"goauthy"},"spec":{"template":{"spec":{"containers":[{"name":"goauthy","env":[{"name":"GOAUTHY_METRICS_LISTEN_ADDR","value":"127.0.0.1:9090"},{"name":"GOAUTHY_METRICS_TOKEN_FILE","value":"/run/metrics-token/token"}],"volumeMounts":[{"name":"isolation113-metrics-token","mountPath":"/run/metrics-token","readOnly":true}]}],"volumes":[{"name":"isolation113-metrics-token","secret":{"secretName":"isolation113-metrics-token","defaultMode":256}}]}}}}
JSON
cat >"$temp_dir/metrics-overlay/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - $profile_base
patches:
  - path: metrics-enable-patch.json
YAML
kustomize build "$temp_dir/metrics-overlay" | sed \
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

printf '%s\n' "$prestart_spec" >"$ISOLATION113_EVIDENCE_DIR/pod-image-pins-before.txt"
ready_after=$(kubectl --context "$context" -n "$namespace" get pods -l app.kubernetes.io/name=goauthy -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase} {.status.containerStatuses[?(@.name=="goauthy")].ready} {.status.containerStatuses[?(@.name=="goauthy")].imageID} {.spec.containers[?(@.name=="goauthy")].image}{"\n"}{end}')
printf '%s\n' "$ready_after" | tee "$ISOLATION113_EVIDENCE_DIR/pod-image-pins-after.txt" >&2
assert_candidate_pods "$ready_after" "$candidate_node_digests" || { echo 'post-overlay app image references or runtime digests differ from the selected immutable candidate' >&2; exit 1; }
printf '%s\n' "$ready_after" >"$ISOLATION113_EVIDENCE_DIR/pod-image-pins.txt"

collect_auth_stage_metrics pre

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
	[ "$status" = 200 ] || {
		collect_auth_stage_metrics post || true
		echo "authorize endpoint did not become functional on $pod within the shared 60-second startup window (last HTTP status: $status)" >&2
		exit 1
	}
	printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$pod" "$status" >>"$readiness_evidence"
done

if [ "$job_status" -ne 0 ]; then
	echo 'pre-scrape auth stage capture failed; refusing to launch the workload without a pre observation' >&2
	capture_failure_state || true
	exit "$job_status"
fi

# Diagnose boot under the same profile without launching a performance workload.
if [ "$startup_only" -eq 1 ]; then
	capture_failure_state
	kubectl --request-timeout=5s --context "$context" -n "$namespace" get pod goauthy-0 goauthy-1 goauthy-2 -o json |
		jq -e '.items | length == 3 and all(.[]; [.status.containerStatuses[]? | select(.name == "goauthy")] | length == 1 and all(.[]; .ready == true and .restartCount == 0))' >/dev/null ||
		{ echo 'startup-only: app readiness or zero-restart invariant failed' >&2; exit 1; }
	runner_completed=true
	echo 'startup-only: three apps ready with zero restarts; no workload executed; not a qualification result'
	exit 0
fi

# The synchronized start time is computed after the pre-scrape so a slow
# pre-scrape retry cannot consume the driver's fixed 30-second schedule slack.
start_ms=$(( $(date +%s) * 1000 + 30000 ))
kubectl --context "$context" -n "$namespace" create configmap isolation113-run --from-literal=start-unix-ms="$start_ms" --dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

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
# Preserve any sticky failure already recorded (for example by the pre-scrape
# or the pre-scrape's endpoint check); a later passing driver wait must not
# clear it. A failing wait only sets the status when nothing failed yet.
if kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/isolation113-driver --timeout=220s; then :; else wait_status=$?; [ "$job_status" -ne 0 ] || job_status=$wait_status; fi
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
collect_auth_stage_metrics post
echo "auth_stage_metrics=$ISOLATION113_EVIDENCE_DIR/auth-stage-{pre,post}-{0,1,2}.json"
if [ "$job_status" -ne 0 ]; then
	capture_failure_state || true
	exit "$job_status"
fi
runner_completed=true
