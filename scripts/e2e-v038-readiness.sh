#!/bin/sh
# Published v0.3.8 cold-start observations; no account or token operations.
set -eu

mode=${1:---check}
case "$mode" in --check|--run) ;; *) echo 'usage: e2e-v038-readiness.sh [--check|--run]' >&2; exit 2;; esac
[ "$#" -le 1 ] || exit 2
if [ "${GOAUTHY_V038_CLEAN_ENV:-}" != "$$" ]; then
	exec env -i PATH="${PATH:-/usr/bin:/bin}" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" \
		GOAUTHY_V038_CLEAN_ENV="$$" /bin/sh -c 'GOAUTHY_V038_CLEAN_ENV=$$; export GOAUTHY_V038_CLEAN_ENV; exec /bin/sh "$@"' sh "$0" "$mode"
fi

sut_image=ghcr.io/mrchypark/goauthy@sha256:0e143036a9cdbbf458f8ebf16739fb59a4d43bb6efff86b8f4a003eb61e51903
sut_revision=908cc698b1f238fb12ce83a47e2656d8333e2523
# Floci 0.12.0 AMD64 manifest; the release default entrypoint serves port 4588.
gcs_image=docker.io/floci/floci-gcp@sha256:042c0c6d29b992691ea640bfce91554329d29004cfe4b68aa2093da23e06784f
gcs_revision=a2ff27caa7a8fb87291b83a5d172db2205246464
gcs_port=4588
gcs_start_verified=true
issuer=http://127.0.0.1:19580
owner_label=io.goauthy.v038-readiness

if [ "$mode" = --check ]; then
	sh -n "$0"
	printf '%s\n' "SUT=$sut_image revision=$sut_revision platform=linux/amd64" \
		'FS cap=120s; GCS cold cap=900s checkpoint=120s; warm cap=120s.' \
		'Offline check only: no Docker daemon, pulls, listeners, or resources.'
	if [ "$gcs_start_verified" != true ]; then
		echo 'GCS BLOCKED: verified Floci GCP image digest and startup contract not supplied; --run finishes FS then exits 78.'
	else
		printf 'GCS=%s port=%s; warm reuses archive/keys with a fresh /data tmpfs.\n' "$gcs_image" "$gcs_port"
	fi
	exit 0
fi

for tool in docker curl jq nc openssl timeout sha256sum sudo chown uname date mktemp chmod rm sed tail head tr grep cat cut tee mkdir sleep awk; do
	command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo 'native Linux/amd64 host required; cross-architecture/FEX execution is unsupported' >&2; exit 1; }
export DOCKER_HOST=unix:///var/run/docker.sock
dkr() { timeout 30 docker "$@"; }
platform=$(dkr info --format '{{.OSType}}/{{.Architecture}}')
case "$platform" in linux/amd64|linux/x86_64) ;; *) echo "native Docker Linux/amd64 server required; got $platform" >&2; exit 1;; esac
nc -z 127.0.0.1 19580 >/dev/null 2>&1 && { echo 'loopback port 19580 is occupied; refusing to start' >&2; exit 1; }

umask 077
run_dir=$(mktemp -d "${TMPDIR%/}/goauthy-v038-readiness.XXXXXX")
inputs=$run_dir/inputs
logs=$run_dir/logs
mkdir -p "$inputs/keys" "$logs"
nonce=$(openssl rand -hex 12)
network_name=goauthy-v038-$nonce
sut_name=$network_name-sut
gcs_name=$network_name-gcs
network_id=; sut_id=; gcs_id=
printf 'run=%s\nimage=%s\nrevision=%s\nplatform=%s\n' "$nonce" "$sut_image" "$sut_revision" "$platform" >"$logs/summary.txt"

build_redaction_patterns() {
	awk 'length($0) > 0 { print }' "$@" >"$inputs/patterns"
	[ -s "$inputs/patterns" ]
}

sanitize_logs() {
	for file in "$logs"/*; do
		[ -f "$file" ] || continue
		if [ -f "$inputs/patterns" ] && grep -F -f "$inputs/patterns" "$file" >/dev/null 2>&1; then
			printf '%s\n' 'Log withheld: synthetic key material detected.' >"$file"
		fi
		chmod 600 "$file"
	done
}

owned_id() {
	kind=$1; ref=$2
	[ -n "$ref" ] || return 1
	dkr "$kind" inspect --format '{{.Id}} {{index .Labels "io.goauthy.v038-readiness"}}' "$ref" 2>/dev/null
}

container_identity() {
	dkr container inspect --format '{{.Id}} {{index .Config.Labels "io.goauthy.v038-readiness"}}' "$1" 2>/dev/null
}

verified_identity() {
	identity_id=${1%% *}; identity_label=${1#* }
	[ "$identity_label" = "$nonce" ] && [ "${#identity_id}" -eq 64 ] || return 1
	case "$identity_id" in *[!a-f0-9]*) return 1;; esac
	printf '%s\n' "$identity_id"
}

verify_absent() {
	absent_kind=$1; absent_ref=$2
	if dkr "$absent_kind" inspect "$absent_ref" >/dev/null 2>"$logs/absence.err"; then return 1; else absent_status=$?; fi
	[ "$absent_status" -eq 1 ] && grep -E 'No such (object|container)|network .* not found' "$logs/absence.err" >/dev/null
}

remove_container() {
	ref=$1
	identity=$(container_identity "$ref") || { verify_absent container "$ref" && return 0; echo "cannot verify owned container absence: $ref" >&2; return 1; }
	owned_container_id=$(verified_identity "$identity") || { echo "refusing container cleanup: ownership mismatch for $ref" >&2; return 1; }
	dkr logs --tail 80 "$owned_container_id" 2>&1 | head -c 65536 | LC_ALL=C tr -cd '\11\12\15\40-\176' >"$logs/$ref.log" || true
	dkr stop --time 10 "$owned_container_id" >/dev/null || return 1
	dkr rm "$owned_container_id" >/dev/null || return 1
	verify_absent container "$owned_container_id"
}

cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=0
	for entry in "$sut_name" "$gcs_name"; do
		# A create response may be interrupted: recover only this run's exact
		# nonce name, and verify its label before acting on its returned ID.
		if [ -f "$run_dir/$entry.created" ]; then remove_container "$entry" || cleanup_failed=1; fi
	done
	if [ -f "$run_dir/network.created" ]; then
		identity=$(owned_id network "$network_name") || identity=
		if owned_network_id=$(verified_identity "$identity"); then
			dkr network rm "$owned_network_id" >/dev/null || cleanup_failed=1
			verify_absent network "$owned_network_id" || cleanup_failed=1
		else
			if ! verify_absent network "$network_name"; then echo "network cleanup ownership/absence unverified: $network_name" >&2; cleanup_failed=1; fi
		fi
	fi
	sanitize_logs
	rm -rf "$inputs"
	[ ! -e "$inputs" ] || cleanup_failed=1
	cleanup_verified=false
	if [ "$cleanup_failed" -eq 0 ]; then cleanup_verified=true; else status=1; fi
	printf 'cleanup_verified=%s\nexit=%s\n' "$cleanup_verified" "$status" | tee -a "$logs/summary.txt"
	if [ "$status" -ne 0 ]; then
		# Logs are bounded and scanned for the fresh synthetic input values.
		for file in "$logs"/*.log; do [ ! -f "$file" ] || tail -n 8 "$file" >&2; done
	fi
	echo "Protected synthetic diagnostics: $logs"
	exit "$status"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 1 15

timeout 120 docker pull "$sut_image" >"$logs/pull.log" 2>&1
identity=$(dkr image inspect --format '{{.Os}}/{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}}' "$sut_image")
[ "$identity" = "linux/amd64 $sut_revision" ] || { echo 'SUT platform/revision mismatch' >&2; exit 1; }
dkr image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$sut_image" | grep -Fx "$sut_image" >/dev/null || { echo 'SUT immutable digest missing from image identity' >&2; exit 1; }
printf '%s\n' "$identity" >>"$logs/summary.txt"

openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' >"$inputs/keys/readiness-1"
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' >"$inputs/oauth-hmac"
openssl rand -hex 32 >"$inputs/bootstrap-client"
build_redaction_patterns "$inputs/keys/readiness-1" "$inputs/oauth-hmac" "$inputs/bootstrap-client"
chmod 755 "$inputs" "$inputs/keys"
chmod 600 "$inputs/keys/readiness-1" "$inputs/oauth-hmac" "$inputs/bootstrap-client"
sudo -n chown 65532:65532 "$inputs/keys/readiness-1" "$inputs/oauth-hmac" "$inputs/bootstrap-client"

: >"$run_dir/network.created"
network_id=$(dkr network create --internal --label "$owner_label=$nonce" "$network_name")
printf 'network %s %s\n' "$network_id" "$network_name" >>"$logs/resources.txt"

create_sut() {
	context=$1
	shift
	nc -z 127.0.0.1 19580 >/dev/null 2>&1 && { echo 'loopback port 19580 became occupied' >&2; return 1; }
	: >"$run_dir/$sut_name.created"
	sut_id=$(dkr create --name "$sut_name" --label "$owner_label=$nonce" --network "$network_id" \
		--user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges \
		--tmpfs /data:rw,noexec,nosuid,uid=65532,gid=65532,mode=0700 \
		--tmpfs /tmp:rw,noexec,nosuid,uid=65532,gid=65532,mode=0700 \
		--mount "type=bind,src=$inputs,dst=/inputs,readonly" --publish 127.0.0.1:19580:8080 \
		--env GOAUTHY_LISTEN_ADDR=:8080 --env "GOAUTHY_ISSUER=$issuer" \
		--env GOAUTHY_RHIZA_PROFILE=standalone --env "GOAUTHY_CLUSTER_ID=v038-$nonce-$context" \
		--env GOAUTHY_NODE_ID=readiness-0 --env GOAUTHY_DATA_DIR=/data/rhiza \
		--env GOAUTHY_MASTER_KEY_DIR=/inputs/keys --env GOAUTHY_ACTIVE_MASTER_KEY_ID=readiness-1 \
		--env GOAUTHY_OAUTH_HMAC_SECRET_FILE=/inputs/oauth-hmac --env GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE=/inputs/bootstrap-client \
		--env GOAUTHY_BOOTSTRAP_CLIENT_ID=readiness-fixture --env GOAUTHY_BOOTSTRAP_REDIRECT_URI=http://127.0.0.1:19580/callback \
		"$@" "$sut_image")
	printf 'container %s %s\n' "$sut_id" "$sut_name" >>"$logs/resources.txt"
	stage_started=$(date +%s)
	printf 'context=%s start_epoch=%s\n' "$context" "$stage_started" >>"$logs/summary.txt"
	dkr start "$sut_id" >/dev/null
}

http_probe() {
	path=$1; output=$2
	curl --noproxy '*' --silent --show-error --connect-timeout 1 --max-time 2 --max-filesize 16384 \
		--output "$output" --write-out '%{http_code}' "$issuer$path" 2>"$output.err" || true
}

observe() {
	stage=$1; cap=$2
	started=$stage_started; checkpoint=false; first_live=false; first_ready=false
	while :; do
		elapsed=$(( $(date +%s) - started ))
		live=$(http_probe /livez "$logs/$stage-livez.body")
		ready=$(http_probe /readyz "$logs/$stage-readyz.body")
		discovery=$(http_probe /.well-known/openid-configuration "$logs/$stage-discovery.body")
		elapsed=$(( $(date +%s) - started ))
		printf 'stage=%s elapsed=%ss livez=%s readyz=%s discovery=%s\n' "$stage" "$elapsed" "$live" "$ready" "$discovery" >>"$logs/health.txt"
		if [ "$live" = 204 ] && [ "$first_live" = false ]; then printf 'stage=%s first_livez=%ss\n' "$stage" "$elapsed" >>"$logs/summary.txt"; first_live=true; fi
		if [ "$ready" = 204 ] && [ "$first_ready" = false ]; then printf 'stage=%s first_readyz=%ss\n' "$stage" "$elapsed" >>"$logs/summary.txt"; first_ready=true; fi
		if [ "$elapsed" -ge 120 ] && [ "$checkpoint" = false ]; then
			echo "CHECKPOINT stage=$stage elapsed=${elapsed}s livez=$live readyz=$ready discovery=$discovery (observation only)"; checkpoint=true
		fi
		if [ "$elapsed" -le "$cap" ] && [ "$live/$ready/$discovery" = 204/204/200 ] && jq -e --arg issuer "$issuer" '.issuer == $issuer and .jwks_uri == ($issuer + "/oidc/jwks.json")' "$logs/$stage-discovery.body" >/dev/null 2>&1; then
			echo "PASS stage=$stage ready_after=${elapsed}s" | tee -a "$logs/summary.txt"; return 0
		fi
		running=$(dkr container inspect --format '{{.State.Running}}' "$sut_id")
		if [ "$running" != true ] || [ "$elapsed" -ge "$cap" ]; then
			observation_exit=1
			if [ "$running" != true ]; then
				echo "FAIL stage=$stage livez=$live readyz=$ready discovery=$discovery observed=${elapsed}s cap=${cap}s running=$running" >&2
			else
				echo "INCOMPLETE observation_window_exceeded stage=$stage livez=$live readyz=$ready discovery=$discovery observed=${elapsed}s cap=${cap}s running=$running" >&2
				observation_exit=75
			fi
			for endpoint in livez readyz discovery; do printf '%s body: ' "$endpoint" >&2; head -c 512 "$logs/$stage-$endpoint.body" | LC_ALL=C tr -cd '\11\12\15\40-\176' >&2; printf '\n' >&2; done
			return "$observation_exit"
		fi
		sleep 2
	done
}

fingerprint_jwks() {
	stage=$1
	[ "$(http_probe /oidc/jwks.json "$logs/$stage-jwks.body")" = 200 ] || return 1
	if ! jq -e '.keys | type == "array" and length > 0 and all(.[]; (has("d") or has("p") or has("q") or has("dp") or has("dq") or has("qi") or has("oth") or has("k")) | not)' "$logs/$stage-jwks.body" >/dev/null; then
		rm -f "$logs/$stage-jwks.body"
		return 1
	fi
	jq -cS '.keys | sort_by(.kid) | map({kty,kid,use,alg,n,e,crv,x,y} | with_entries(select(.value != null)))' "$logs/$stage-jwks.body" >"$logs/$stage-jwks.public.json" || return 1
	sha256sum "$logs/$stage-jwks.public.json" | cut -d ' ' -f 1
}

create_sut fs
observe fs 120
remove_container "$sut_name"
rm "$run_dir/$sut_name.created"
if [ "$gcs_start_verified" != true ] || [ -z "$gcs_image" ] || [ -z "$gcs_port" ]; then
	echo 'GCS BLOCKED: verified Floci GCP digest/startup contract absent; FS completed; no GCS resources provisioned.' >&2
	exit 78
fi
timeout 120 docker pull "$gcs_image" >"$logs/gcs-pull.log" 2>&1
[ "$(dkr image inspect --format '{{.Os}}/{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}}' "$gcs_image")" = "linux/amd64 $gcs_revision" ] || { echo 'GCS emulator identity mismatch' >&2; exit 1; }
dkr image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$gcs_image" | grep -Fx "$gcs_image" >/dev/null || exit 1
: >"$run_dir/$gcs_name.created"
gcs_id=$(dkr create --name "$gcs_name" --label "$owner_label=$nonce" --network "$network_id" --network-alias gcs \
	--publish "127.0.0.1::$gcs_port" "$gcs_image")
printf 'container %s %s\n' "$gcs_id" "$gcs_name" >>"$logs/resources.txt"
dkr start "$gcs_id" >/dev/null
gcs_host_port=$(dkr container inspect --format "{{(index (index .NetworkSettings.Ports \"$gcs_port/tcp\") 0).HostPort}}" "$gcs_id")
case "$gcs_host_port" in ''|*[!0-9]*) echo 'invalid emulator loopback port' >&2; exit 1;; esac
bucket=readiness-$nonce
attempt=0
until curl --noproxy '*' --silent --fail --max-time 2 -H 'Content-Type: application/json' \
	--data "{\"name\":\"$bucket\"}" "http://127.0.0.1:$gcs_host_port/storage/v1/b?project=readiness-fixture" >"$logs/bucket.json"; do
	attempt=$((attempt + 1)); [ "$attempt" -lt 30 ] || exit 1; sleep 1
done
jq -e --arg bucket "$bucket" '.name == $bucket' "$logs/bucket.json" >/dev/null
curl --noproxy '*' --silent --fail --max-time 5 "http://127.0.0.1:$gcs_host_port/storage/v1/b/$bucket/o" >"$logs/initial-objects.json"
jq -e '(.items // []) | length == 0' "$logs/initial-objects.json" >/dev/null
create_sut gcs --env GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true --env GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=gcs \
	--env "GOAUTHY_RHIZA_OBJECT_STORE_BUCKET=$bucket" --env "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX=cold-$nonce" \
	--env "STORAGE_EMULATOR_HOST=http://gcs:$gcs_port" --env GCE_METADATA_DISABLED=true
observe gcs-cold 900
cold_fingerprint=$(fingerprint_jwks cold)
# Stop/start preserves the emulator/bucket/keys; Docker recreates /data tmpfs.
dkr stop --time 15 "$sut_id" >/dev/null
[ "$(dkr container inspect --format '{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}' "$sut_id")" = 'false 0 false' ] || { echo 'cold SUT did not stop gracefully' >&2; exit 1; }
stage_started=$(date +%s)
dkr start "$sut_id" >/dev/null
observe gcs-warm 120
warm_fingerprint=$(fingerprint_jwks warm)
[ "$cold_fingerprint" = "$warm_fingerprint" ] || { echo 'public JWKS material changed across GCS restart' >&2; exit 1; }
printf 'JWKS public material preserved: %s\n' "$cold_fingerprint" | tee -a "$logs/summary.txt"
