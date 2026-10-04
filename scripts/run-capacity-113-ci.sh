#!/bin/sh
# CI-only setup and calibration wrapper for the issue #113 local SaaS
# isolation diagnostic. It provisions a disposable single-node Kind
# greenfield profile (three logical GoAuthy members plus a local Versity
# object store), runs the existing scripts/e2e-kind-saas-isolation-113.sh
# diagnostic against a pinned immutable candidate image, and derives all
# calibration outputs from the mandatory shared analyzer
# scripts/summarize-e2e-kind-saas-isolation-113.sh.
#
# It never commits, pushes, deploys, or writes outside its caller-selected
# evidence/results directories and its own Kind cluster. All synthetic
# credentials are generated for the run and never committed.
#
# Modes:
#   $0 EVIDENCE_DIR RESULTS_DIR            provision, run, summarize
#   $0 --summarize EVIDENCE_DIR RESULTS_DIR summarize only (offline test hook)
set -eu
umask 077

usage() {
	echo "usage: $0 [--summarize] EVIDENCE_DIR RESULTS_DIR" >&2
	echo "env: GOAUTHY_IMAGE GOAUTHY_CANDIDATE_SOURCE [KIND_CLUSTER] [KIND_NODE_IMAGE]" >&2
	exit 2
}

fail() {
	echo "capacity-113-ci: $*" >&2
	exit 1
}

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

startup_project_jq='
	def known_name($n):
		if $n == "fixture-loopback-address" then "init"
		elif $n == "wait-for-rhiza-bucket" then "init"
		elif $n == "goauthy" then "app"
		elif $n == "sidecarfixture" then "fixture"
		else "other" end;
	def reason_enum($r):
		if $r == null then null
		elif ($r == "ErrImageNeverPull" or $r == "CrashLoopBackOff" or $r == "OOMKilled" or $r == "Error" or $r == "Completed"
			or $r == "ContainerCreating" or $r == "PodInitializing" or $r == "ErrImagePull" or $r == "ImagePullBackOff"
			or $r == "CreateContainerConfigError" or $r == "CreateContainerError" or $r == "RunContainerError"
			or $r == "InvalidImageName") then $r
		else "other" end;
	def phase_enum($s):
		($s.running // null) as $r |
		($s.waiting // null) as $w |
		($s.terminated // null) as $t |
		if $r != null then "Running"
		elif $w != null then "Waiting"
		elif $t != null then "Terminated"
		else "Unknown" end;
	def restart_bucket($c):
		($c | type) as $ty |
		if $ty == "number" then
			(if ($c | isfinite) then
				(if $c >= 0 and ($c | floor) == $c then
					(if $c == 0 then "0" elif $c <= 2 then "1-2" elif $c <= 5 then "3-5" else "6+" end)
				else "unknown" end)
			else "unknown" end)
		else "unknown" end;
	def container_view($idx; $statuses; $c):
		([$statuses[] | select(.name == $c.name)][0]) as $st |
		($st.ready // false) as $ready |
		($st.state // {}) as $state |
		($state.waiting // null) as $waiting |
		($state.terminated // null) as $terminated |
		{
			index: $idx,
			name: known_name($c.name),
			phase: phase_enum($state),
			ready: ($ready == true),
			restart_bucket: restart_bucket($st.restartCount // null),
			waiting: (if $waiting != null then reason_enum($waiting.reason) else null end),
			terminated: (if $terminated != null then reason_enum($terminated.reason) else null end)
		};
	. as $pods |
	(($pods | type) == "object") as $is_obj |
	(if $is_obj then (($pods.items | type) == "array") else false end) as $valid |
	(if $valid then
		($pods.items | map(select((.metadata.name // "") | test("^goauthy-[0-9]+$")) | select(.metadata.namespace == "goauthy")))
	else [] end) as $gp |
	[range(0;3) as $idx |
		($gp[] | select(.metadata.name == ("goauthy-" + ($idx | tostring)))) as $pod |
		{
			index: $idx,
			present: ($pod != null),
			containers: (if $pod == null then []
				else
					([(($pod.spec.initContainers // [])[] | container_view($idx; ($pod.status.initContainerStatuses // []); .)),
					  (($pod.spec.containers // [])[] | container_view($idx; ($pod.status.containerStatuses // []); .))] | flatten)
				end)
		}
	] as $pods_out |
	{
		source: "failure-capture/pods.json",
		reason: null,
		pods_json_exit: $pods_exit,
		available: $valid,
		complete: (([$pods_out[].index] | sort | unique) == [0, 1, 2] and ($pods_out | length) == 3),
		observed: (([$pods_out[].containers[]] | length) > 0),
		pods: $pods_out
	}
'

startup_summary() {
	pods=$evidence_dir/failure-capture/pods.json
	status_file=$evidence_dir/failure-capture/capture-status.txt
	pods_exit=$(awk -F= '
		BEGIN { v = "" }
		$1 == "pods.json_exit" { n++; if (NF == 2) v = $2; else v = "" }
		END { if (n == 1 && v ~ /^[0-9]+$/ && v + 0 <= 255) print v + 0 }
	' "$status_file" 2>/dev/null || true)
	case "$pods_exit" in
		''|*[!0-9]*) pods_exit=null ;;
	esac
	unavailable() {
		jq -n --arg reason "$1" --argjson pods_exit "$pods_exit" '{
			source:"failure-capture/pods.json",
			available:false,
			reason:$reason,
			pods_json_exit:$pods_exit,
			complete:false,
			observed:false,
			pods:[]
		}'
	}
	if [ ! -f "$pods" ]; then
		unavailable "capture-missing"
	elif ! jq -e . "$pods" >/dev/null 2>&1; then
		unavailable "capture-invalid"
	elif ! jq -e 'type == "object" and (.items | type) == "array"' "$pods" >/dev/null 2>&1; then
		unavailable "capture-invalid"
	else
		jq --argjson pods_exit "$pods_exit" "$startup_project_jq" "$pods" 2>/dev/null ||
			unavailable "projection-error"
	fi
}

summarize_results() {
	analyzer=$root/scripts/summarize-e2e-kind-saas-isolation-113.sh
	stage_dir=$temp_dir/analyzer-stage
	mkdir -p "$stage_dir"

	seen_idx=$temp_dir/seen-idx
	: >"$seen_idx"
	for f in "$evidence_dir"/driver-isolation113-driver-*.log; do
		[ -f "$f" ] || continue
		base=$(basename "$f")
		case "$base" in
			*driver-goauthy-*)
				idx=$(printf '%s' "$base" | sed -nE 's/.*goauthy-([0-9]+)-.*/\1/p')
				[ -n "$idx" ] || { echo "cannot derive driver index from $base" >&2; exit 1; }
				target=$base
				;;
			*)
				idx=${base#driver-isolation113-driver-}
				idx=${idx%.log}
				idx=${idx%%-*}
				case "$idx" in ''|*[!0-9]*) continue ;; esac
				target=driver-isolation113-driver-goauthy-$idx-0-test.log
				;;
		esac
		if grep -Fx "$idx" "$seen_idx" >/dev/null 2>&1; then
			echo "duplicate driver index $idx in $base" >&2
			exit 1
		fi
		printf '%s\n' "$idx" >>"$seen_idx"
		ln -s "$f" "$stage_dir/$target"
	done
	[ -f "$evidence_dir/container-samples.jsonl" ] && ln -s "$evidence_dir/container-samples.jsonl" "$stage_dir/container-samples.jsonl"
	for f in "$evidence_dir"/fixture-metrics-*.json; do
		[ -f "$f" ] || continue
		ln -s "$f" "$stage_dir/$(basename "$f")"
	done

	analyzer_status=0
	analyzer_ok=false
	if [ ! -x "$analyzer" ]; then
		analyzer_status=127
	else
		"$analyzer" "$stage_dir" >"$temp_dir/analyzer.json" 2>"$temp_dir/analyzer.stderr" || analyzer_status=$?
		if [ "$analyzer_status" -eq 0 ] && jq -e . "$temp_dir/analyzer.json" >/dev/null 2>&1; then
			analyzer_ok=true
		fi
	fi

	if [ "$analyzer_ok" = true ]; then
		jq '{
			schema_version,
			analyzer,
			diagnostic_directory_basename,
			inputs,
			denominators: {
				complete: .denominators.complete,
				incomplete: .denominators.incomplete,
				excess: .denominators.excess,
				unexpected_groups: .denominators.unexpected_groups
			},
			groups: [.groups[] | {driver_index, phase, route, operation, n, success_n, error_n, p95_ms, p99_ms}],
			protected: .protected,
			performance: {
				criterion: .performance.criterion,
				status: .performance.status,
				comparisons: [.performance.comparisons[] | {driver_index, phase, route, n, p95_ms, p99_ms, p95_limit_ms, p99_limit_ms, pass}]
			},
			resources: {ceiling: .resources.ceiling, evidence: .resources.evidence},
			fixture: {aggregate: .fixture.aggregate},
			small_sample,
			overall,
			criterion_pass: (.overall.correctness == "pass" and .overall.performance == "pass"),
			criterion_status: .overall.performance
		}' "$temp_dir/analyzer.json" >"$results_dir/criterion.json" || fail 'failed to derive the calibration criterion'
		jq '.resources + {available: true}' "$temp_dir/analyzer.json" >"$results_dir/resource-summary.json" || fail 'failed to derive the resource summary'
	else
		analyzer_reason="analyzer unavailable or malformed (exit status $analyzer_status)"
		jq -n --arg reason "$analyzer_reason" --argjson status "$analyzer_status" '{
			schema_version: 1,
			analyzer: "scripts/summarize-e2e-kind-saas-isolation-113.sh",
			diagnostic_directory_basename: "unavailable",
			error: {reason: $reason, analyzer_status: $status},
			overall: {correctness: "fail", performance: "inconclusive", resource_ceiling: "inconclusive", status: "fail", issue_closure: false, admission: "none", reason: "analyzer unavailable; correctness fail-closed"},
			criterion_pass: false,
			criterion_status: "inconclusive"
		}' >"$results_dir/criterion.json"
		jq -n --arg reason "$analyzer_reason" '{
			available: false,
			reason: $reason,
			ceiling: {status: "missing", result: "inconclusive", reason: "no approved local resource ceiling; analyzer unavailable"},
			series: [],
			evidence: {unavailable_non_rss_count: null, complete: false}
		}' >"$results_dir/resource-summary.json"
	fi

	startup=$(startup_summary) || fail 'failed to derive startup observability'
	jq --argjson startup "$startup" '. + {startup: $startup}' "$results_dir/resource-summary.json" >"$temp_dir/resource-summary.json" &&
		mv "$temp_dir/resource-summary.json" "$results_dir/resource-summary.json" ||
		fail 'failed to add startup observability to the resource summary'

	json_or_null() {
		if [ -s "$1" ] && jq -e . "$1" >/dev/null 2>&1; then
			cat "$1"
		else
			printf 'null'
		fi
	}
	helper_pins=$(json_or_null "$evidence_dir/helper-image-pins.json")
	fixture_runtime=$(json_or_null "$evidence_dir/fixture-runtime-image-pins.json")
	driver_runtime=$(json_or_null "$evidence_dir/driver-runtime-image-pins.json")
	helper_head=$(cat "$evidence_dir/helper-source-head.txt" 2>/dev/null || true)
	jq -n --argjson helper "$helper_pins" --argjson fixture "$fixture_runtime" --argjson driver "$driver_runtime" \
		--arg candidate_image "${GOAUTHY_IMAGE:-}" --arg candidate_source "${GOAUTHY_CANDIDATE_SOURCE:-}" \
		--arg helper_source_head "$helper_head" '
		def runtime_digest: sub("^(containerd|docker-pullable)://"; "") | if contains("@sha256:") then sub("^.*@"; "") else . end;
		def runtime_pins($v): if ($v | type) == "array" then [$v[] | {image, digest: (.imageID | runtime_digest)}] else null end;
		{
			candidate: {image: $candidate_image, source: $candidate_source},
			helper_source_head: $helper_source_head,
			helper_image_pins: (
				if $helper == null then null else
					{
						fixture: ($helper.fixture | {image_ref, manifest_digest, config_digest, loaded_image_id}),
						driver: ($helper.driver | {image_ref, manifest_digest, config_digest, loaded_image_id})
					}
				end),
			fixture_runtime_pins: runtime_pins($fixture),
			driver_runtime_pins: runtime_pins($driver)
		}' >"$results_dir/pins.json" || fail 'failed to write image pins'

	kubectl_version=$(kubectl version --client 2>/dev/null | tr '\n' ' ' || true)
	jq -n \
		--arg os "$(uname -s)" --arg kernel "$(uname -r)" --arg arch "$(uname -m)" \
		--arg cpus "$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || true)" \
		--arg mem_total_kib "$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || true)" \
		--arg go "$(go version 2>/dev/null || true)" \
		--arg docker "$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)" \
		--arg kind "$(kind version 2>/dev/null || true)" \
		--arg kubectl "$kubectl_version" \
		--arg kustomize "$(kustomize version 2>/dev/null || true)" \
		--arg awk "$(awk --version 2>/dev/null | head -n 1 || true)" \
		--arg jq "$(jq --version 2>/dev/null || true)" \
		--arg runner_image_os "${ImageOS:-}" --arg runner_os "${RUNNER_OS:-}" --arg runner_arch "${RUNNER_ARCH:-}" \
		'{os:$os,kernel:$kernel,arch:$arch,cpus:$cpus,mem_total_kib:$mem_total_kib,go:$go,docker:$docker,kind:$kind,kubectl:$kubectl,kustomize:$kustomize,awk:$awk,jq:$jq,runner_image_os:$runner_image_os,runner_os:$runner_os,runner_arch:$runner_arch}' \
		>"$results_dir/runner-environment.json" || fail 'failed to write runner environment metadata'

	if [ "$analyzer_ok" = true ]; then
		correctness=$(jq -r '.overall.correctness' "$results_dir/criterion.json")
		performance=$(jq -r '.overall.performance' "$results_dir/criterion.json")
		criterion_pass=$(jq -r '.criterion_pass' "$results_dir/criterion.json")
	else
		correctness=fail
		performance=inconclusive
		criterion_pass=false
	fi

	{
		echo '# Issue #113 CI calibration result'
		echo
		echo "- candidate image: \`${GOAUTHY_IMAGE:-}\`"
		echo "- candidate source: \`${GOAUTHY_CANDIDATE_SOURCE:-}\`"
		echo "- diagnostic exit status: $runner_status"
		echo "- analyzer exit status: $analyzer_status"
		echo "- criterion pass: $criterion_pass"
		echo "- criterion status: $performance"
		echo
		echo '## Overall'
		echo
		echo '```json'
		jq '.overall' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Groups'
		echo
		echo '```json'
		jq '.groups' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Protected errors'
		echo
		echo '```json'
		jq '.protected' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Denominators'
		echo
		echo '```json'
		jq '.denominators | {complete, incomplete, excess, unexpected_groups}' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Performance'
		echo
		echo '```json'
		jq '.performance' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Resources'
		echo
		echo '```json'
		jq . "$results_dir/resource-summary.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Startup'
		echo
		echo '```json'
		jq '.startup' "$results_dir/resource-summary.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Fixture'
		echo
		echo '```json'
		jq '.fixture' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Runner environment'
		echo
		echo '```json'
		jq . "$results_dir/runner-environment.json" 2>/dev/null || true
		echo '```'
	} >"$results_dir/report.md"

	[ "$runner_status" -eq 0 ] || fail "diagnostic runner failed with status $runner_status"
	[ "$correctness" = pass ] || fail "correctness fail-closed: $correctness"
	if [ "$criterion_pass" = true ]; then
		echo "capacity-113-ci: relative IAM latency criterion met; safe aggregate results in $results_dir"
	else
		echo "capacity-113-ci: relative IAM latency criterion not met (status: $performance); reported in calibration mode; safe aggregate results in $results_dir" >&2
	fi
}

if [ "${1:-}" = "--summarize" ]; then
	shift
	[ "$#" -eq 2 ] || usage
	evidence_dir=$1
	results_dir=$2
	runner_status=0
	temp_dir=$(mktemp -d)
	chmod 700 "$temp_dir"
	trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
	mkdir -p "$results_dir"
	summarize_results
	exit $?
fi

[ "$#" -eq 2 ] || usage
evidence_dir=$1
results_dir=$2

cd "$root"

: "${GOAUTHY_IMAGE:?set GOAUTHY_IMAGE to the immutable candidate image reference}"
: "${GOAUTHY_CANDIDATE_SOURCE:?set GOAUTHY_CANDIDATE_SOURCE to the reviewed source SHA}"
: "${KIND_CLUSTER:=goauthy-capacity-113-ci}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"

printf '%s' "$GOAUTHY_IMAGE" | grep -Eq '^ghcr\.io/mrchypark/goauthy@sha256:[0-9a-f]{64}$' || fail 'GOAUTHY_IMAGE must be ghcr.io/mrchypark/goauthy@sha256:<64 lowercase hex>'
printf '%s' "$GOAUTHY_CANDIDATE_SOURCE" | grep -Eq '^[0-9a-f]{40}$' || fail 'GOAUTHY_CANDIDATE_SOURCE must be a 40-character lowercase hex SHA'
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) fail 'KIND_CLUSTER must be a DNS label' ;; esac
[ "${#KIND_CLUSTER}" -le 40 ] || fail 'KIND_CLUSTER is too long'
case "$evidence_dir" in /*) ;; *) fail 'EVIDENCE_DIR must be absolute' ;; esac
case "$results_dir" in /*) ;; *) fail 'RESULTS_DIR must be absolute' ;; esac
case "$evidence_dir" in "$root"/*) fail 'EVIDENCE_DIR must be outside the repository' ;; esac
case "$results_dir" in "$root"/*) fail 'RESULTS_DIR must be outside the repository' ;; esac
[ ! -e "$evidence_dir" ] || fail 'EVIDENCE_DIR already exists; refusing to overwrite'
mkdir -p "$results_dir"

for tool in docker kind kubectl kustomize openssl go curl nc tar jq timeout awk sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done

kind_version=$(kind version 2>/dev/null || true)
case "$kind_version" in "kind v0.32.0 "*) ;; *) fail "unexpected kind version: $kind_version" ;; esac
kubectl_client_version=$(kubectl version --client 2>/dev/null || true)
case "$kubectl_client_version" in *"v1.35.3"*) ;; *) fail "unexpected kubectl version: $kubectl_client_version" ;; esac

context=kind-$KIND_CLUSTER
node=$KIND_CLUSTER-control-plane
temp_dir=$(mktemp -d)
chmod 700 "$temp_dir"
created=false
inotify_original=
load_alias=

cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=false
	if [ -n "$load_alias" ]; then
		docker rmi "$load_alias" >/dev/null 2>&1 || cleanup_failed=true
	fi
	if [ "$created" = true ]; then
		if [ -n "$inotify_original" ]; then
			docker exec "$node" sysctl -w "fs.inotify.max_user_instances=$inotify_original" >/dev/null 2>&1 || cleanup_failed=true
		fi
		kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || cleanup_failed=true
	fi
	rm -rf "$temp_dir" || cleanup_failed=true
	if [ "$status" -eq 0 ] && [ "$cleanup_failed" = true ]; then
		status=1
	fi
	exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

"$root/scripts/e2e-preflight.sh" host-capacity

if kind get clusters 2>/dev/null | grep -Fx "$KIND_CLUSTER" >/dev/null; then
	fail "Kind cluster already exists: $KIND_CLUSTER"
fi
created=true
kind create cluster --name "$KIND_CLUSTER" --image "$KIND_NODE_IMAGE" --wait 180s
api_server=$(kubectl config view --raw --minify --context "$context" -o jsonpath='{.clusters[0].cluster.server}')
case "$api_server" in
	https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
esac

inotify_original=$(docker exec "$node" cat /proc/sys/fs/inotify/max_user_instances)
docker exec "$node" sysctl -w fs.inotify.max_user_instances=512 >/dev/null 2>&1 ||
	docker exec "$node" sh -c 'echo 512 > /proc/sys/fs/inotify/max_user_instances'
"$root/scripts/e2e-preflight.sh" kind-inotify --cluster "$KIND_CLUSTER"

docker pull "$GOAUTHY_IMAGE"
revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$GOAUTHY_IMAGE" 2>/dev/null || true)
[ "$revision" = "$GOAUTHY_CANDIDATE_SOURCE" ] || fail "candidate image revision label '$revision' does not match GOAUTHY_CANDIDATE_SOURCE '$GOAUTHY_CANDIDATE_SOURCE'"
candidate_config_id=$(docker image inspect --format '{{.Id}}' "$GOAUTHY_IMAGE" 2>/dev/null || true)
printf '%s' "$candidate_config_id" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
	fail 'candidate image config id is not a sha256 digest'
# The sixth run failed with the app container ErrImageNeverPull. The importer
# mechanism is inferred, not directly observed: Kind's docker-save importer may
# not attach the original digest reference, so the canonical deployment
# reference may not resolve. Check whether the canonical reference already
# resolves; only attach it when absent, so a pre-registered identical image is
# not disturbed. The config blob (config ID) is preserved; the packaging
# manifest digest may differ from the original registry manifest and is not
# claimed equal.
proposed_alias="${GOAUTHY_IMAGE%%@*}:${KIND_CLUSTER}"
if docker image inspect "$proposed_alias" >/dev/null 2>&1; then
	fail "refusing to overwrite a pre-existing host image tag: $proposed_alias"
fi
load_alias=$proposed_alias
docker tag "$GOAUTHY_IMAGE" "$proposed_alias"
kind load docker-image "$proposed_alias" --name "$KIND_CLUSTER"
if docker rmi "$proposed_alias" >/dev/null 2>&1; then
	load_alias=
fi
if ! docker exec "$node" crictl inspecti -o json "$GOAUTHY_IMAGE" >"$temp_dir/cri-image.json" 2>/dev/null; then
	docker exec "$node" ctr --namespace k8s.io images tag "$proposed_alias" "$GOAUTHY_IMAGE" >/dev/null ||
		fail 'failed to attach the canonical candidate reference in the Kind node'
	if ! docker exec "$node" crictl inspecti -o json "$GOAUTHY_IMAGE" >"$temp_dir/cri-image.json" 2>/dev/null; then
		fail 'candidate canonical reference does not resolve in the Kind node CRI'
	fi
fi
node_config_id=$(jq -r '.status.id // empty' "$temp_dir/cri-image.json" 2>/dev/null || true)
[ -n "$node_config_id" ] || fail 'candidate CRI image identity is empty'
[ "$node_config_id" = "$candidate_config_id" ] ||
	fail 'candidate image config identity differs between the host original and the Kind node'
printf 'candidate image loaded: config_id=%s reference=%s\n' "$candidate_config_id" "$GOAUTHY_IMAGE" >&2

browser_password=$(openssl rand -hex 16)
client_secret=$(openssl rand -hex 32)
master_key=$(openssl rand -base64 32 | tr -d '\n')
oauth_hmac=$(openssl rand -base64 32 | tr -d '\n')
dcr_token=$(openssl rand -hex 16)
rhiza_admin=$(openssl rand -hex 32)
voter0=$(openssl rand -hex 32)
voter1=$(openssl rand -hex 32)
voter2=$(openssl rand -hex 32)
versity_user="goauthy-ci-$(openssl rand -hex 4)"
versity_password=$(openssl rand -hex 24)
browser_phc=$(printf '%s\n' "$browser_password" | go run "$root/cmd/goauthy-password")
[ -n "$browser_phc" ] || fail 'failed to derive the synthetic bootstrap password hash'
members=$(printf '[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"%s"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"%s"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"%s"}]' "$voter0" "$voter1" "$voter2")

kubectl --context "$context" apply -f "$root/deploy/k8s/namespace.yaml" >/dev/null
kubectl --context "$context" -n goauthy create secret generic goauthy-secrets \
	--from-literal=dev-1="$master_key" \
	--from-literal=oauth-hmac="$oauth_hmac" \
	--from-literal=bootstrap-client="$client_secret" \
	--from-literal=dcr-registration-token="$dcr_token" \
	--from-literal=bootstrap-user-password-phc="$browser_phc" \
	--from-literal=rhiza-admin-token="$rhiza_admin" \
	--from-literal=rhiza-members="$members" \
	--from-literal=versity-root-user="$versity_user" \
	--from-literal=versity-root-password="$versity_password" \
	--dry-run=client -o yaml | kubectl --context "$context" apply -f - >/dev/null

baseline_normalize_jq='
	[.[] | if .kind == "List" then (.items // []) else [.] end] | flatten | {kind:"List",apiVersion:"v1",items:.}
'
baseline_patch_jq='
	.items |= map(
		if .kind == "StatefulSet" and .metadata.name == "goauthy" and .metadata.namespace == "goauthy"
		then
			.spec.replicas = 0
			| (.spec.template.spec.containers[] | select(.name == "goauthy") | .image) = $image
		else . end)
'
baseline_validate_jq='
	([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy")] | length) == 1
	and ([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy" and .spec.replicas == 0)] | length) == 1
	and ([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[] | select(.name == "goauthy" and .image == $image)] | length) == 1
	and ([.items[] | select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[] | select(.image == $image)] | length) == 1
'

kustomize build "$root/deploy/k8s" >"$temp_dir/baseline.yaml"
kubectl --context "$context" create --dry-run=client -o json -f "$temp_dir/baseline.yaml" >"$temp_dir/baseline-raw.json" ||
	fail 'kubectl dry-run baseline render failed'
jq -s "$baseline_normalize_jq" "$temp_dir/baseline-raw.json" >"$temp_dir/baseline.json"
jq --arg image "$GOAUTHY_IMAGE" "$baseline_patch_jq" "$temp_dir/baseline.json" >"$temp_dir/baseline-patched.json"
jq -e --arg image "$GOAUTHY_IMAGE" "$baseline_validate_jq" "$temp_dir/baseline-patched.json" >/dev/null ||
	fail 'rendered baseline must select exactly one GoAuthy StatefulSet at zero replicas with the immutable candidate image'
kubectl --context "$context" apply -f "$temp_dir/baseline-patched.json" >/dev/null
kubectl --context "$context" -n goauthy rollout status statefulset/versity --timeout=240s
kubectl --context "$context" -n goauthy wait --for=condition=complete job/versity-init --timeout=240s
kubectl --context "$context" -n goauthy get statefulset goauthy -o json |
	jq -e --arg image "$GOAUTHY_IMAGE" 'select(.spec.replicas==0 and ([.spec.template.spec.containers[]|select(.name=="goauthy" and .image==$image)]|length)==1)' >/dev/null ||
	fail 'baseline GoAuthy StatefulSet is not at zero replicas with the selected candidate image'

runner_status=0
KIND_CLUSTER="$KIND_CLUSTER" \
GOAUTHY_IMAGE="$GOAUTHY_IMAGE" \
GOAUTHY_CANDIDATE_SOURCE="$GOAUTHY_CANDIDATE_SOURCE" \
GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
GOAUTHY_E2E_CLIENT_SECRET="$client_secret" \
ISOLATION113_EVIDENCE_DIR="$evidence_dir" \
	"$root/scripts/e2e-kind-saas-isolation-113.sh" || runner_status=$?

summarize_results
