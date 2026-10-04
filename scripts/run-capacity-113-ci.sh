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
	echo "env: GOAUTHY_IMAGE GOAUTHY_CANDIDATE_SOURCE [GOAUTHY_LOCAL_BUILD] [KIND_CLUSTER] [KIND_NODE_IMAGE]" >&2
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

	# Bounded diagnostic-only projection of browser t.Helper fatal records from
	# the private staged per-driver logs. Only the exact fixed test-file anchor,
	# a controlled reason enum, an optional 100..599 numeric status, and the
	# per-driver index already present in the staged filename are read. Response
	# bodies, URLs, credentials, and arbitrary error text are never classified
	# or copied into any safe artifact. Unrecognized or missing diagnostics stay
	# unknown; they are never treated as success or as cause proof.
	: >"$temp_dir/iam-fatal.tsv"
	for f in "$stage_dir"/driver-isolation113-driver-*.log; do
		[ -f "$f" ] || continue
		fidx=$(basename "$f" | sed -nE 's/.*goauthy-([0-9]+)-.*/\1/p')
		[ -n "$fidx" ] || continue
		awk -v di="$fidx" '
			{
				line = $0
				if (line !~ /^[[:space:]]*connection_use_grant_test\.go:[0-9]+:/) next
				sub(/^[[:space:]]*connection_use_grant_test\.go:[0-9]+:[[:space:]]*/, "", line)
				if (line ~ /^isolation113 /) next
				if (line ~ /^isolation113-stage /) next
				if (line ~ /^waiting [0-9]+ seconds for the login attempt window$/) next
				reason = ""; status = ""
				if (line ~ /^authorize status = [0-9]+, want login form:/) {
					n = line; sub(/^authorize status = /, "", n); sub(/,.*/, "", n)
					if (n ~ /^[0-9]+$/ && n + 0 >= 100 && n + 0 <= 599) { reason = "authorize_status"; status = n }
				} else if (line ~ /^login status=403, want redirect, category=invalid_login_request$/) {
					reason = "login_403_invalid_request"; status = "403"
				} else if (line ~ /^login status=403, want redirect, category=unclassified_403$/) {
					reason = "login_403_unclassified"; status = "403"
				} else if (line ~ /^login status = [0-9]+, want redirect/) {
					n = line; sub(/^login status = /, "", n); sub(/,.*/, "", n)
					if (n ~ /^[0-9]+$/ && n + 0 >= 100 && n + 0 <= 599) { reason = "login_status"; status = n }
				} else if (line ~ /^login did not rotate the browser session/) {
					reason = "session_rotation"
				} else if (line ~ /^login redirect is not a valid callback:/) {
					reason = "callback_invalid"
				} else if (line ~ /^login form has no interaction token/) {
					reason = "interaction_missing"
				} else if (line ~ /^unsafe browser session cookie/) {
					reason = "session_cookie_unsafe"
				} else if (line ~ /^authorize response did not set a browser session cookie/) {
					reason = "session_cookie_missing"
				} else if (line ~ /^(Get|Post) "/) {
					n = line
					sub(/^(Get|Post) "[^"]*":[[:space:]]*/, "", n)
					if (n != line && n ~ /Client\.Timeout|^context deadline exceeded/) reason = "transport_timeout"
				}
				if (reason == "") reason = "unknown"
				print di "\t" reason "\t" status
			}
		' "$f" >>"$temp_dir/iam-fatal.tsv"
	done
	if [ -s "$temp_dir/iam-fatal.tsv" ]; then
		jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) | map({
			driver_index: (.[0] | tonumber),
			reason: .[1],
			status: (if .[2] == "" then null else (.[2] | tonumber) end)
		})' "$temp_dir/iam-fatal.tsv" >"$temp_dir/iam-fatal.json"
	else
		printf '[]' >"$temp_dir/iam-fatal.json"
	fi

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
		jq --slurpfile iam_fatal "$temp_dir/iam-fatal.json" '{
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
			groups: [.groups[] | {driver_index, phase, route, operation, n, success_n, error_n, outcomes, statuses, p95_ms, p99_ms}],
		protected: .protected,
		fault_routes: .fault_routes,
		iam_stages: {
			stage_outcomes: [.iam_stages.stage_outcomes[] | {driver_index, phase, stage, outcome, n, elapsed_ms_max, elapsed_ms_p95}],
			timeout_n: .iam_stages.timeout_n,
			coverage: [.iam_stages.coverage[] | {driver_index, phase, iam_attempts, stage_observations}],
			attempt_coverage: [.iam_stages.attempt_coverage[] | {driver_index, phase, scheduled_unix_ms, stage_n}],
			complete: .iam_stages.complete,
			attempt_complete: .iam_stages.attempt_complete
		},
		iam_failure_diagnostics: (
				([.protected.groups[] | select(.route == "iam" and .error_n > 0)]) as $ig |
				([$ig[].error_n] | add // 0) as $ierr |
				([$ig[] | .driver_index] | unique) as $drivers |
				([$drivers[] | . as $d |
					([$ig[] | select(.driver_index == $d)]) as $g |
					([$g[].error_n] | add // 0) as $err |
					([$iam_fatal[0][] | select(.driver_index == $d)]) as $f |
					([$f[] | select(.reason != "unknown")] | length) as $known |
					{
						driver_index: $d,
						error_n: $err,
						phase_error_counts: [$g[] | {phase, error_n}],
						anchored_n: $known,
						unrecognized_n: (($f | length) - $known),
						excess_n: (if $known > $err then $known - $err else 0 end),
						missing_n: (if $err > $known then $err - $known else 0 end),
						complete: ($err > 0 and $known == $err and (($f | length) - $known) == 0),
						reasons: $f
					}
				]) as $diag |
				([$diag[] | select(.complete | not)] | length) as $incomplete |
				{
					criterion: "every protected IAM error must carry an anchored connection_use_grant_test.go t.Helper diagnostic; recognized count must equal total errors exactly with no unrecognized or excess diagnostics, otherwise incomplete, never success or cause proof",
					source: "private staged per-driver logs; anchored fixed test-file fatal prefixes only; raw fatals carry no phase attribution",
					errors: $ierr,
					anchored: ([$diag[].anchored_n] | add // 0),
					unrecognized: ([$diag[].unrecognized_n] | add // 0),
					excess: ([$diag[].excess_n] | add // 0),
					missing: ([$diag[].missing_n] | add // 0),
					complete: ($ierr > 0 and $incomplete == 0),
					status: (if $ierr == 0 then "none" elif $incomplete == 0 then "diagnosed" else "incomplete" end),
					groups: $diag
				}
			),
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
			iam_failure_diagnostics: {
				criterion: "every protected IAM error must carry an anchored connection_use_grant_test.go t.Helper diagnostic; recognized count must equal total errors exactly with no unrecognized or excess diagnostics, otherwise incomplete, never success or cause proof",
				source: "unavailable",
				errors: null,
				anchored: null,
				unrecognized: null,
				excess: null,
				missing: null,
				complete: false,
				status: "unavailable",
				groups: []
			},
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
	candidate_node_pins=$(json_or_null "$evidence_dir/candidate-node-pins.json")
	fixture_runtime=$(json_or_null "$evidence_dir/fixture-runtime-image-pins.json")
	driver_runtime=$(json_or_null "$evidence_dir/driver-runtime-image-pins.json")
	helper_head=$(cat "$evidence_dir/helper-source-head.txt" 2>/dev/null || true)
	jq -n --argjson helper "$helper_pins" --argjson fixture "$fixture_runtime" --argjson driver "$driver_runtime" --argjson candidate_node "$candidate_node_pins" \
		--arg candidate_image "${GOAUTHY_IMAGE:-}" --arg candidate_source "${GOAUTHY_CANDIDATE_SOURCE:-}" \
		--arg helper_source_head "$helper_head" \
		--arg local_build "${GOAUTHY_LOCAL_BUILD:-0}" \
		--arg candidate_manifest "${candidate_manifest_digest:-${GOAUTHY_CANDIDATE_MANIFEST_DIGEST:-}}" \
		--arg candidate_config "${candidate_config_id:-${GOAUTHY_CANDIDATE_CONFIG_DIGEST:-}}" '
		def runtime_digest: sub("^(containerd|docker-pullable)://"; "") | if contains("@sha256:") then sub("^.*@"; "") else . end;
		def strict_digest: if (type) == "string" and (test("^sha256:[0-9a-f]{64}$")) then . else null end;
		def runtime_pins($v): if ($v | type) == "array" then [$v[] | {image, digest: (.imageID | runtime_digest)}] else null end;
		def node_pins($v):
			try (if ($v | type) == "object"
				and ($v.config_digest | test("^sha256:[0-9a-f]{64}$"))
				and ($v.runtime_digests | type) == "array"
				and all($v.runtime_digests[]; type == "string" and test("^sha256:[0-9a-f]{64}$"))
			then $v | {config_digest, runtime_digests} else null end) catch null;
		{
			candidate: {
				image: $candidate_image,
				source: $candidate_source,
			mode: (if $local_build == "1" then "source-build" else "released-image" end),
			manifest_digest: (if $local_build == "1" then ($candidate_manifest | strict_digest) else null end),
			config_digest: (if $local_build == "1" then ($candidate_config | strict_digest) else null end),
				node_pins: node_pins($candidate_node)
			},
			helper_source_head: $helper_source_head,
			helper_image_pins: (
				if $helper == null then null else
					{
						fixture: ($helper.fixture | {image_ref, manifest_digest, config_digest, loaded_image_id, node_pins: node_pins(.node_pins)}),
						driver: ($helper.driver | {image_ref, manifest_digest, config_digest, loaded_image_id, node_pins: node_pins(.node_pins)})
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
		echo '## IAM failure diagnostics'
		echo
		echo '```json'
		jq '.iam_failure_diagnostics' "$results_dir/criterion.json" 2>/dev/null || true
		echo '```'
		echo
		echo '## Fault routes'
		echo
		echo '```json'
		jq '.fault_routes' "$results_dir/criterion.json" 2>/dev/null || true
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

: "${GOAUTHY_CANDIDATE_SOURCE:?set GOAUTHY_CANDIDATE_SOURCE to the reviewed source SHA}"
: "${GOAUTHY_LOCAL_BUILD:=0}"
: "${KIND_CLUSTER:=goauthy-capacity-113-ci}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"

case "$GOAUTHY_LOCAL_BUILD" in 0|1) ;; *) fail 'GOAUTHY_LOCAL_BUILD must be 0 or 1' ;; esac
printf '%s' "$GOAUTHY_CANDIDATE_SOURCE" | grep -Eq '^[0-9a-f]{40}$' || fail 'GOAUTHY_CANDIDATE_SOURCE must be a 40-character lowercase hex SHA'
case "$KIND_CLUSTER" in ''|*[!a-z0-9-]*|-*|*-) fail 'KIND_CLUSTER must be a DNS label' ;; esac
[ "${#KIND_CLUSTER}" -le 40 ] || fail 'KIND_CLUSTER is too long'
if [ "$GOAUTHY_LOCAL_BUILD" = 1 ]; then
	# Manual-CI-only ephemeral source build. No release, no registry
	# publication, and no pull of any mutable tag: the candidate image is
	# built from the reviewed source and bound to the actual imported OCI
	# manifest and config digests before the diagnostic driver starts.
	[ -z "${GOAUTHY_IMAGE:-}" ] || fail 'GOAUTHY_LOCAL_BUILD=1 must not be combined with a pre-set GOAUTHY_IMAGE'
	[ "$(git -C "$root" rev-parse --verify HEAD 2>/dev/null || true)" = "$GOAUTHY_CANDIDATE_SOURCE" ] ||
		fail 'source build requires the reviewed source SHA to equal the clean checkout HEAD'
	[ -z "$(git -C "$root" status --porcelain --untracked-files=all)" ] ||
		fail 'source build requires a clean committed checkout'
	GOAUTHY_IMAGE="goauthy:ci-$KIND_CLUSTER"
	export GOAUTHY_IMAGE
else
	: "${GOAUTHY_IMAGE:?set GOAUTHY_IMAGE to the immutable candidate image reference}"
	printf '%s' "$GOAUTHY_IMAGE" | grep -Eq '^ghcr\.io/mrchypark/goauthy@sha256:[0-9a-f]{64}$' || fail 'GOAUTHY_IMAGE must be ghcr.io/mrchypark/goauthy@sha256:<64 lowercase hex>'
fi
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
candidate_owned=0
meta_config_digest=

cleanup() {
	status=$?
	trap - 0 1 2 15
	cleanup_failed=false
	if [ -n "$load_alias" ]; then
		docker rmi "$load_alias" >/dev/null 2>&1 || cleanup_failed=true
	fi
	# Ownership is reserved before load, so a partial load that created the tag
	# but returned nonzero is still cleaned up. Delete only when the current
	# tag config equals the known built config: an absent tag is nothing to do,
	# and a mismatched tag is preserved with a controlled cleanup failure
	# rather than deleting an unexpected target. A fail before the reservation
	# never deletes anything.
	if [ "$candidate_owned" = 1 ]; then
		current_tag_id=$(docker image inspect --format '{{.Id}}' "$GOAUTHY_IMAGE" 2>/dev/null || true)
		if [ -n "$current_tag_id" ]; then
			if [ "$current_tag_id" = "$meta_config_digest" ]; then
				docker rmi "$GOAUTHY_IMAGE" >/dev/null 2>&1 || cleanup_failed=true
			else
				echo "capacity-113-ci: cleanup preserved an unexpected image tag: $GOAUTHY_IMAGE" >&2
				cleanup_failed=true
			fi
		fi
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

candidate_manifest_digest=
candidate_build_mode=released-image
if [ "$GOAUTHY_LOCAL_BUILD" = 1 ]; then
	candidate_build_mode=source-build
	candidate_oci=$temp_dir/candidate-oci.tar
	candidate_docker=$temp_dir/candidate-docker.tar
	# Refuse to touch a pre-existing host tag before any costly work.
	if docker image inspect "$GOAUTHY_IMAGE" >/dev/null 2>&1; then
		fail "refusing to overwrite a pre-existing host image tag: $GOAUTHY_IMAGE"
	fi
	# One build, two exporters: a real OCI image layout for the Kind node and a
	# classic Docker archive for the host. The classic Docker archive is loaded
	# into the host because the classic CI Docker store does not accept OCI
	# layouts. Provenance/SBOM are disabled so each emission is a bounded
	# single-platform manifest. No mutable tag is published or pulled and no
	# registry is contacted.
	docker buildx build \
		--output "type=oci,dest=$candidate_oci,name=$GOAUTHY_IMAGE" \
		--output "type=docker,dest=$candidate_docker" \
		--label "org.opencontainers.image.revision=$GOAUTHY_CANDIDATE_SOURCE" \
		--provenance=false --sbom=false \
		-f "$root/Dockerfile" "$root"
	# Derive the actual OCI manifest and config identity from the archive
	# itself. The shared multi-exporter metadata key is not trusted because it
	# merges exporter results.
	. "$root/scripts/capacity-113-oci-archive-identity.sh"
	oci_identity=$(oci_archive_identity "$candidate_oci" "$GOAUTHY_CANDIDATE_SOURCE") ||
		fail 'source-build OCI archive identity verification failed'
	candidate_manifest_digest=$(printf '%s\n' "$oci_identity" | awk -F'\t' 'NR==1{print $1}')
	meta_config_digest=$(printf '%s\n' "$oci_identity" | awk -F'\t' 'NR==1{print $2}')
	printf '%s' "$candidate_manifest_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
		fail 'source-build OCI manifest digest is missing or malformed'
	printf '%s' "$meta_config_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
		fail 'source-build OCI config digest is missing or malformed'
	# Reserve ownership after the absence check and known config, before the
	# host load, so a partial load that creates the tag but returns nonzero is
	# still cleaned up (cleanup re-verifies the tag config before deleting).
	candidate_owned=1
	docker load -i "$candidate_docker" >/dev/null ||
		fail 'failed to load the source-build Docker archive into the host image store'
	if ! docker image inspect "$GOAUTHY_IMAGE" >/dev/null 2>&1; then
		docker tag "$meta_config_digest" "$GOAUTHY_IMAGE" >/dev/null ||
			fail 'failed to tag the source-build candidate in the host image store'
	fi
else
	docker pull "$GOAUTHY_IMAGE"
fi
revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$GOAUTHY_IMAGE" 2>/dev/null || true)
[ "$revision" = "$GOAUTHY_CANDIDATE_SOURCE" ] || fail "candidate image revision label '$revision' does not match GOAUTHY_CANDIDATE_SOURCE '$GOAUTHY_CANDIDATE_SOURCE'"
candidate_config_id=$(docker image inspect --format '{{.Id}}' "$GOAUTHY_IMAGE" 2>/dev/null || true)
printf '%s' "$candidate_config_id" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
	fail 'candidate image config id is not a sha256 digest'
if [ "$GOAUTHY_LOCAL_BUILD" = 1 ]; then
	# Bind the host payload: the loaded image config must equal the build OCI
	# config digest, and the saved archive must expose the same config blob.
	[ "$candidate_config_id" = "$meta_config_digest" ] ||
		fail 'source-build image config id differs from the build OCI config digest'
	saved_config_blob=$(docker image save "$GOAUTHY_IMAGE" | tar -xOf - manifest.json | jq -er '.[0].Config | select(test("^blobs/sha256/[0-9a-f]{64}$"))') ||
		fail 'source-build saved archive manifest is missing a strict config blob path'
	[ "sha256:${saved_config_blob##*/}" = "$candidate_config_id" ] ||
		fail 'source-build saved archive config digest differs from the image config id'
fi
# Source-build node reference helpers. `ctr images inspect` prints a human
# tree, not JSON, so the target manifest is read from the documented
# `ctr images ls` columns (REF TYPE DIGEST ...) by exact REF match. Only strict
# sha256 digests are ever printed; any other value becomes a sentinel.
node_ls_digest() {
	_rows=$(docker exec "$node" ctr --namespace k8s.io images ls 2>/dev/null |
		awk -v ref="$1" '$1 == ref && $3 ~ /^sha256:[0-9a-f]{64}$/ { print $3 }')
	[ "$(printf '%s\n' "$_rows" | awk 'NF {n++} END {print n+0}')" -eq 1 ] || return 1
	printf '%s' "$_rows"
}

node_cri_config() {
	_cfg=$(docker exec "$node" crictl inspecti -o json "$1" 2>/dev/null | jq -r '.status.id // ""' 2>/dev/null) || return 1
	[ -n "$_cfg" ] || return 1
	printf '%s' "$_cfg"
}

sanitize_digest() {
	if printf '%s' "$1" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
		printf '%s' "$1"
	else
		printf 'invalid'
	fi
}

if [ "$GOAUTHY_LOCAL_BUILD" = 1 ]; then
	# Import the exact OCI layout archive, preserving the content-addressed
	# manifest digest.
	kind load image-archive "$candidate_oci" --name "$KIND_CLUSTER" ||
		fail 'failed to import the source-build OCI archive into the Kind node'
	# Resolve the actual registered containerd name(s) by target manifest digest
	# from the documented `ctr images ls` columns.
	imported_names=$(docker exec "$node" ctr --namespace k8s.io images ls 2>/dev/null |
		awk -v manifest="$candidate_manifest_digest" '$3 == manifest { print $1 }' | sort)
	[ -n "$imported_names" ] ||
		fail "source-build candidate manifest $candidate_manifest_digest is not registered in the Kind node image store"
	# Deterministic non-bare source name: prefer a canonical repo@sha256 name,
	# else a mapped name. Never a bare digest.
	imported_name=
	for name in $imported_names; do
		case "$name" in
			*@sha256:*) imported_name=$name; break ;;
		esac
	done
	if [ -z "$imported_name" ]; then
		for name in $imported_names; do
			case "$name" in
				sha256:*) continue ;;
				*) imported_name=$name; break ;;
			esac
		done
	fi
	[ -n "$imported_name" ] ||
		fail 'source-build candidate has no non-bare registered image name in the Kind node'
	imported_target=$(node_ls_digest "$imported_name") ||
		fail 'source-build imported candidate registered name is not uniquely resolvable in the Kind node image store'
	[ "$imported_target" = "$candidate_manifest_digest" ] ||
		fail "source-build imported candidate target manifest $(sanitize_digest "$imported_target") differs from $candidate_manifest_digest"
	imported_config=$(node_cri_config "$imported_name") || imported_config=
	[ "$imported_config" = "$candidate_config_id" ] ||
		fail "source-build imported candidate config $(sanitize_digest "$imported_config") differs from $candidate_config_id"
	# Ensure the fully-qualified digest alias exists so CRI repoDigests carries
	# the actual manifest for the final runtime proof. Attach only when absent;
	# never --force.
	candidate_repo=${GOAUTHY_IMAGE%%:*}
	case "$candidate_repo" in
		*/*) ;;
		*) candidate_repo="docker.io/library/$candidate_repo" ;;
	esac
	candidate_alias="$candidate_repo@$candidate_manifest_digest"
	alias_target=$(node_ls_digest "$candidate_alias") || alias_target=
	if [ -n "$alias_target" ]; then
		[ "$alias_target" = "$candidate_manifest_digest" ] ||
			fail "source-build digest alias $candidate_alias target manifest $(sanitize_digest "$alias_target") differs from $candidate_manifest_digest"
		alias_config=$(node_cri_config "$candidate_alias") || alias_config=
		[ "$alias_config" = "$candidate_config_id" ] ||
			fail "source-build digest alias $candidate_alias config $(sanitize_digest "$alias_config") differs from $candidate_config_id"
	else
		docker exec "$node" ctr --namespace k8s.io images tag "$imported_name" "$candidate_alias" >/dev/null ||
			fail "failed to attach the source-build digest alias $candidate_alias in the Kind node"
	fi
	# Canonical runtime reference, using the normalized registered name.
	canonical_name="docker.io/library/$GOAUTHY_IMAGE"
	canonical_target=$(node_ls_digest "$canonical_name") || canonical_target=
	if [ -n "$canonical_target" ]; then
		[ "$canonical_target" = "$candidate_manifest_digest" ] ||
			fail "source-build canonical reference $canonical_name target manifest $(sanitize_digest "$canonical_target") differs from $candidate_manifest_digest"
		canonical_config=$(node_cri_config "$GOAUTHY_IMAGE") || canonical_config=
		[ "$canonical_config" = "$candidate_config_id" ] ||
			fail "source-build canonical reference $canonical_name config $(sanitize_digest "$canonical_config") differs from $candidate_config_id"
	else
		docker exec "$node" ctr --namespace k8s.io images tag "$imported_name" "$canonical_name" >/dev/null ||
			fail 'failed to attach the canonical source-build candidate reference in the Kind node'
	fi
	# The newly attached digest alias must propagate into CRI repoDigests for
	# the final strict runtime proof. Poll briefly for propagation only; target
	# and config mismatches already failed above and are never retried.
	cri_propagated=false
	cri_attempt=0
	while [ "$cri_attempt" -lt 10 ]; do
		if docker exec "$node" crictl inspecti -o json "$GOAUTHY_IMAGE" >"$temp_dir/cri-image.json" 2>/dev/null &&
			jq -e --arg manifest "$candidate_manifest_digest" '[(.status.repoDigests // [])[] | sub("^.*@"; "")] | index($manifest) != null' "$temp_dir/cri-image.json" >/dev/null 2>&1; then
			cri_propagated=true
			break
		fi
		cri_attempt=$((cri_attempt + 1))
		sleep 0.5
	done
	[ "$cri_propagated" = true ] ||
		fail "source-build canonical reference $canonical_name CRI repoDigests does not carry manifest $candidate_manifest_digest after alias attachment"
else
	# The sixth run failed with the app container ErrImageNeverPull. The importer
	# mechanism is inferred, not directly observed: Kind's docker-save importer may
	# not attach the original digest reference, so the canonical deployment
	# reference may not resolve. Check whether the canonical reference already
	# resolves; only attach it when absent, so a pre-registered identical image is
	# not disturbed. The config blob (config ID) is preserved; the packaging
	# manifest digest may differ from the original registry manifest and is not
	# claimed equal. The owned alias must be retained through every later host
	# candidate use and removed only once by the EXIT cleanup, because removing it
	# midrun can drop the image content the host still needs.
	proposed_alias="${GOAUTHY_IMAGE%%@*}:${KIND_CLUSTER}"
	if docker image inspect "$proposed_alias" >/dev/null 2>&1; then
		fail "refusing to overwrite a pre-existing host image tag: $proposed_alias"
	fi
	load_alias=$proposed_alias
	docker tag "$GOAUTHY_IMAGE" "$proposed_alias"
	kind load docker-image "$proposed_alias" --name "$KIND_CLUSTER"
	if ! docker exec "$node" crictl inspecti -o json "$GOAUTHY_IMAGE" >"$temp_dir/cri-image.json" 2>/dev/null; then
		docker exec "$node" ctr --namespace k8s.io images tag "$proposed_alias" "$GOAUTHY_IMAGE" >/dev/null ||
			fail 'failed to attach the canonical candidate reference in the Kind node'
		if ! docker exec "$node" crictl inspecti -o json "$GOAUTHY_IMAGE" >"$temp_dir/cri-image.json" 2>/dev/null; then
			fail 'candidate canonical reference does not resolve in the Kind node CRI'
		fi
	fi
fi
node_config_id=$(jq -r '.status.id // empty' "$temp_dir/cri-image.json" 2>/dev/null || true)
[ -n "$node_config_id" ] || fail 'candidate CRI image identity is empty'
[ "$node_config_id" = "$candidate_config_id" ] ||
	fail 'candidate image config identity differs between the host original and the Kind node'
if [ "$GOAUTHY_LOCAL_BUILD" = 1 ]; then
	jq -e --arg manifest "$candidate_manifest_digest" '[(.status.repoDigests // [])[] | sub("^.*@"; "")] | index($manifest) != null' "$temp_dir/cri-image.json" >/dev/null ||
		fail 'source-build candidate node manifest digest does not match the build OCI manifest digest'
fi
printf 'candidate image loaded: mode=%s config_id=%s manifest_digest=%s reference=%s\n' "$candidate_build_mode" "$candidate_config_id" "${candidate_manifest_digest:-none}" "$GOAUTHY_IMAGE" >&2

browser_password=$(openssl rand -hex 16)
client_secret=$(openssl rand -hex 32)
master_key=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')
oauth_hmac=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')
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
GOAUTHY_LOCAL_CANDIDATE="$GOAUTHY_LOCAL_BUILD" \
GOAUTHY_CANDIDATE_MANIFEST_DIGEST="$candidate_manifest_digest" \
GOAUTHY_E2E_BROWSER_PASSWORD="$browser_password" \
GOAUTHY_E2E_CLIENT_SECRET="$client_secret" \
ISOLATION113_EVIDENCE_DIR="$evidence_dir" \
	"$root/scripts/e2e-kind-saas-isolation-113.sh" || runner_status=$?

summarize_results
