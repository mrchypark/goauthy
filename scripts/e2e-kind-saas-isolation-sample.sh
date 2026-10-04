#!/bin/sh
set -eu

usage() { echo "usage: $0 KIND_CLUSTER NAMESPACE OUTPUT.jsonl" >&2; exit 2; }
fail() { echo "$*" >&2; exit 1; }
[ "$#" -eq 3 ] || usage
cluster=$1 namespace=$2 output=$3
case $cluster in ''|*[!a-z0-9-]*) fail 'invalid Kind cluster name';; esac
case $namespace in ''|*[!a-z0-9.-]*|.*|*.|*..*) fail 'invalid namespace';; esac
[ -n "$output" ] || usage
for tool in docker jq mktemp date sleep kubectl awk; do command -v "$tool" >/dev/null 2>&1 || fail "required tool missing: $tool"; done
node="${cluster}-control-plane"
docker inspect "$node" >/dev/null 2>&1 || fail "Kind node container missing: $node"
docker exec "$node" crictl version >/dev/null 2>&1 || fail 'crictl unavailable in Kind node'
umask 077
set -C
: >"$output" || fail 'output file must be a new writable path'
set +C
pod_status_dir=$(mktemp -d "${TMPDIR:-/tmp}/goauthy-pod-status.XXXXXX") || fail 'could not create private pod-status directory'
pod_status_file="$pod_status_dir/pod-status.json"
trap 'rm -rf "$pod_status_dir"' 0
trap 'exit 0' HUP INT TERM

# Node cAdvisor metrics path through the API server node proxy using the
# existing read-only kubectl context; no cluster role or permission change.
# One bounded fetch per existing sample iteration covers all six containers.
cadvisor_path="/api/v1/nodes/$node/proxy/metrics/cadvisor"

projection='
  def counter:
    (if type == "object" then (.value // null) else . end) as $raw
    | if ($raw|type) == "string" and ($raw|test("^(0|[1-9][0-9]*)$")) then
        ($raw|tonumber) as $number
        | if ($number|isfinite) and $number >= 0 and ($number|floor) == $number and $number <= 9007199254740991 then $number else null end
      elif ($raw|type) == "number" then
        $raw as $number
        | if ($number|isfinite) and $number >= 0 and ($number|floor) == $number and $number <= 9007199254740991 then $number else null end
      else null end;
  ["goauthy-0", "goauthy-1", "goauthy-2"][] as $pod
  | ["goauthy", "sidecarfixture"][] as $container
  | ([$pod_status[0].items[]? | select(.metadata.name == $pod) | .status.containerStatuses[]? | select(
      .name == $container and .state.running != null and
      (.containerID | type) == "string" and (.containerID | test("^containerd://[0-9a-f]+$"))
    ) | .containerID]) as $current_ids
  | (if $pod_status_ok and ($current_ids | length) == 1 then $current_ids[0] else null end) as $current_id
  | (if $current_id == null then null else ($current_id | sub("^containerd://"; "")) end) as $active_cri_id
  | ([.stats[]? | select(
      .attributes.labels["io.kubernetes.pod.namespace"] == $namespace and
      .attributes.labels["io.kubernetes.pod.name"] == $pod and
      .attributes.labels["io.kubernetes.container.name"] == $container
    )]) as $matches
  | ([$matches[] | select(.attributes.id == $active_cri_id)]) as $active_matches
  | (if ($active_matches | length) == 1 then $active_matches[0] else {} end) as $s
  | ($s.memory.rssBytes // $s.memory.rss_bytes) as $rss
  | ($s.cpu.usageCoreNanoSeconds | counter) as $cpu
  | ($s.memory.workingSetBytes | counter) as $working
  | ($rss | counter) as $rss_bytes
  | ($cfs[$pod + "/" + $container] // {}) as $c
  | ($c.periodsTotal) as $cfs_periods
  | ($c.throttledPeriodsTotal) as $cfs_throttled_periods
  | ($c.throttledSecondsTotal) as $cfs_throttled_seconds
  | {
      hostTimestampUTC: $timestamp,
      namespace: $namespace,
      pod: $pod,
      container: $container,
      containerID: (if ($active_cri_id != null and ($s.attributes.id | type) == "string") then $s.attributes.id else null end),
      currentContainerID: $current_id,
      candidateContainerIDs: [$matches[] | .attributes.id // null],
      cpuUsageCoreNanoSeconds: $cpu,
      memoryWorkingSetBytes: $working,
      memoryRSSBytes: $rss_bytes,
      cpuCfsPeriodsTotal: (if ($cfs_periods|type) == "number" then $cfs_periods else null end),
      cpuCfsThrottledPeriodsTotal: (if ($cfs_throttled_periods|type) == "number" then $cfs_throttled_periods else null end),
      cpuCfsThrottledSecondsTotal: (if ($cfs_throttled_seconds|type) == "number" then $cfs_throttled_seconds else null end),
      cpuCfsUnavailable: (
        if $cfs_ok then
          (if ($cfs_periods == "ambiguous" or $cfs_throttled_periods == "ambiguous" or $cfs_throttled_seconds == "ambiguous") then ["cfs-counter-ambiguous"]
           elif (($cfs_periods|type) != "number" or ($cfs_throttled_periods|type) != "number" or ($cfs_throttled_seconds|type) != "number") then ["cfs-counter-unavailable"]
           else [] end)
        else ["cadvisor-endpoint-unavailable"] end
      ),
      unavailable: (
        (if $sample_ok then [] else ["cri-stats-command-failed"] end) +
        (if $pod_status_ok then [] else ["pod-status-command-failed"] end) +
        (if ($current_ids | length) == 0 then ["running-container-id-unavailable"] elif ($current_ids | length) > 1 then ["running-container-id-ambiguous"] else [] end) +
        (if ($matches | length) == 0 then ["container-not-reported"] else [] end) +
        (if $active_cri_id != null and ($active_matches | length) == 0 then ["current-container-id-not-reported"] elif ($active_matches | length) > 1 then ["duplicate-container-rows"] else [] end) +
        (if ($active_matches | length) == 1 and ($s.attributes.id | type) != "string" then ["container-id-unavailable"] else [] end) +
        (if ($active_matches | length) == 1 and $cpu == null then ["cpu-counter-unavailable"] else [] end) +
        (if ($active_matches | length) == 1 and $working == null then ["working-set-unavailable"] else [] end) +
        (if ($active_matches | length) == 1 and $rss_bytes == null then (if $rss == null then ["rss-not-exposed"] else ["rss-counter-unavailable"] end) else [] end)
      )
    }
'

# Parse the cAdvisor text once into a compact per-container CFS map. Only the
# three allowlisted cumulative metrics with strict namespace/pod/container
# labels are read; no raw metric line, URL, label, or header is emitted.
cfs_awk='
  {
    metric = ""
    if ($0 ~ /^container_cpu_cfs_periods_total\{/) metric = "periodsTotal"
    else if ($0 ~ /^container_cpu_cfs_throttled_periods_total\{/) metric = "throttledPeriodsTotal"
    else if ($0 ~ /^container_cpu_cfs_throttled_seconds_total\{/) metric = "throttledSecondsTotal"
    if (metric == "") next
    if (!match($0, /namespace="[^"]*"/)) next
    if (substr($0, RSTART + 11, RLENGTH - 12) != ns) next
    if (!match($0, /pod="[^"]*"/)) next
    pod = substr($0, RSTART + 5, RLENGTH - 6)
    if (!match($0, /container="[^"]*"/)) next
    ctr = substr($0, RSTART + 11, RLENGTH - 12)
    key = pod SUBSEP ctr SUBSEP metric
    if (key in seen) dup[key] = 1
    else seen[key] = $NF
  }
  END {
    for (key in seen) {
      split(key, parts, SUBSEP)
      if (dup[key]) print parts[1] "\t" parts[2] "\t" parts[3] "\tdup"
      else print parts[1] "\t" parts[2] "\t" parts[3] "\t" seen[key]
    }
  }
'

cfs_parse='
  def period_count($v):
    if ($v|type) == "string" and ($v|test("^(0|[1-9][0-9]*)$")) then
      ($v|tonumber) as $n | if ($n|isfinite) and $n >= 0 and ($n|floor) == $n and $n <= 9007199254740991 then $n else null end
    else null end;
  def seconds($v):
    if ($v|type) == "string" and ($v|test("^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$")) then
      ($v|tonumber) as $n | if ($n|isfinite) and $n >= 0 and $n <= 9007199254740991 then $n else null end
    else null end;
  [ split("\n")[] | select(length > 0) | split("\t") | {pod: .[0], container: .[1], metric: .[2], raw: .[3]} ]
  | reduce .[] as $e ({};
      ($e.pod + "/" + $e.container) as $k
      | .[$k] = ((.[$k] // {}) + {($e.metric): (if $e.raw == "dup" then "ambiguous" elif $e.metric == "throttledSecondsTotal" then seconds($e.raw) else period_count($e.raw) end)})
    )
'

while :; do
	timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	if pod_status=$(kubectl --request-timeout=5s --context "kind-$cluster" -n "$namespace" get pods -l app.kubernetes.io/name=goauthy -o json 2>/dev/null); then
		pod_status_ok=true
	else
		pod_status='{"items":[]}'
		pod_status_ok=false
	fi
	if stats=$(docker exec "$node" crictl stats -o json 2>/dev/null); then
		sample_ok=true
	else
		stats='{"stats":[]}'
		sample_ok=false
	fi
	if cadvisor=$(kubectl --request-timeout=5s --context "kind-$cluster" get --raw "$cadvisor_path" 2>/dev/null); then
		cfs_ok=true
	else
		cadvisor=''
		cfs_ok=false
	fi
	cfs_json=$(printf '%s\n' "$cadvisor" | awk -v ns="$namespace" "$cfs_awk" | jq -R -s -c "$cfs_parse")
	printf '%s\n' "$pod_status" >"$pod_status_file"
	if ! jq -s -e 'length == 1 and (.[0]|type) == "object" and (.[0].items|type) == "array"' "$pod_status_file" >/dev/null 2>&1; then
		fail 'pod status must be one JSON object with an items array'
	fi
	printf '%s\n' "$stats" | jq -c --arg timestamp "$timestamp" --arg namespace "$namespace" --slurpfile pod_status "$pod_status_file" --argjson pod_status_ok "$pod_status_ok" --argjson sample_ok "$sample_ok" --argjson cfs "$cfs_json" --argjson cfs_ok "$cfs_ok" "$projection" >>"$output"
	sleep 1
done
