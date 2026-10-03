#!/bin/sh
set -eu

usage() { echo "usage: $0 KIND_CLUSTER NAMESPACE OUTPUT.jsonl" >&2; exit 2; }
fail() { echo "$*" >&2; exit 1; }
[ "$#" -eq 3 ] || usage
cluster=$1 namespace=$2 output=$3
case $cluster in ''|*[!a-z0-9-]*) fail 'invalid Kind cluster name';; esac
case $namespace in ''|*[!a-z0-9.-]*|.*|*.|*..*) fail 'invalid namespace';; esac
[ -n "$output" ] || usage
for tool in docker jq date sleep kubectl; do command -v "$tool" >/dev/null 2>&1 || fail "required tool missing: $tool"; done
node="${cluster}-control-plane"
docker inspect "$node" >/dev/null 2>&1 || fail "Kind node container missing: $node"
docker exec "$node" crictl version >/dev/null 2>&1 || fail 'crictl unavailable in Kind node'
umask 077
set -C
: >"$output" || fail 'output file must be a new writable path'
set +C
trap 'exit 0' HUP INT TERM

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
  | ([$pod_status.items[]? | select(.metadata.name == $pod) | .status.containerStatuses[]? | select(
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
	printf '%s\n' "$stats" | jq -c --arg timestamp "$timestamp" --arg namespace "$namespace" --argjson pod_status "$pod_status" --argjson pod_status_ok "$pod_status_ok" --argjson sample_ok "$sample_ok" "$projection" >>"$output"
	sleep 1
done
