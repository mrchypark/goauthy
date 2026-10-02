#!/bin/sh
set -eu

usage() { echo "usage: $0 KIND_CLUSTER NAMESPACE OUTPUT.jsonl" >&2; exit 2; }
fail() { echo "$*" >&2; exit 1; }
[ "$#" -eq 3 ] || usage
cluster=$1 namespace=$2 output=$3
case $cluster in ''|*[!a-z0-9-]*) fail 'invalid Kind cluster name';; esac
case $namespace in ''|*[!a-z0-9.-]*|.*|*.|*..*) fail 'invalid namespace';; esac
[ -n "$output" ] || usage
for tool in docker jq date sleep; do command -v "$tool" >/dev/null 2>&1 || fail "required tool missing: $tool"; done
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
  | ([.stats[]? | select(
      .attributes.labels["io.kubernetes.pod.namespace"] == $namespace and
      .attributes.labels["io.kubernetes.pod.name"] == $pod and
      .attributes.labels["io.kubernetes.container.name"] == $container
    )]) as $matches
  | ($matches[0] // {}) as $s
  | ($s.memory.rssBytes // $s.memory.rss_bytes) as $rss
  | ($s.cpu.usageCoreNanoSeconds | counter) as $cpu
  | ($s.memory.workingSetBytes | counter) as $working
  | ($rss | counter) as $rss_bytes
  | {
      hostTimestampUTC: $timestamp,
      namespace: $namespace,
      pod: $pod,
      container: $container,
      containerID: (if ($s.attributes.id | type) == "string" then $s.attributes.id else null end),
      cpuUsageCoreNanoSeconds: $cpu,
      memoryWorkingSetBytes: $working,
      memoryRSSBytes: $rss_bytes,
      unavailable: (
        (if $sample_ok then [] else ["cri-stats-command-failed"] end) +
        (if ($matches | length) == 0 then ["container-not-reported"] elif ($matches | length) > 1 then ["duplicate-container-rows"] else [] end) +
        (if ($matches | length) == 1 and ($s.attributes.id | type) != "string" then ["container-id-unavailable"] else [] end) +
        (if ($matches | length) == 1 and $cpu == null then ["cpu-counter-unavailable"] else [] end) +
        (if ($matches | length) == 1 and $working == null then ["working-set-unavailable"] else [] end) +
        (if ($matches | length) == 1 and $rss_bytes == null then (if $rss == null then ["rss-not-exposed"] else ["rss-counter-unavailable"] end) else [] end)
      )
    }
'

while :; do
	timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	if stats=$(docker exec "$node" crictl stats -o json 2>/dev/null); then
		sample_ok=true
	else
		stats='{"stats":[]}'
		sample_ok=false
	fi
	printf '%s\n' "$stats" | jq -c --arg timestamp "$timestamp" --arg namespace "$namespace" --argjson sample_ok "$sample_ok" "$projection" >>"$output"
	sleep 1
done
