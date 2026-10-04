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
  | ($c.periodsTotal // {}) as $cp
  | ($c.throttledPeriodsTotal // {}) as $ctp
  | ($c.throttledSecondsTotal // {}) as $cts
  | ($cp.v) as $cfs_periods
  | ($ctp.v) as $cfs_throttled_periods
  | ($cts.v) as $cfs_throttled_seconds
  | ([$cp.i, $ctp.i, $cts.i] | map(select(. != null and . != ""))) as $cfs_instances
  | ($cfs_ok
     and ($cfs_periods != "ambiguous" and $cfs_throttled_periods != "ambiguous" and $cfs_throttled_seconds != "ambiguous")
     and ($cfs_instances | length) == 3
     and (($cfs_instances | unique | length) == 1)
     and ($cfs_instances[0] == $active_cri_id)
     and (($cfs_periods|type) == "number" and ($cfs_throttled_periods|type) == "number" and ($cfs_throttled_seconds|type) == "number")) as $cfs_bound
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
      cpuCfsPeriodsTotal: (if $cfs_bound then $cfs_periods else null end),
      cpuCfsThrottledPeriodsTotal: (if $cfs_bound then $cfs_throttled_periods else null end),
      cpuCfsThrottledSecondsTotal: (if $cfs_bound then $cfs_throttled_seconds else null end),
      cpuCfsUnavailable: (
        if $cfs_bound then []
        elif ($cfs_ok | not) then ["cadvisor-endpoint-unavailable"]
        elif ($cfs_periods == "ambiguous" or $cfs_throttled_periods == "ambiguous" or $cfs_throttled_seconds == "ambiguous") then ["cfs-counter-ambiguous"]
        elif (($cfs_instances | length) == 3 and (($cfs_instances | unique | length) > 1)) then ["cfs-counter-ambiguous"]
        else ["cfs-counter-unavailable"] end
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
  function valid_ts(s,   n) {
    if (s !~ /^[0-9]+$/) return 0
    n = length(s)
    if (n > 19) return 0
    if (n < 19) return 1
    return (s "@") <= ("9223372036854775807" "@")
  }
  function split_labels(labels, segs,   i, n, c, inq, esc, cnt, cur) {
    n = length(labels)
    cnt = 0
    cur = ""
    inq = 0
    esc = 0
    for (i = 1; i <= n; i++) {
      c = substr(labels, i, 1)
      if (inq) {
        cur = cur c
        if (esc) esc = 0
        else if (c == "\\") esc = 1
        else if (c == "\"") inq = 0
      } else if (c == "\"") {
        inq = 1; cur = cur c
      } else if (c == ",") {
        cnt++; segs[cnt] = cur; cur = ""
      } else {
        cur = cur c
      }
    }
    cnt++; segs[cnt] = cur
    return cnt
  }
  function label_value(labels, want,   segs, cnt, i, eqpos, key, val) {
    cnt = split_labels(labels, segs)
    for (i = 1; i <= cnt; i++) {
      eqpos = index(segs[i], "=")
      if (eqpos == 0) continue
      key = substr(segs[i], 1, eqpos - 1)
      if (key != want) continue
      val = substr(segs[i], eqpos + 1)
      if (length(val) >= 2 && substr(val, 1, 1) == "\"" && substr(val, length(val), 1) == "\"") {
        return substr(val, 2, length(val) - 2)
      }
      return ""
    }
    return ""
  }
  function instance_of(raw,   s) {
    s = raw
    if (s ~ /\/cri-containerd-[0-9a-f]+\.scope$/) {
      sub(/^.*\/cri-containerd-/, "", s)
      sub(/\.scope$/, "", s)
    } else if (s ~ /\/[0-9a-f]+$/) {
      sub(/^.*\//, "", s)
    } else {
      return ""
    }
    if (s ~ /^[0-9a-f]+$/ && length(s) == 64) return s
    return ""
  }
  {
    metric = ""
    if ($0 ~ /^container_cpu_cfs_periods_total\{/) metric = "periodsTotal"
    else if ($0 ~ /^container_cpu_cfs_throttled_periods_total\{/) metric = "throttledPeriodsTotal"
    else if ($0 ~ /^container_cpu_cfs_throttled_seconds_total\{/) metric = "throttledSecondsTotal"
    if (metric == "") next
    open = index($0, "{")
    if (open == 0) next
    rest = substr($0, open + 1)
    i = 1; inq = 0; esc = 0; endpos = 0
    while (i <= length(rest)) {
      c = substr(rest, i, 1)
      if (inq) {
        if (esc) esc = 0
        else if (c == "\\") esc = 1
        else if (c == "\"") inq = 0
      } else if (c == "\"") { inq = 1 }
      else if (c == "}") { endpos = i; break }
      i++
    }
    if (endpos == 0) next
    labels = substr(rest, 1, endpos - 1)
    if (label_value(labels, "namespace") != ns) next
    pod = label_value(labels, "pod")
    if (pod == "") next
    ctr = label_value(labels, "container")
    if (ctr == "") next
    inst = instance_of(label_value(labels, "id"))
    tail = substr(rest, endpos + 1)
    gsub(/[ \t]+/, " ", tail)
    sub(/^ /, "", tail)
    sub(/ $/, "", tail)
    ntok = split(tail, tok, " ")
    value = "malformed"
    if (ntok == 1) value = tok[1]
    else if (ntok == 2 && valid_ts(tok[2])) value = tok[1]
    key = pod SUBSEP ctr SUBSEP metric
    if (key in seen) dup[key] = 1
    else { seen[key] = value; insts[key] = inst }
  }
  END {
    for (key in seen) {
      split(key, parts, SUBSEP)
      if (dup[key]) print parts[1] "\t" parts[2] "\t" parts[3] "\t" "\tdup"
      else print parts[1] "\t" parts[2] "\t" parts[3] "\t" insts[key] "\t" seen[key]
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
  [ split("\n")[] | select(length > 0) | split("\t") | {pod: .[0], container: .[1], metric: .[2], instance: .[3], raw: .[4]} ]
  | reduce .[] as $e ({};
      ($e.pod + "/" + $e.container) as $k
      | .[$k] = ((.[$k] // {}) + {($e.metric): (if $e.raw == "dup" then {v: "ambiguous", i: ""} else {v: (if $e.metric == "throttledSecondsTotal" then seconds($e.raw) else period_count($e.raw) end), i: $e.instance} end)})
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
