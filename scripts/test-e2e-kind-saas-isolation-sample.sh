#!/bin/sh
# Exercise the real CRI projection and the resource gate embedded in the runner.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM
mkdir "$temp_dir/bin"

for tool in awk date grep jq mktemp sed sh stat; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 1; }
done

# Keep the regression bound to the production jq gate instead of copying it.
awk '
	index($0, "jq -s -e") && !copy { copy=1; next }
	copy && index($0, "\"$sample_output\"") { exit }
	copy { print }
' "$root/scripts/e2e-kind-saas-isolation-113.sh" >"$temp_dir/gate.jq"
[ -s "$temp_dir/gate.jq" ] || { echo 'could not extract runner resource gate' >&2; exit 1; }

jq -cn '
	def id($n): ($n|tostring) as $s | ("0" * (64 - ($s|length))) + $s;
	["goauthy-0","goauthy-1","goauthy-2"] as $pods |
	["goauthy","sidecarfixture"] as $containers |
	{stats:[
		$pods|to_entries[] as $p | $containers|to_entries[] as $c |
		(($p.key*2)+$c.key+1) as $n |
		{attributes:{id:id($n),labels:{
			"io.kubernetes.pod.namespace":"goauthy",
			"io.kubernetes.pod.name":$p.value,
			"io.kubernetes.container.name":$c.value}},
		cpu:{usageCoreNanoSeconds:{value:"12345"}},
		memory:{workingSetBytes:{value:"67890"}}}
	]}' >"$temp_dir/cri.json"
jq -cn '
	def id($n): ($n|tostring) as $s | ("0" * (64 - ($s|length))) + $s;
	["goauthy-0","goauthy-1","goauthy-2"] as $pods |
	["goauthy","sidecarfixture"] as $containers |
	{items:[
		$pods|to_entries[] as $p |
		{metadata:{name:$p.value},status:{containerStatuses:[
			$containers|to_entries[] as $c |
			(($p.key*2)+$c.key+1) as $n |
			{name:$c.value,state:{running:{}},containerID:("containerd://"+id($n))}
		]}}
	]}' >"$temp_dir/pods.json"
jq '.items[0].metadata.annotations = {padding: ("x" * 2300000)}' "$temp_dir/pods.json" >"$temp_dir/large-pods.json"
printf 'this is not json' >"$temp_dir/malformed.json"
printf '{"items":[]}\n{"items":[]}\n' >"$temp_dir/multi.json"

cat >"$temp_dir/bin/docker" <<'EOF'
#!/bin/sh
case "$*" in
	*"crictl version"*) exit 0 ;;
	*"crictl stats -o json"*)
		if [ "${CRI_FAIL:-0}" = 1 ]; then exit 42; fi
		cat "$CRI_FIXTURE"
		;;
	*) exit 0 ;;
esac
EOF
chmod +x "$temp_dir/bin/docker"
cat >"$temp_dir/bin/kubectl" <<'EOF'
#!/bin/sh
case "$*" in
	*" get pods "*) cat "$KUBE_FIXTURE" ;;
	*" get --raw "*)
		if [ "${CADVISOR_FAIL:-0}" = 1 ]; then exit 7; fi
		cat "$CADVISOR_FIXTURE"
		;;
	*) exit 2 ;;
esac
EOF
chmod +x "$temp_dir/bin/kubectl"
PATH="$temp_dir/bin:$PATH"
export PATH
CRI_FIXTURE=$temp_dir/cri.json
KUBE_FIXTURE=$temp_dir/pods.json
CADVISOR_FIXTURE=$temp_dir/cadvisor.txt
export CRI_FIXTURE KUBE_FIXTURE CADVISOR_FIXTURE
# Real 64-hex Kind/containerd IDs shared by the CRI fixtures and the cAdvisor
# cgroup scope labels.
hexid() { printf '%064x' "$1"; }
id1=$(hexid 1)
hexdead=$(printf 'deadbeef%056d' 0)
: >"$temp_dir/cadvisor.txt"
cfs_n=0
for cfs_pod in goauthy-0 goauthy-1 goauthy-2; do
	for cfs_container in goauthy sidecarfixture; do
		cfs_n=$((cfs_n + 1))
		cfs_id=$(hexid "$cfs_n")
		printf 'container_cpu_cfs_periods_total{container="%s",namespace="goauthy",pod="%s",id="/kubepods.slice/cri-containerd-%s.scope"} 100\n' "$cfs_container" "$cfs_pod" "$cfs_id" >>"$temp_dir/cadvisor.txt"
		printf 'container_cpu_cfs_throttled_periods_total{container="%s",namespace="goauthy",pod="%s",id="/kubepods.slice/cri-containerd-%s.scope"} 5\n' "$cfs_container" "$cfs_pod" "$cfs_id" >>"$temp_dir/cadvisor.txt"
		printf 'container_cpu_cfs_throttled_seconds_total{container="%s",namespace="goauthy",pod="%s",id="/kubepods.slice/cri-containerd-%s.scope"} 0.25\n' "$cfs_container" "$cfs_pod" "$cfs_id" >>"$temp_dir/cadvisor.txt"
	done
done

run_case() {
	name=$1 expected=$2 mode=$3
	kube_fixture=$temp_dir/pods.json
	case $mode in
		valid|large-pods|malformed-pods|multi-pods) cp "$temp_dir/cri.json" "$temp_dir/input.json" ;;
		restart-mismatch) jq --arg idd "$hexdead" '.stats += [(.stats[] | select(.attributes.labels["io.kubernetes.pod.name"]=="goauthy-0" and .attributes.labels["io.kubernetes.container.name"]=="goauthy") | .attributes.id=$idd)]' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		duplicate-active) jq '.stats += [.stats[] | select(.attributes.labels["io.kubernetes.pod.name"]=="goauthy-0" and .attributes.labels["io.kubernetes.container.name"]=="goauthy")]' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		mismatch-only) jq --arg idd "$hexdead" '(.stats[] | select(.attributes.labels["io.kubernetes.pod.name"]=="goauthy-0" and .attributes.labels["io.kubernetes.container.name"]=="goauthy").attributes.id)=$idd' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		missing) jq 'del(.stats[0].cpu.usageCoreNanoSeconds)' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		null) jq '.stats[0].cpu.usageCoreNanoSeconds.value=null' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		wrong) jq '.stats[0].memory.workingSetBytes.value="not-a-counter"' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		negative) jq '.stats[0].cpu.usageCoreNanoSeconds.value="-1"' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		command-fail) cp "$temp_dir/cri.json" "$temp_dir/input.json" ;;
		*) echo "unknown case: $mode" >&2; exit 2 ;;
	esac
	case $mode in
		large-pods) kube_fixture=$temp_dir/large-pods.json ;;
		malformed-pods) kube_fixture=$temp_dir/malformed.json ;;
		multi-pods) kube_fixture=$temp_dir/multi.json ;;
	esac
	KUBE_FIXTURE=$kube_fixture
	export KUBE_FIXTURE
	CRI_FIXTURE=$temp_dir/input.json
	export CRI_FIXTURE
	if [ "$mode" = command-fail ]; then CRI_FAIL=1; export CRI_FAIL; else unset CRI_FAIL || :; fi
	output=$temp_dir/$name.jsonl
	"$root/scripts/e2e-kind-saas-isolation-sample.sh" fixture goauthy "$output" >/dev/null 2>&1 &
	sampler_pid=$!
	i=0
	while [ ! -s "$output" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	if [ ! -s "$output" ]; then kill -TERM "$sampler_pid" 2>/dev/null || :; wait "$sampler_pid" 2>/dev/null || :; echo "$name: sampler emitted no row" >&2; exit 1; fi
	kill -TERM "$sampler_pid"
	if wait "$sampler_pid"; then sampler_status=0; else sampler_status=$?; fi
	[ "$sampler_status" -eq 0 ] || { echo "$name: sampler exited $sampler_status" >&2; exit 1; }
	if jq -s -e -f "$temp_dir/gate.jq" "$output" >/dev/null 2>&1; then gate_status=0; else gate_status=1; fi
	if [ "$gate_status" -ne "$expected" ]; then echo "$name: expected gate status $expected, got $gate_status" >&2; exit 1; fi
	printf '%s: %s\n' "$name" "$(if [ "$expected" -eq 0 ]; then echo accepted; else echo rejected; fi)"
}

run_case wrapped-counters 0 valid
jq -s -e 'length==6 and all(.[]; .memoryRSSBytes==null and (.unavailable|index("rss-not-exposed"))!=null)' "$temp_dir/wrapped-counters.jsonl" >/dev/null
run_case restart-id-mismatch 0 restart-mismatch
jq -s -e --arg id1 "$id1" --arg idd "$hexdead" 'length==6 and ([.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .containerID==$id1 and .currentContainerID==("containerd://"+$id1) and (.candidateContainerIDs|index($idd))!=null and ([.unavailable[]|select(.!="rss-not-exposed")]|length)==0)' "$temp_dir/restart-id-mismatch.jsonl" >/dev/null
run_case duplicate-active-id 1 duplicate-active
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .containerID==null and (.unavailable|index("duplicate-container-rows"))!=null' "$temp_dir/duplicate-active-id.jsonl" >/dev/null
run_case current-id-mismatch 1 mismatch-only
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .containerID==null and (.unavailable|index("current-container-id-not-reported"))!=null' "$temp_dir/current-id-mismatch.jsonl" >/dev/null
run_case missing-required-counter 1 missing
run_case null-required-counter 1 null
run_case wrong-type-counter 1 wrong
run_case negative-counter 1 negative
run_case cri-command-failure 1 command-fail

# CPU CFS throttle evidence (node cAdvisor via the kubectl node proxy).
run_case cfs-valid 0 valid
jq -s -e 'length==6 and all(.[]; .cpuCfsPeriodsTotal==100 and .cpuCfsThrottledPeriodsTotal==5 and .cpuCfsThrottledSecondsTotal==0.25 and .cpuCfsUnavailable==[])' "$temp_dir/cfs-valid.jsonl" >/dev/null

# Prometheus optional int64 timestamp must be accepted but never read as the
# counter; with and without a timestamp the values are identical.
sed 's/} 100$/} 100 1696700000000/; s/} 5$/} 5 1696700000000/; s/} 0.25$/} 0.25 1696700000000/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-ts.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-ts.txt run_case cfs-timestamp 0 valid
jq -s -e 'length==6 and all(.[]; .cpuCfsPeriodsTotal==100 and .cpuCfsThrottledPeriodsTotal==5 and .cpuCfsThrottledSecondsTotal==0.25 and .cpuCfsUnavailable==[])' "$temp_dir/cfs-timestamp.jsonl" >/dev/null

# A label value containing a space must not shift the VALUE extraction.
sed 's/namespace="goauthy",pod="goauthy-0"/namespace="goauthy",image="foo bar",pod="goauthy-0"/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-label-space.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-label-space.txt run_case cfs-label-space 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==100 and .cpuCfsUnavailable==[]' "$temp_dir/cfs-label-space.jsonl" >/dev/null

# Malformed timestamp and trailing unsupported tokens fail closed.
sed 's/} 100$/} 100 notanumber/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-bad-ts.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-bad-ts.txt run_case cfs-bad-timestamp 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-bad-timestamp.jsonl" >/dev/null

sed 's/} 100$/} 100 1696700000000 extra/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-trailing.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-trailing.txt run_case cfs-trailing-token 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-trailing-token.jsonl" >/dev/null

grep -v '^container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-missing.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-missing.txt run_case cfs-missing 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-missing.jsonl" >/dev/null

{ cat "$temp_dir/cadvisor.txt"; grep '^container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"' "$temp_dir/cadvisor.txt"; } >"$temp_dir/cadvisor-dup.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-dup.txt run_case cfs-dup 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-ambiguous"))!=null' "$temp_dir/cfs-dup.jsonl" >/dev/null

sed 's/^\(container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"[^}]*}\) .*/\1 notanumber/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-invalid.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-invalid.txt run_case cfs-invalid 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-invalid.jsonl" >/dev/null

sed 's/^\(container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"[^}]*}\) .*/\1 100.5/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-fractional.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-fractional.txt run_case cfs-fractional-period 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-fractional-period.jsonl" >/dev/null

sed 's/^\(container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"[^}]*}\) .*/\1 9007199254740992/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-oversize.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-oversize.txt run_case cfs-oversize-period 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-oversize-period.jsonl" >/dev/null

CADVISOR_FIXTURE=$temp_dir/cadvisor.txt run_case cfs-seconds-fractional 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsThrottledSecondsTotal==0.25 and .cpuCfsUnavailable==[]' "$temp_dir/cfs-seconds-fractional.jsonl" >/dev/null

CADVISOR_FAIL=1 run_case cfs-endpoint-fail 0 valid
jq -s -e 'length==6 and all(.[]; .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cadvisor-endpoint-unavailable"))!=null)' "$temp_dir/cfs-endpoint-fail.jsonl" >/dev/null
unset CADVISOR_FAIL || :

# cAdvisor source-instance binding: each accepted CFS metric must carry the
# cgroup scope of the selected current CRI container ID. A mismatched,
# malformed, absent, or conflicting instance is unavailable or ambiguous.
sed 's#cri-containerd-[0-9a-f]*\.scope#cri-containerd-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.scope#' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-mismatch.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-mismatch.txt run_case cfs-instance-mismatch 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-instance-mismatch.jsonl" >/dev/null

sed 's#id="/kubepods.slice/cri-containerd-[0-9a-f]*\.scope"#id="/x"#' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-badinst.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-badinst.txt run_case cfs-instance-malformed 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-instance-malformed.jsonl" >/dev/null

sed 's#,id="/kubepods.slice/cri-containerd-[0-9a-f]*\.scope"##' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-noid.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-noid.txt run_case cfs-instance-absent 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-instance-absent.jsonl" >/dev/null

cp "$temp_dir/cadvisor.txt" "$temp_dir/cadvisor-conflict.txt"
grep '^container_cpu_cfs_periods_total{container="goauthy",namespace="goauthy",pod="goauthy-0"' "$temp_dir/cadvisor.txt" | sed 's#cri-containerd-[0-9a-f]*\.scope#cri-containerd-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.scope#' >>"$temp_dir/cadvisor-conflict.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-conflict.txt run_case cfs-instance-conflict 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-ambiguous"))!=null' "$temp_dir/cfs-instance-conflict.jsonl" >/dev/null

# A valid numeric timestamp with an invalid metric value must stay unavailable.
sed 's/} 100$/} notanumber 1696700000000/' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-invalidval.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-invalidval.txt run_case cfs-invalid-value-valid-ts 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-invalid-value-valid-ts.jsonl" >/dev/null

# Exact label-name binding: a lookalike label whose name merely ends in
# "namespace"/"id" (e.g. container_label_io_kubernetes_pod_uid) must not be
# read as the real label. The real labels win.
sed 's#namespace="goauthy",pod="goauthy-0",id="#container_label_io_kubernetes_pod_uid="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",container_label_io_kubernetes_pod_namespace="evil",namespace="goauthy",pod="goauthy-0",id="#' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-lookalike.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-lookalike.txt run_case cfs-lookalike-labels 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==100 and .cpuCfsUnavailable==[]' "$temp_dir/cfs-lookalike-labels.jsonl" >/dev/null

# Only a lookalike *_uid label and no real id label: the source instance is
# absent and the metric must be unavailable even though the lookalike value
# equals the current CRI id.
sed 's#,id="/kubepods.slice/cri-containerd-[0-9a-f]*\.scope"#,container_label_io_kubernetes_pod_uid="/kubepods.slice/cri-containerd-0000000000000000000000000000000000000000000000000000000000000001.scope"#' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-lookalikeid.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-lookalikeid.txt run_case cfs-lookalike-id-absent 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==null and (.cpuCfsUnavailable|index("cfs-counter-unavailable"))!=null' "$temp_dir/cfs-lookalike-id-absent.jsonl" >/dev/null

# A quoted label value containing a comma and an escaped fake id= must not
# shift the label boundary or the value extraction.
sed 's#namespace="goauthy",pod="goauthy-0",id="#container_label_io_kubernetes_pod_uid="a,id=\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",b",namespace="goauthy",pod="goauthy-0",id="#' "$temp_dir/cadvisor.txt" >"$temp_dir/cadvisor-comma.txt"
CADVISOR_FIXTURE=$temp_dir/cadvisor-comma.txt run_case cfs-label-comma 0 valid
jq -s -e '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .cpuCfsPeriodsTotal==100 and .cpuCfsUnavailable==[]' "$temp_dir/cfs-label-comma.jsonl" >/dev/null

# Sampler-to-summary pipeline controls using the ACTUAL cfs_delta from the
# shared analyzer (bounded extract, not a copied implementation). These run
# real sampler-produced rows through the real delta function.
series_count() {
  if count_value=$(jq -s '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")]|length' "$1" 2>/dev/null); then
    printf '%s\n' "$count_value"
  else
    printf '0\n'
  fi
}
capture_two() {
  name=$1
  output=$temp_dir/$name.jsonl
  "$root/scripts/e2e-kind-saas-isolation-sample.sh" fixture goauthy "$output" >/dev/null 2>&1 &
  sampler_pid=$!
  i=0
  while [ "$(series_count "$output")" -lt 2 ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  kill -TERM "$sampler_pid" 2>/dev/null || :
  wait "$sampler_pid" || { echo "$name: sampler failed" >&2; exit 1; }
  [ "$(series_count "$output")" -ge 2 ] || { echo "$name: sampler emitted fewer than two target rows" >&2; exit 1; }
}
awk '
  /^def cfs_delta\(/ { copy=1 }
  copy && /^def / && !/^def cfs_delta\(/ { exit }
  copy { print }
' "$root/scripts/summarize-e2e-kind-saas-isolation-113.jq" >"$temp_dir/cfs_delta.jq"
[ -s "$temp_dir/cfs_delta.jq" ] || { echo 'could not extract cfs_delta' >&2; exit 1; }
{ cat "$temp_dir/cfs_delta.jq"; echo '$rows[0] | cfs_delta($field)'; } >"$temp_dir/cfs_delta_run.jq"
series() { jq -s -c '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")]'; }

CADVISOR_FIXTURE=$temp_dir/cadvisor.txt capture_two cfs-pipeline-valid
CADVISOR_FIXTURE=$temp_dir/cadvisor-mismatch.txt capture_two cfs-pipeline-mismatch
CADVISOR_FIXTURE=$temp_dir/cadvisor-noid.txt capture_two cfs-pipeline-absent
series <"$temp_dir/cfs-pipeline-valid.jsonl" >"$temp_dir/series-valid.json"
series <"$temp_dir/cfs-pipeline-mismatch.jsonl" >"$temp_dir/series-mismatch.json"
series <"$temp_dir/cfs-pipeline-absent.jsonl" >"$temp_dir/series-absent.json"

# Two matching valid samples: stable containerID, length 2, complete, delta 0.
jq -e 'length == 2 and ([.[].containerID] | unique | length) == 1' "$temp_dir/series-valid.json" >/dev/null
jq -n --slurpfile rows "$temp_dir/series-valid.json" --arg field "cpuCfsPeriodsTotal" -f "$temp_dir/cfs_delta_run.jq" >"$temp_dir/cfs-delta-valid.json"
jq -e '.complete == true and .delta == 0 and .first == 100 and .last == 100' "$temp_dir/cfs-delta-valid.json" >/dev/null

# Both mismatch / absent: no usable field, complete false, delta null.
jq -n --slurpfile rows "$temp_dir/series-mismatch.json" --arg field "cpuCfsPeriodsTotal" -f "$temp_dir/cfs_delta_run.jq" >"$temp_dir/cfs-delta-mismatch.json"
jq -e '.complete == false and .delta == null' "$temp_dir/cfs-delta-mismatch.json" >/dev/null
jq -n --slurpfile rows "$temp_dir/series-absent.json" --arg field "cpuCfsPeriodsTotal" -f "$temp_dir/cfs_delta_run.jq" >"$temp_dir/cfs-delta-absent.json"
jq -e '.complete == false and .delta == null' "$temp_dir/cfs-delta-absent.json" >/dev/null

# A matching valid sample followed by a mismatch sample with the same constant
# CRI containerID models a cAdvisor identity change while the CRI ID stays
# constant: incomplete, delta null.
{ cat "$temp_dir/cfs_delta.jq"; echo '$a[0] + $b[0] | cfs_delta($field)'; } >"$temp_dir/cfs_delta_combined.jq"
series <"$temp_dir/cfs-pipeline-valid.jsonl" | jq -c '.[0:1]' >"$temp_dir/series-a.json"
series <"$temp_dir/cfs-pipeline-mismatch.jsonl" | jq -c '.[0:1]' >"$temp_dir/series-b.json"
jq -n --slurpfile a "$temp_dir/series-a.json" --slurpfile b "$temp_dir/series-b.json" --arg field "cpuCfsPeriodsTotal" -f "$temp_dir/cfs_delta_combined.jq" >"$temp_dir/cfs-delta-combined.json"
jq -e '.complete == false and .delta == null' "$temp_dir/cfs-delta-combined.json" >/dev/null
jq -ne --slurpfile a "$temp_dir/series-a.json" --slurpfile b "$temp_dir/series-b.json" '$a[0] + $b[0] | length == 2 and all(.[]; (.containerID | type) == "string" and (.containerID | length) > 0) and ([.[].containerID] | unique | length) == 1' >/dev/null

private_canary() {
	canary_dir=$(mktemp -d) || return 1
	old_tmpdir=${TMPDIR-}
	TMPDIR=$canary_dir
	export TMPDIR
	KUBE_FIXTURE=$temp_dir/large-pods.json
	export KUBE_FIXTURE
	output=$temp_dir/private-canary.jsonl
	"$root/scripts/e2e-kind-saas-isolation-sample.sh" fixture goauthy "$output" >/dev/null 2>&1 &
	sampler_pid=$!
	i=0
	private_file=''
	while [ "$i" -lt 50 ]; do
		for f in "$canary_dir"/*/pod-status.json; do
			if [ -f "$f" ]; then private_file=$f; break; fi
		done
		[ -n "$private_file" ] && break
		sleep 0.1
		i=$((i + 1))
	done
	if [ -z "$private_file" ]; then
		echo 'private-canary: sampler created no private pod-status file' >&2
		kill -TERM "$sampler_pid" 2>/dev/null || :
		wait "$sampler_pid" 2>/dev/null || :
		rm -rf "$canary_dir"
		return 1
	fi
	if perms=$(stat -c '%a' "$private_file" 2>/dev/null); then :;
	else perms=$(stat -f '%Lp' "$private_file" 2>/dev/null) || perms=unknown; fi
	if [ "$perms" != 600 ]; then
		echo "private-canary: private pod-status file mode is $perms, expected 600" >&2
		kill -TERM "$sampler_pid" 2>/dev/null || :
		wait "$sampler_pid" 2>/dev/null || :
		rm -rf "$canary_dir"
		return 1
	fi
	i=0
	while [ "$i" -lt 50 ]; do
		if jq -e 'type == "object" and (.items | type) == "array"' "$private_file" >/dev/null 2>&1; then break; fi
		sleep 0.1
		i=$((i + 1))
	done
	if [ "$i" -ge 50 ]; then
		echo 'private-canary: private pod-status file never held a pod-status object' >&2
		kill -TERM "$sampler_pid" 2>/dev/null || :
		wait "$sampler_pid" 2>/dev/null || :
		rm -rf "$canary_dir"
		return 1
	fi
	i=0
	while [ ! -s "$output" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	if [ ! -s "$output" ]; then
		echo 'private-canary: sampler emitted no row' >&2
		kill -TERM "$sampler_pid" 2>/dev/null || :
		wait "$sampler_pid" 2>/dev/null || :
		rm -rf "$canary_dir"
		return 1
	fi
	kill -TERM "$sampler_pid"
	if wait "$sampler_pid"; then sampler_status=0; else sampler_status=$?; fi
	if [ "$sampler_status" -ne 0 ]; then
		echo "private-canary: sampler exited $sampler_status" >&2
		rm -rf "$canary_dir"
		return 1
	fi
	for f in "$canary_dir"/*; do
		if [ -e "$f" ]; then
			echo 'private-canary: owned pod-status directory was not removed on exit' >&2
			rm -rf "$canary_dir"
			return 1
		fi
	done
	[ -s "$output" ] || { echo 'private-canary: output file was removed' >&2; rm -rf "$canary_dir"; return 1; }
	rm -rf "$canary_dir"
	if [ -n "$old_tmpdir" ]; then TMPDIR=$old_tmpdir; export TMPDIR; else unset TMPDIR; fi
	jq -s -e 'length==6 and all(.[]; .memoryRSSBytes==null and (.unavailable|index("rss-not-exposed"))!=null)' "$output" >/dev/null
	printf '%s: %s\n' 'private-canary' 'accepted'
}

run_case large-input 0 large-pods
jq -s -e 'length==6 and all(.[]; .memoryRSSBytes==null and (.unavailable|index("rss-not-exposed"))!=null)' "$temp_dir/large-input.jsonl" >/dev/null
jq -s -e --arg id1 "$id1" '[.[]|select(.pod=="goauthy-0" and .container=="goauthy")][0] | .containerID==$id1 and .currentContainerID==("containerd://"+$id1) and ([.unavailable[]|select(.!="rss-not-exposed")]|length)==0' "$temp_dir/large-input.jsonl" >/dev/null
for mode in malformed multi; do
	KUBE_FIXTURE=$temp_dir/$mode.json
	export KUBE_FIXTURE
	case_dir=$(mktemp -d "$temp_dir/reject.XXXXXX")
	if TMPDIR=$case_dir "$root/scripts/e2e-kind-saas-isolation-sample.sh" fixture goauthy "$temp_dir/$mode-rejected.jsonl" >/dev/null 2>&1; then
		echo "$mode: sampler accepted invalid pod JSON" >&2; exit 1
	fi
	[ ! -s "$temp_dir/$mode-rejected.jsonl" ] || { echo "$mode: sampler emitted rows" >&2; exit 1; }
	for f in "$case_dir"/*; do
		[ ! -e "$f" ] || { echo "$mode: private input survived failure" >&2; exit 1; }
	done
	printf '%s: rejected with private input removed\n' "$mode"
done
private_canary || exit 1
echo 'sampler projection and runner resource-gate regression passed'
