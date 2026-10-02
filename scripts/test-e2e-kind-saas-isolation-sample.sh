#!/bin/sh
# Exercise the real CRI projection and the resource gate embedded in the runner.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0 HUP INT TERM
mkdir "$temp_dir/bin"

for tool in awk date jq sh; do
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
	["goauthy-0","goauthy-1","goauthy-2"] as $pods |
	["goauthy","sidecarfixture"] as $containers |
	{stats:[
		$pods[] as $pod | $containers[] as $container |
		{attributes:{id:($pod+"/"+$container),labels:{
			"io.kubernetes.pod.namespace":"goauthy",
			"io.kubernetes.pod.name":$pod,
			"io.kubernetes.container.name":$container}},
		cpu:{usageCoreNanoSeconds:{value:"12345"}},
		memory:{workingSetBytes:{value:"67890"}}}
	]}' >"$temp_dir/cri.json"

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
PATH="$temp_dir/bin:$PATH"
export PATH
CRI_FIXTURE=$temp_dir/cri.json
export CRI_FIXTURE

run_case() {
	name=$1 expected=$2 mode=$3
	case $mode in
		valid) cp "$temp_dir/cri.json" "$temp_dir/input.json" ;;
		missing) jq 'del(.stats[0].cpu.usageCoreNanoSeconds)' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		null) jq '.stats[0].cpu.usageCoreNanoSeconds.value=null' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		wrong) jq '.stats[0].memory.workingSetBytes.value="not-a-counter"' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		negative) jq '.stats[0].cpu.usageCoreNanoSeconds.value="-1"' "$temp_dir/cri.json" >"$temp_dir/input.json" ;;
		command-fail) cp "$temp_dir/cri.json" "$temp_dir/input.json" ;;
		*) echo "unknown case: $mode" >&2; exit 2 ;;
	esac
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
run_case missing-required-counter 1 missing
run_case null-required-counter 1 null
run_case wrong-type-counter 1 wrong
run_case negative-counter 1 negative
run_case cri-command-failure 1 command-fail
echo 'sampler projection and runner resource-gate regression passed'
