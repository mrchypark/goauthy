#!/bin/sh
# Offline privacy-safe summarizer for the local three-member SaaS isolation
# diagnostic. Reads a diagnostic directory and emits safe JSON on stdout.
# Only fixed isolation113 observation records and numeric counters are parsed;
# no raw logs, credentials, or container IDs are emitted.
set -eu
umask 077

usage() {
	echo "usage: $0 <diagnostic-directory>" >&2
	exit 2
}

[ "$#" -eq 1 ] || usage
dir=$1
case "$dir" in
	/*) ;;
	*) echo "diagnostic directory must be absolute: $dir" >&2; exit 1 ;;
esac
[ -d "$dir" ] || { echo "diagnostic directory not found: $dir" >&2; exit 1; }

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
analyzer_jq=$script_dir/summarize-e2e-kind-saas-isolation-113.jq
[ -f "$analyzer_jq" ] || { echo "companion analyzer not found: $analyzer_jq" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/parse.awk" <<'AWK'
/isolation113 phase=/ {
	s = $0
	sub(/^.*isolation113 /, "isolation113 ", s)
	m = split(s, tok, " ")
	if (tok[1] != "isolation113") { print "malformed observation prefix" > "/dev/stderr"; exit 1 }
	phase = ""; route = ""; operation = ""; outcome = ""; status = ""
	sched = ""; lag = ""; comp = ""
	for (i = 2; i <= m; i++) {
		t = tok[i]
		if (t ~ /^phase=/) phase = substr(t, 7)
		else if (t ~ /^route=/) route = substr(t, 7)
		else if (t ~ /^operation=/) operation = substr(t, 11)
		else if (t ~ /^outcome=/) outcome = substr(t, 9)
		else if (t ~ /^status=/) status = substr(t, 8)
		else if (t ~ /^scheduled_unix_ms=/) sched = substr(t, 19)
		else if (t ~ /^start_lag_ms=/) lag = substr(t, 14)
		else if (t ~ /^completion_latency_ms=/) comp = substr(t, 23)
		else { print "unexpected observation token" > "/dev/stderr"; exit 1 }
	}
	if (phase != "baseline" && phase != "mixed" && phase != "recovery") { print "invalid phase" > "/dev/stderr"; exit 1 }
	if (route != "iam" && route != "api-key") { print "invalid route" > "/dev/stderr"; exit 1 }
	if (route == "iam" && (operation != "" || status != "")) { print "iam record carries operation/status" > "/dev/stderr"; exit 1 }
	if (route == "api-key") {
		if (operation == "") { print "api-key record missing operation" > "/dev/stderr"; exit 1 }
		if (status !~ /^[0-9]+$/ || status + 0 < 100 || status + 0 > 599) { print "invalid status" > "/dev/stderr"; exit 1 }
	}
	if (outcome != "success" && outcome != "failed" && outcome != "transport-error" && outcome != "http-error") { print "invalid outcome" > "/dev/stderr"; exit 1 }
	if (sched != "" && sched !~ /^[0-9]+$/) { print "invalid scheduled_unix_ms" > "/dev/stderr"; exit 1 }
	if (lag !~ /^[0-9]+(\.[0-9]+)?$/) { print "invalid start_lag_ms" > "/dev/stderr"; exit 1 }
	if (comp !~ /^[0-9]+(\.[0-9]+)?$/) { print "invalid completion_latency_ms" > "/dev/stderr"; exit 1 }
	print di "\t" phase "\t" route "\t" operation "\t" outcome "\t" status "\t" sched "\t" lag "\t" comp
}
AWK

cat >"$tmp/parse_stage.awk" <<'AWK'
/isolation113-stage / {
	s = $0
	sub(/^.*isolation113-stage /, "isolation113-stage ", s)
	m = split(s, tok, " ")
	if (tok[1] != "isolation113-stage") { print "malformed stage prefix" > "/dev/stderr"; exit 1 }
	phase = ""; route = ""; stage = ""; outcome = ""; status = ""; elapsed = ""; sched = ""
	for (i = 2; i <= m; i++) {
		t = tok[i]
		if (t ~ /^phase=/) phase = substr(t, 7)
		else if (t ~ /^route=/) route = substr(t, 7)
		else if (t ~ /^stage=/) stage = substr(t, 7)
		else if (t ~ /^outcome=/) outcome = substr(t, 9)
		else if (t ~ /^status=/) status = substr(t, 8)
		else if (t ~ /^elapsed_ms=/) elapsed = substr(t, 12)
		else if (t ~ /^scheduled_unix_ms=/) sched = substr(t, 19)
		else { print "unexpected stage token" > "/dev/stderr"; exit 1 }
	}
	if (phase != "baseline" && phase != "mixed" && phase != "recovery") { print "invalid stage phase" > "/dev/stderr"; exit 1 }
	if (route != "iam") { print "invalid stage route" > "/dev/stderr"; exit 1 }
	if (stage != "authorize-get" && stage != "login-post") { print "invalid stage" > "/dev/stderr"; exit 1 }
	if (outcome != "none" && outcome != "timeout" && outcome != "canceled" && outcome != "transport") { print "invalid stage outcome" > "/dev/stderr"; exit 1 }
	if (status !~ /^[0-9]+$/) { print "invalid stage status" > "/dev/stderr"; exit 1 }
	if (elapsed !~ /^[0-9]+(\.[0-9]+)?$/) { print "invalid stage elapsed" > "/dev/stderr"; exit 1 }
	if (sched !~ /^[0-9]+$/) { print "invalid stage scheduled_unix_ms" > "/dev/stderr"; exit 1 }
	print di "\t" phase "\t" stage "\t" outcome "\t" status "\t" elapsed "\t" sched
}
AWK

obs_tsv=$tmp/observations.tsv
stage_tsv=$tmp/stages.tsv
: >"$obs_tsv"
: >"$stage_tsv"

attributed=false
for f in "$dir"/driver-isolation113-driver-*.log; do
	[ -f "$f" ] || continue
	idx=$(basename "$f" | sed -nE 's/.*goauthy-([0-9]+)-.*/\1/p')
	[ -n "$idx" ] || { echo "cannot derive driver index from $(basename "$f")" >&2; exit 1; }
	awk -v di="$idx" -f "$tmp/parse.awk" "$f" >>"$obs_tsv"
	awk -v di="$idx" -f "$tmp/parse_stage.awk" "$f" >>"$stage_tsv"
	attributed=true
done

if [ "$attributed" != true ]; then
	if [ -s "$dir/driver.log" ]; then
		awk -v di="" -f "$tmp/parse.awk" "$dir/driver.log" >>"$obs_tsv"
		awk -v di="" -f "$tmp/parse_stage.awk" "$dir/driver.log" >>"$stage_tsv"
	else
		echo "no driver observation logs found in $dir" >&2
		exit 1
	fi
fi

[ -s "$obs_tsv" ] || { echo "no observation records parsed" >&2; exit 1; }

jq -R -s '
	split("\n") | map(select(length > 0)) | map(split("\t")) | map({
		driver_index: (if .[0] == "" then null else (.[0] | tonumber) end),
		phase: .[1],
		stage: .[2],
		outcome: .[3],
		status: (.[4] | tonumber),
		elapsed_ms: (.[5] | tonumber),
		scheduled_unix_ms: (.[6] | tonumber)
	})
' "$stage_tsv" >"$tmp/stages.json"

if dup=$(awk -F'\t' '$7 != "" {print $1"\t"$2"\t"$3"\t"$4"\t"$7}' "$obs_tsv" | sort | uniq -d) && [ -n "$dup" ]; then
	echo "duplicate observation records detected" >&2
	exit 1
fi

jq -R -s '
	split("\n") | map(select(length > 0)) | map(split("\t")) | map({
		driver_index: (if .[0] == "" then null else (.[0] | tonumber) end),
		phase: .[1],
		route: .[2],
		operation: (if .[3] == "" then null else .[3] end),
		outcome: .[4],
		status: (if .[5] == "" then null else (.[5] | tonumber) end),
		scheduled_unix_ms: (if .[6] == "" then null else (.[6] | tonumber) end),
		start_lag_ms: (.[7] | tonumber),
		completion_latency_ms: (.[8] | tonumber)
	})
' "$obs_tsv" >"$tmp/observations.json"

jq -s '
	def nonneg: type == "number" and isfinite and . >= 0;
	def strict_int: type == "number" and isfinite and . >= 0 and (floor == .) and . <= 9007199254740991;
	def cfs_seconds: type == "number" and isfinite and . >= 0 and . <= 9007199254740991;
	def allowed_unavailable: ["cri-stats-command-failed","pod-status-command-failed","running-container-id-unavailable","running-container-id-ambiguous","container-not-reported","current-container-id-not-reported","duplicate-container-rows","container-id-unavailable","cpu-counter-unavailable","working-set-unavailable","rss-not-exposed","rss-counter-unavailable"];
	def allowed_cfs_unavailable: ["cadvisor-endpoint-unavailable","cfs-counter-unavailable","cfs-counter-ambiguous"];
	. as $rows |
	($rows | length) as $n |
	if $n == 0 then error("no container samples") else . end |
	([$rows[] | "\(.hostTimestampUTC)\t\(.pod)\t\(.container)"] | group_by(.) | map(select(length > 1))) as $dups |
	if ($dups | length) > 0 then error("duplicate container samples") else . end |
	[$rows[] |
		. as $r |
		(if ($r.hostTimestampUTC | type) == "string" and ($r.hostTimestampUTC | length) > 0 then . else error("missing hostTimestampUTC") end) |
		(if ($r.pod | type) == "string" and ($r.pod | test("^goauthy-[0-9]+$")) then . else error("unexpected pod name") end) |
		(if $r.container == "goauthy" or $r.container == "sidecarfixture" then . else error("unexpected container label") end) |
		(if ($r.cpuUsageCoreNanoSeconds | nonneg) then . else error("invalid cpu counter") end) |
		(if ($r.memoryWorkingSetBytes | nonneg) then . else error("invalid working set") end) |
		(if $r.memoryRSSBytes == null or ($r.memoryRSSBytes | nonneg) then . else error("invalid rss") end) |
		(if ($r.unavailable | type) == "array" and ($r.unavailable | all(.[]; . as $u | allowed_unavailable | index($u) != null)) then . else error("invalid unavailable label") end) |
		(if ($r.cpuCfsPeriodsTotal == null or ($r.cpuCfsPeriodsTotal | strict_int)) then . else error("invalid cfs periods") end) |
		(if ($r.cpuCfsThrottledPeriodsTotal == null or ($r.cpuCfsThrottledPeriodsTotal | strict_int)) then . else error("invalid cfs throttled periods") end) |
		(if ($r.cpuCfsThrottledSecondsTotal == null or ($r.cpuCfsThrottledSecondsTotal | cfs_seconds)) then . else error("invalid cfs throttled seconds") end) |
		(if $r.cpuCfsUnavailable == null or (($r.cpuCfsUnavailable | type) == "array" and ($r.cpuCfsUnavailable | all(.[]; . as $u | allowed_cfs_unavailable | index($u) != null))) then . else error("invalid cfs unavailable label") end) |
		{
			hostTimestampUTC: $r.hostTimestampUTC,
			pod_index: ($r.pod | capture("^goauthy-(?<i>[0-9]+)$") | .i | tonumber),
			container: $r.container,
			containerID: $r.containerID,
			cpuUsageCoreNanoSeconds: $r.cpuUsageCoreNanoSeconds,
			memoryWorkingSetBytes: $r.memoryWorkingSetBytes,
			memoryRSSBytes: $r.memoryRSSBytes,
			unavailable: $r.unavailable,
			cpuCfsPeriodsTotal: $r.cpuCfsPeriodsTotal,
			cpuCfsThrottledPeriodsTotal: $r.cpuCfsThrottledPeriodsTotal,
			cpuCfsThrottledSecondsTotal: $r.cpuCfsThrottledSecondsTotal,
			cpuCfsUnavailable: $r.cpuCfsUnavailable
		}
	]
' "$dir/container-samples.jsonl" >"$tmp/samples.json"

: >"$tmp/fixture.jsonl"
for f in "$dir"/fixture-metrics-*.json; do
	[ -f "$f" ] || continue
	idx=$(basename "$f" .json | sed -nE 's/fixture-metrics-([0-9]+)/\1/p')
	[ -n "$idx" ] || { echo "cannot derive fixture index from $(basename "$f")" >&2; exit 1; }
	jq -e '
		def int: type == "number" and isfinite and . >= 0 and floor == .;
		. as $m |
		($m | keys_unsorted | sort) == ["fail","healthy","slow-body","slow-headers"] and
		(["healthy","slow-headers","slow-body","fail"] | all(.[]; . as $r |
			($m[$r] | type) == "object" and
			($m[$r].started | int) and ($m[$r].completed | int) and ($m[$r].active | int) and
			$m[$r].completed <= $m[$r].started and
			$m[$r].active == ($m[$r].started - $m[$r].completed)))
	' "$f" >/dev/null || { echo "invalid fixture metrics: $(basename "$f")" >&2; exit 1; }
	jq -c --argjson i "$idx" '{index: $i, metrics: .}' "$f" >>"$tmp/fixture.jsonl"
done
[ -s "$tmp/fixture.jsonl" ] || { echo "no fixture metrics found in $dir" >&2; exit 1; }
jq -s '.' "$tmp/fixture.jsonl" >"$tmp/fixture.json"

jq -n \
	--slurpfile obs "$tmp/observations.json" \
	--slurpfile samp "$tmp/samples.json" \
	--slurpfile fix "$tmp/fixture.json" \
	--slurpfile stages "$tmp/stages.json" \
	'{observations: $obs[0], samples: $samp[0], fixture: $fix[0], stages: $stages[0]}' >"$tmp/input.json"

jq -f "$analyzer_jq" --arg dir "$dir" "$tmp/input.json"
