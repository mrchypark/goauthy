#!/bin/sh
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$script_dir"

reject() {
	if jq "$1" results.json | jq -f qualify.jq >/dev/null 2>&1; then
		printf 'qualification accepted invalid evidence: %s\n' "$1" >&2
		exit 1
	fi
}

jq -f qualify.jq results.json | jq -e '
  .standalone_correctness == "pass"
  and .standalone_performance == "inconclusive"
  and (.runs == [1, 2, 3])
  and (.performance_breaches | length) == 1
' >/dev/null

reject 'del(.[2])'
reject '.[0].violations = ["mutation"]'
reject '.[0].final_pools[0].Leases = 1'
reject '.[0].groups |= map(if .phase == "mixed" and .route == "oauth-cancel" then .outcomes = [] else . end)'
reject '.[0].groups |= map(if .phase == "mixed" and .route == "oauth-cancel" then .outcomes = [{outcome: "success", n: 16}] else . end)'
reject '.[0].protected_comparisons |= map(. + {pass: true, p95_ms: 999999, p99_ms: 999999})'

for field in max_rss_bytes sampled_heap_peak_bytes sampled_goroutine_peak; do
	reject "del(.[0].resources.$field)"
	for value in null true '"1"' -1 1.5 1e999; do
		reject ".[0].resources.$field = $value"
	done
done

reject 'del(.[0].resources.sample_count)'
for value in null true '"1"' 0 -1 1.5 1e999; do
	reject ".[0].resources.sample_count = $value"
done

printf 'retained evidence qualification passed; invalid evidence mutations rejected\n'
