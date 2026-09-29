#!/bin/sh
set -eu

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

printf 'retained evidence qualification passed; invalid evidence mutations rejected\n'
