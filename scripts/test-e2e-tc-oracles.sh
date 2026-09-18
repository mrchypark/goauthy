#!/bin/sh
# Exercise the live harness predicate, replacing only tc's external output.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' 0
awk '/^assert_tc_drop_counters\(\) \{/ { copy=1 } copy { print } copy && /^}$/ { exit }' \
  "$root/scripts/e2e-network-chaos.sh" >"$temp_dir/predicate.sh"
grep -q '^assert_tc_drop_counters()' "$temp_dir/predicate.sh"
# shellcheck disable=SC1091
. "$temp_dir/predicate.sh"
tc_exec() { cat "$temp_dir/fixture"; }
fixture() {
  : >"$temp_dir/fixture"
  i=0
  while [ "$i" -lt "$1" ]; do
    printf 'action order 1: gact action drop\nSent 47 bytes %s pkt (dropped %s, overlimits 0 requeues 0)\n' "$2" "$2" >>"$temp_dir/fixture"
    i=$((i + 1))
  done
}
fixture 4 0
if (assert_tc_drop_counters) 2>/dev/null; then echo 'accepted zero traffic' >&2; exit 1; fi
fixture 3 1
if (assert_tc_drop_counters) 2>/dev/null; then echo 'accepted missing filters' >&2; exit 1; fi
fixture 4 1
assert_tc_drop_counters
awk '/^tc_exec\(\) \{/ { copy=1 } copy { print } copy && /^}$/ { exit }' \
  "$root/scripts/e2e-network-chaos.sh" >"$temp_dir/namespace-guard.sh"
grep -q '^tc_exec()' "$temp_dir/namespace-guard.sh"
# shellcheck disable=SC1091
. "$temp_dir/namespace-guard.sh"
validate_tc_sandbox() { return 1; }
docker() { touch "$temp_dir/unvalidated-exec"; }
# The caller's OR-list deliberately disables errexit, as cleanup does.
tc_exec qdisc show || true
[ ! -e "$temp_dir/unvalidated-exec" ]
printf '%s\n' 'native tc counter and namespace guard checks passed'
