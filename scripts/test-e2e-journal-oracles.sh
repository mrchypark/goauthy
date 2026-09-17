#!/bin/sh
# Negative checks execute the actual shell assertions, not copied predicates.
set -eu
umask 077
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' 0
awk '/^trace_cut_valid\(\)/,/^}/' "$script_dir/e2e-journal-entrypoint.sh" >"$temp/trace-function"
test -s "$temp/trace-function"
# shellcheck disable=SC1091 # the function above is extracted from the fixture
. "$temp/trace-function"
export fault_dir="$temp" tracee_pid=42 journal=/data/sqlite.db.restore-state.json data_dir=/data
rename='17 renameat(3, "tmp", 3, "/data/sqlite.db.restore-state.json") = 0 (DELAYED)'
killed=' 42 +++ killed by SIGKILL +++'
printf '%s\n' "$rename" "$killed" >"$temp/trace"
trace_cut_valid
printf '%s\n' '17 fsync(3</data>) = 0' "$rename" "$killed" >"$temp/trace"
trace_cut_valid
printf '%s\n' "$rename" '17 fsync(3</data>) <unfinished ...>' "$killed" >"$temp/trace"
if trace_cut_valid; then echo 'accepted fsync after journal rename' >&2; exit 1; fi
printf '%s\n' "$rename" '41 +++ killed by SIGKILL +++' >"$temp/trace"
if trace_cut_valid; then echo 'accepted wrong tracee PID' >&2; exit 1; fi
printf '%s\n' "$killed" >"$temp/trace"
if trace_cut_valid; then echo 'accepted absent delayed rename' >&2; exit 1; fi

awk '/journal_source_uid=\$\(cat/ { copy=1 } copy {print} copy && /did not create fresh no-PVC pods/ {exit}' \
 "$script_dir/e2e-kind-backup-restore.sh" >"$temp/uid-body"
grep -q 'journal_fresh_uid=' "$temp/uid-body"
{ printf 'check_uid() {\n'; cat "$temp/uid-body"; printf '\n}\ncheck_uid\n'; } >"$temp/uid-check"
# The actual assertion must reject a failed cat rather than comparing its empty output.
export temp_dir="$temp" ordinal=0
source_uid=$temp/journal-interruption-source-uid-0
fresh_uid=$temp/journal-interruption-uid-before-0
printf new >"$fresh_uid"
if sh "$temp/uid-check" 2>/dev/null; then echo 'accepted missing source UID' >&2; exit 1; fi
: >"$source_uid"
if sh "$temp/uid-check" 2>/dev/null; then echo 'accepted empty source UID' >&2; exit 1; fi
printf new >"$source_uid"
if sh "$temp/uid-check" 2>/dev/null; then echo 'accepted reused UID' >&2; exit 1; fi
printf old >"$source_uid"
sh "$temp/uid-check"
echo 'journal trace and fresh-Pod UID oracles passed'
