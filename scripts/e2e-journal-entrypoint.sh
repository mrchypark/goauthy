#!/bin/sh
# Test-only: stops after the kernel-completed restore-state rename and before
# its parent-directory fsync. The production image always executes /goauthy.
set -eu
umask 077

data_dir=/var/lib/goauthy
journal="$data_dir/sqlite.db.restore-state.json"
fault_dir="$data_dir/.journal-fault"
phase=${GOAUTHY_JOURNAL_PHASE:-}
tracer_pid=
tracee_pid=

case "$phase" in
prepared|sqlite-backed-up|graph-installed|sqlite-installed|committed) ;;
*) exit 1 ;;
esac

# shellcheck disable=SC2329 # invoked by the EXIT/INT/TERM trap below.
cleanup() {
	if [ -n "$tracee_pid" ] && tracee_identity && kill -0 "$tracee_pid" 2>/dev/null; then
		kill -KILL "$tracee_pid" 2>/dev/null || true
	fi
	if [ -n "$tracer_pid" ] && kill -0 "$tracer_pid" 2>/dev/null; then
		kill -KILL "$tracer_pid" 2>/dev/null || true
	fi
}
# shellcheck disable=SC2329 # invoked by the INT/TERM traps below.
on_signal() {
	cleanup
	trap - EXIT
	exit "$1"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

die() {
	# Keep diagnostics stable and never print application arguments or secrets.
	echo "journal fault fixture failed: $1" >&2
	exit 1
}

is_expected_phase() {
	[ -f "$journal" ] && jq -e --arg phase "$phase" \
		'.phase == $phase and .install_graph == true and .graph_had_original == true' \
		"$journal" >/dev/null 2>&1
}

layout_valid() {
	is_expected_phase || return 1
	db="$data_dir/sqlite.db"
	db_backup="$db.restore-backup"
	graph="$data_dir/latticedb"
	graph_backup="$graph.restore-backup"
	case "$phase" in
	prepared)
		[ -f "$db" ] && [ ! -e "$db_backup" ] && [ -d "$graph" ] && [ ! -e "$graph_backup" ]
		;;
	sqlite-backed-up)
		[ ! -e "$db" ] && [ -f "$db_backup" ] && [ -d "$graph" ] && [ ! -e "$graph_backup" ]
		;;
	graph-installed)
		[ ! -e "$db" ] && [ -f "$db_backup" ] && [ -d "$graph" ] && [ -d "$graph_backup" ]
		;;
	sqlite-installed|committed)
		[ -f "$db" ] && [ -f "$db_backup" ] && [ -d "$graph" ] && [ -d "$graph_backup" ]
		;;
	esac
}

tracee_identity() {
	[ -n "$tracee_pid" ] || return 1
	[ "$(readlink "/proc/$tracee_pid/exe" 2>/dev/null || true)" = /goauthy ] || return 1
	parent=$(awk '{print $4}' "/proc/$tracee_pid/stat" 2>/dev/null || true)
	[ "$parent" = "$tracer_pid" ]
}

trace_cut_valid() {
	awk -v pid="$tracee_pid" -v journal="$journal" -v dir="$data_dir" '
		$1 == pid && index($0, "+++ killed by SIGKILL +++") { killed = 1; exit }
		{
			if (index($0, journal) && index($0, "= 0 (DELAYED)")) {
				rename_seen = 1
				directory_fsync_after = 0
			} else if (rename_seen && index($0, "fsync(") && index($0, "<" dir ">")) {
				directory_fsync_after = 1
			}
		}
		END { exit !(killed && rename_seen && !directory_fsync_after) }
	' "$fault_dir/trace"
}

[ "$(id -u)" != 0 ] || die "must run as nonroot"
[ -d "$data_dir" ] || die "data directory unavailable"

if [ -e "$fault_dir/released" ]; then
	if [ ! -f "$fault_dir/proof.json" ] || ! jq -e --arg phase "$phase" '.phase == $phase' "$fault_dir/proof.json" >/dev/null 2>&1; then
		die "released proof phase invalid"
	fi
	if [ -e "$journal" ]; then
		is_expected_phase || die "released journal phase invalid"
	fi
	exec /goauthy "$@"
fi

mkdir -p "$fault_dir"
chmod 700 "$fault_dir"
trace="$fault_dir/trace"
tracee_file="$fault_dir/tracee.pid"
tracer_stderr="$fault_dir/strace.stderr"
rm -f "$trace" "$tracee_file" "$tracer_stderr"

# fd 3 retains the container's application stderr. The inner shell restores it
# before exec, while strace's own stderr remains private to the fixture.
exec 3>&2
# shellcheck disable=SC2016 # this is the inner tracee shell program.
strace -f --kill-on-exit -y -P "$journal" -P "$data_dir" \
	-e trace=rename,renameat,renameat2,fsync \
	-e inject=rename:delay_exit=2s \
	-e inject=renameat:delay_exit=2s \
	-e inject=renameat2:delay_exit=2s \
	-o "$trace" sh -c '
		pidfile=$1
		shift
		printf "%s\n" "$$" > "$pidfile"
		exec 2>&3
		exec 3>&-
		exec /goauthy "$@"
	' sh "$tracee_file" "$@" 2>"$tracer_stderr" &
tracer_pid=$!

deadline=$(( $(date +%s) + 90 ))
while :; do
	if [ -f "$tracee_file" ]; then
		candidate=$(tr -d '[:space:]' < "$tracee_file")
		case "$candidate" in
		*[!0-9]*|'') ;;
		*)
			if [ "$candidate" -gt 1 ] && [ "$candidate" -ne "$$" ]; then
				tracee_pid=$candidate
			fi
			;;
		esac
	fi
	if tracee_identity && layout_valid; then
		break
	fi
	[ "$(date +%s)" -lt "$deadline" ] || die "required journal state not observed"
	sleep 0.05
done

tracee_identity || die "tracee identity invalid"
layout_valid || die "journal layout invalid"
killed_pid=$tracee_pid
kill -KILL "$tracee_pid" 2>/dev/null || die "tracee kill failed"
set +e
wait "$tracer_pid"
tracer_status=$?
set -e
[ "$tracer_status" -eq 137 ] || die "tracer did not exit from tracee SIGKILL"
tracer_pid=
tracee_pid=

# The PID is retained separately because it is intentionally cleared before
# cleanup can run; trace evidence must refer to that exact killed process.
tracee_pid=$killed_pid
trace_cut_valid || die "trace does not prove delayed journal cut"
tracee_pid=
layout_valid || die "retained journal layout invalid"

proof_tmp="$fault_dir/.proof.$$"
printf '{"phase":"%s","tracee_sigkill":true,"before_directory_fsync":true,"layout_valid":true,"pid":%s}\n' \
	"$phase" "$killed_pid" > "$proof_tmp"
chmod 600 "$proof_tmp"
mv -f "$proof_tmp" "$fault_dir/proof.json"

hold_deadline=$(( $(date +%s) + 300 ))
while [ ! -e "$fault_dir/release" ]; do
	[ "$(date +%s)" -lt "$hold_deadline" ] || die "release marker not observed"
	sleep 1
done
: > "$fault_dir/released"
chmod 600 "$fault_dir/released"
exit 137
