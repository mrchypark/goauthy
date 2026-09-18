#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temp=$(mktemp -d)
lock=$temp/lock
holder_fifo=$temp/holder.fifo
waiter_fifo=$temp/waiter.fifo
mkfifo "$holder_fifo" "$waiter_fifo"
cleanup() {
	trap - 0 1 2 15
	for pid in ${holder_pid:-} ${waiter_pid:-}; do [ -z "$pid" ] || kill "$pid" 2>/dev/null || true; done
	rm -rf "$temp"
}
trap cleanup 0 1 2 15

wait_for_file() {
	file=$1
	for _ in $(seq 1 100); do [ -f "$file" ] && return 0; sleep 0.01; done
	return 1
}

E2E_PORT_LOCK_DIR=$lock E2E_PORT_LOCK_TIMEOUT_SECONDS=2 \
	sh -c '. "$1/e2e-port-lock.sh"; e2e_port_lock_acquire; : >"$2/holder"; read command <"$3"; e2e_port_lock_release' sh "$script_dir" "$temp" "$holder_fifo" &
holder_pid=$!
wait_for_file "$temp/holder"
holder_pid_record=$(sed -n '1p' "$lock/pid")

# A live owner is never stolen. The wait hook blocks exactly when contention is
# observed, so this does not depend on a timing sleep.
E2E_PORT_LOCK_DIR=$lock E2E_PORT_LOCK_TIMEOUT_SECONDS=2 E2E_TEST_TEMP=$temp E2E_TEST_FIFO=$waiter_fifo \
	sh -c '. "$1/e2e-port-lock.sh"; sleep() { : >"$E2E_TEST_TEMP/waiting"; read command <"$E2E_TEST_FIFO"; }; e2e_port_lock_acquire; : >"$E2E_TEST_TEMP/waiter"; e2e_port_lock_release' sh "$script_dir" &
waiter_pid=$!
wait_for_file "$temp/waiting"
[ ! -f "$temp/waiter" ]
[ "$(sed -n '1p' "$lock/pid")" = "$holder_pid_record" ]
# A different process cannot release a lock merely by setting the shell flag.
sh -c 'set -eu; . "$1/e2e-port-lock.sh"; e2e_port_lock_dir=$2; e2e_port_lock_owned=true; e2e_port_lock_release' sh "$script_dir" "$lock"
[ "$(sed -n '1p' "$lock/pid")" = "$holder_pid_record" ]
printf '%s\n' release >"$holder_fifo"
wait "$holder_pid"
printf '%s\n' continue >"$waiter_fifo"
wait "$waiter_pid"

# A crash after mkdir but before pid publication is bounded and fail-closed.
empty_lock=$temp/empty-lock
mkdir "$empty_lock"
if E2E_PORT_LOCK_DIR=$empty_lock E2E_PORT_LOCK_TIMEOUT_SECONDS=0 \
	sh -c '. "$1/e2e-port-lock.sh"; e2e_port_lock_acquire' sh "$script_dir" 2>"$temp/empty.err"; then
	echo 'empty lock unexpectedly acquired' >&2
	exit 1
fi
[ -d "$empty_lock" ]
grep -q 'timed out waiting for E2E port lock' "$temp/empty.err"

# Invalid and dead published owners are recovered.
malformed_lock=$temp/malformed-lock
mkdir "$malformed_lock"
printf 'not-a-pid\n' >"$malformed_lock/pid"
E2E_PORT_LOCK_DIR=$malformed_lock E2E_PORT_LOCK_TIMEOUT_SECONDS=0 \
	sh -c '. "$1/e2e-port-lock.sh"; e2e_port_lock_acquire || exit; : >"$2/malformed-acquired"; e2e_port_lock_release' sh "$script_dir" "$temp"
[ -f "$temp/malformed-acquired" ]

dead_lock=$temp/dead-lock
mkdir "$dead_lock"
printf '999999\nunknown\n' >"$dead_lock/pid"
E2E_PORT_LOCK_DIR=$dead_lock E2E_PORT_LOCK_TIMEOUT_SECONDS=0 \
	sh -c '. "$1/e2e-port-lock.sh"; e2e_port_lock_acquire || exit; : >"$2/dead-acquired"; e2e_port_lock_release' sh "$script_dir" "$temp"
[ -f "$temp/dead-acquired" ]

# A live reused PID with a different recorded start time is stale too.
reused_lock=$temp/reused-lock
mkdir "$reused_lock"
printf '%s\nnot-current\n' "$$" >"$reused_lock/pid"
E2E_PORT_LOCK_DIR=$reused_lock E2E_PORT_LOCK_TIMEOUT_SECONDS=0 \
	sh -c 'set -eu; . "$1/e2e-port-lock.sh"; e2e_port_lock_acquire; : >"$2/reused-acquired"; e2e_port_lock_release' sh "$script_dir" "$temp"
[ -f "$temp/reused-acquired" ]

echo 'e2e port lock regression passed'
