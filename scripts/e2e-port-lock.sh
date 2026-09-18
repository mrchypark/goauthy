#!/bin/sh

# A shared lock is deliberate: custom port ranges may overlap too.
# An empty lock directory is never removed: it may be a live owner between
# mkdir and publishing its identity. E2E_PORT_LOCK_TIMEOUT_SECONDS bounds that
# crash case instead of risking deletion of a just-created lock.
e2e_port_lock_process_start() {
	ps -o lstart= -p "$1" 2>/dev/null | sed 's/^[[:space:]]*//'
}

e2e_port_lock_remove_stale() {
	# rmdir only succeeds if no owner started publishing a replacement record.
	rm -f "$e2e_port_lock_dir/pid"
	rmdir "$e2e_port_lock_dir" 2>/dev/null || true
}

e2e_port_lock_acquire() {
	e2e_port_lock_dir=${E2E_PORT_LOCK_DIR:-${TMPDIR:-/tmp}/goauthy-e2e-port.lock}
	e2e_port_lock_timeout=${E2E_PORT_LOCK_TIMEOUT_SECONDS:-120}
	case "$e2e_port_lock_timeout" in ''|*[!0-9]*) echo 'E2E_PORT_LOCK_TIMEOUT_SECONDS must be a non-negative integer' >&2; return 2;; esac
	e2e_port_lock_owned=false
	e2e_port_lock_started=$(date +%s) || return 1
	e2e_port_lock_deadline=$((e2e_port_lock_started + e2e_port_lock_timeout))

	while ! mkdir "$e2e_port_lock_dir" 2>/dev/null; do
		if [ -f "$e2e_port_lock_dir/pid" ]; then
			lock_pid=$(sed -n '1p' "$e2e_port_lock_dir/pid" 2>/dev/null || true)
			lock_start=$(sed -n '2p' "$e2e_port_lock_dir/pid" 2>/dev/null || true)
			lock_extra=$(sed -n '3p' "$e2e_port_lock_dir/pid" 2>/dev/null || true)
			case "$lock_pid" in
				''|*[!0-9]*) e2e_port_lock_remove_stale; continue ;;
				*)
					if [ -z "$lock_start" ] || [ -n "$lock_extra" ]; then
						e2e_port_lock_remove_stale
						continue
					else
						current_start=$(e2e_port_lock_process_start "$lock_pid")
						if ! kill -0 "$lock_pid" 2>/dev/null || [ -z "$current_start" ] || [ "$current_start" != "$lock_start" ]; then
							e2e_port_lock_remove_stale
							continue
						fi
					fi
					;;
			esac
		fi
		e2e_port_lock_now=$(date +%s) || return 1
		if [ "$e2e_port_lock_now" -ge "$e2e_port_lock_deadline" ]; then
			echo "timed out waiting for E2E port lock: $e2e_port_lock_dir" >&2
			return 1
		fi
		sleep 1
	done

	e2e_port_lock_start=$(e2e_port_lock_process_start "$$")
	if [ -z "$e2e_port_lock_start" ]; then
		rmdir "$e2e_port_lock_dir" 2>/dev/null || true
		echo "cannot identify E2E port lock owner: $$" >&2
		return 1
	fi
	e2e_port_lock_tmp=$e2e_port_lock_dir/.pid.$$
	if ! printf '%s\n%s\n' "$$" "$e2e_port_lock_start" >"$e2e_port_lock_tmp" || ! mv "$e2e_port_lock_tmp" "$e2e_port_lock_dir/pid"; then
		rm -f "$e2e_port_lock_tmp"
		rmdir "$e2e_port_lock_dir" 2>/dev/null || true
		echo "cannot publish E2E port lock owner: $e2e_port_lock_dir" >&2
		return 1
	fi
	e2e_port_lock_owned=true
}

e2e_port_lock_release() {
	[ "${e2e_port_lock_owned:-false}" = true ] || return 0
	[ "$(sed -n '1p' "$e2e_port_lock_dir/pid" 2>/dev/null || true)" = "$$" ] || return 0
	[ "$(sed -n '2p' "$e2e_port_lock_dir/pid" 2>/dev/null || true)" = "$(e2e_port_lock_process_start "$$")" ] || return 0
	rm -f "$e2e_port_lock_dir/pid"
	rmdir "$e2e_port_lock_dir" 2>/dev/null || true
	e2e_port_lock_owned=false
}
