#!/bin/sh
# E2E hosts need at least 12 GiB free on both the checkout and temporary
# filesystem before Go/Docker work starts. This script never cleans or mutates
# host or container state.
set -eu

min_available_kib=12582912 # 12 GiB

fail() {
	echo "e2e preflight: $*" >&2
	exit 1
}

usage() {
	fail "usage: $0 host-capacity [--available-kib KIB] | kind-inotify --cluster NAME | kind-inotify --value VALUE"
}

number() {
	case "$1" in ''|*[!0-9]*) return 1 ;; esac
	return 0
}

available_kib() {
	path=$1
	[ -d "$path" ] || fail "path does not exist: $path"
	value=$(df -Pk "$path" | awk 'NR == 2 { print $4; exit }')
	number "$value" || fail "cannot determine available KiB for $path"
	printf '%s\n' "$value"
}

require_capacity() {
	path=$1
	value=$2
	if [ "$value" -lt "$min_available_kib" ]; then
		fail "$path has ${value} KiB free; need at least ${min_available_kib} KiB (12 GiB). Free host/Docker space, then rerun the E2E target."
	fi
}

host_capacity() {
	fixture=
	if [ "${1:-}" = --available-kib ]; then
		[ "$#" -eq 2 ] || usage
		fixture=$2
		number "$fixture" || fail "--available-kib must be a non-negative integer"
	elif [ "$#" -ne 0 ]; then
		usage
	fi

	if [ -n "$fixture" ]; then
		require_capacity fixture "$fixture"
		echo "e2e preflight: host-capacity fixture passed (${fixture} KiB >= ${min_available_kib} KiB)"
		return
	fi

	command -v docker >/dev/null 2>&1 || fail "docker is required; install it and start the Docker daemon"
	docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable; start Docker and rerun the E2E target"
	tmpdir=${TMPDIR:-/tmp}
	pwd_available=$(available_kib "$PWD")
	tmp_available=$(available_kib "$tmpdir")
	require_capacity "$PWD" "$pwd_available"
	require_capacity "$tmpdir" "$tmp_available"
	echo "e2e preflight: host capacity passed (PWD=${pwd_available} KiB TMPDIR=${tmp_available} KiB; minimum ${min_available_kib} KiB)"
}

check_inotify() {
	label=$1
	value=$2
	number "$value" || fail "$label has invalid fs.inotify.max_user_instances value: $value"
	if [ "$value" -lt 256 ]; then
		fail "$label has fs.inotify.max_user_instances=${value}; need at least 256. Increase the host/Kind runtime limit, recreate the dedicated Kind cluster, then rerun the E2E target."
	fi
}

kind_inotify() {
	case "${1:-}" in
		--value)
			[ "$#" -eq 2 ] || usage
			check_inotify fixture "$2"
			echo "e2e preflight: kind-inotify fixture passed ($2 >= 256)"
			return
			;;
		--cluster)
			[ "$#" -eq 2 ] || usage
			cluster=$2
			[ -n "$cluster" ] || fail "--cluster must not be empty"
			;;
		*) usage ;;
	esac

	command -v kind >/dev/null 2>&1 || fail "kind is required to inspect the new cluster"
	command -v docker >/dev/null 2>&1 || fail "docker is required to inspect Kind nodes"
	nodes=$(kind get nodes --name "$cluster") || fail "cannot list Kind nodes for $cluster"
	[ -n "$nodes" ] || fail "Kind cluster $cluster has no nodes to inspect"
	for node in $nodes; do
		value=$(docker exec "$node" cat /proc/sys/fs/inotify/max_user_instances) || fail "cannot read fs.inotify.max_user_instances from Kind node $node"
		check_inotify "Kind node $node" "$value"
	done
	echo "e2e preflight: Kind inotify limits passed for $cluster"
}

case "${1:-}" in
	host-capacity) shift; host_capacity "$@" ;;
	kind-inotify) shift; kind_inotify "$@" ;;
	*) usage ;;
esac
