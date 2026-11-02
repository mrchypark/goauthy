#!/bin/sh
# Build before provisioning; later calls exec only this content-addressed helper.
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
source_dir=$script_dir/e2e-stage-supervisor-src
export GOENV=off GOWORK=off
host_target=$(cd "$source_dir" && go env GOHOSTOS GOHOSTARCH)
GOOS=$(printf '%s\n' "$host_target" | sed -n '1p')
GOARCH=$(printf '%s\n' "$host_target" | sed -n '2p')
case "$GOOS" in darwin|linux) ;; *) echo 'unsupported supervisor host' >&2; exit 1;; esac
case "$GOARCH" in ''|*[!a-z0-9_]*) echo 'invalid supervisor host architecture' >&2; exit 1;; esac
export GOOS GOARCH CGO_ENABLED=0 GOFLAGS=
toolchain=$(cd "$source_dir" && go version)
if command -v sha256sum >/dev/null 2>&1; then
	digest=$({ cat "$source_dir/go.mod" "$source_dir/main.go"; printf '%s\n' "$toolchain" "$GOOS/$GOARCH"; } | sha256sum | cut -d ' ' -f 1)
else
	digest=$({ cat "$source_dir/go.mod" "$source_dir/main.go"; printf '%s\n' "$toolchain" "$GOOS/$GOARCH"; } | shasum -a 256 | cut -d ' ' -f 1)
fi
cache=${HOME:?}/.cache/goauthy-stage-supervisor/$GOOS-$GOARCH-$digest
binary=$cache/supervisor
if [ "${1:-}" != --prepare ]; then
	[ -x "$binary" ] || { echo 'stage supervisor is not prepared' >&2; exit 1; }
	exec "$binary" "$@"
fi
[ "$#" -eq 1 ] || exit 2
[ ! -x "$binary" ] || exit 0
umask 077
mkdir -p "$cache"
build_dir=$(mktemp -d "$cache/build.XXXXXX")
build_pid=
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$build_pid" ]; then
		# cmd/go handles INT and waits for its compiler workers. Never TERM/KILL
		# only go: that would lose ownership of unfinished compiler children.
		kill -INT "$build_pid" 2>/dev/null || true
		attempt=0
		while [ "$attempt" -lt 75 ] && kill -0 "$build_pid" 2>/dev/null; do sleep 1; attempt=$((attempt + 1)); done
		if kill -0 "$build_pid" 2>/dev/null; then
			echo "supervisor build still active; PID=$build_pid diagnostics=$build_dir" >&2
			exit 1
		fi
		wait "$build_pid" 2>/dev/null || true
	fi
	rm -rf "$build_dir"
	exit "$status"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 1 15
cd "$source_dir"
go build -mod=readonly -p=1 -trimpath -o "$build_dir/supervisor" . &
build_pid=$!
if wait "$build_pid"; then build_status=0; else build_status=$?; fi
build_pid=
[ "$build_status" -eq 0 ] || exit "$build_status"
mv "$build_dir/supervisor" "$binary"
