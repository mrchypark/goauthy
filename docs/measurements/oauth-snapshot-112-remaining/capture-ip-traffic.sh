#!/bin/sh
set -eu

usage() {
	printf 'usage: %s INTERFACE PEER_IPV4 PEER_PORT SECONDS\n' "$0" >&2
	exit 2
}

[ "$#" -eq 4 ] || usage
interface=$1
peer=$2
port=$3
seconds=$4
case "$interface" in ''|*[!A-Za-z0-9_.-]*) usage ;; esac
printf '%s\n' "$peer" | awk -F. 'NF == 4 { ok = 1; for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i + 0 > 255) ok = 0 } END { exit !ok }' || usage
case "$port" in ''|*[!0-9]*) usage ;; esac
case "$seconds" in ''|*[!0-9]*) usage ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || usage
[ "$seconds" -ge 1 ] && [ "$seconds" -le 300 ] || usage
command -v tcpdump >/dev/null 2>&1 || { printf 'tcpdump is required\n' >&2; exit 1; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/oauth112-wire.XXXXXX")
pid=
timer=
cleanup() {
	rc=$?
	trap - EXIT HUP INT TERM
	if [ -n "$timer" ]; then
		kill "$timer" 2>/dev/null || true
		wait "$timer" 2>/dev/null || true
	fi
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
pcap=$tmp/packets.pcap
log=$tmp/capture.log
tcpdump -i "$interface" -n -s 96 -w "$pcap" "ip and udp and host $peer and port $port" 2>"$log" &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
	wait "$pid" 2>/dev/null || true
	pid=
	printf 'capture did not start; check interface and capture permission\n' >&2
	exit 1
fi
sleep "$seconds" &
timer=$!
wait "$timer"
timer=
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" || {
	pid=
	printf 'packet capture failed\n' >&2
	exit 1
}
pid=

if ! tcpdump -r "$pcap" -n -q -v >"$tmp/decoded" 2>"$tmp/decode.log"; then
	printf 'capture decode failed\n' >&2
	exit 1
fi
awk '
/^IP / && match($0, /length [0-9]+/) {
  n = substr($0, RSTART + 7, RLENGTH - 7)
  packets++
  bytes += n
}
END {
  if (packets == 0) exit 1
  printf "captured_ipv4_udp_packets=%d\nudp_port_matched_ipv4_bytes=%d\n", packets, bytes
}' "$tmp/decoded" >"$tmp/summary" || {
	printf 'capture contained no decodable IPv4 UDP packets for the filter\n' >&2
	exit 1
}
awk '
/packets captured/ { captured = $1 }
/packets dropped by kernel/ { dropped = $1; seen = 1 }
END {
  if (captured == "" || !seen) exit 1
  printf "tcpdump_packets_captured=%s\ntcpdump_packets_dropped=%s\n", captured, dropped
  if (dropped != 0) exit 2
}' "$log" >"$tmp/loss" || {
	printf 'capture loss is nonzero or tcpdump did not report a loss counter\n' >&2
	cat "$tmp/loss" >&2
	exit 1
}
cat "$tmp/summary" "$tmp/loss"
