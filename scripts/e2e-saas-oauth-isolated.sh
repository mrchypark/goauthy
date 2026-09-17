#!/bin/sh
set -eu
# Run only inside a disposable --network=none container. The public-unicast
# alias is local to its loopback: no host routes, DNAT, or outbound exceptions.
# Some Dory kernels expose an unconfigured, DOWN sit0 tunnel even in net=none.
[ -z "$(ip -o link show | awk -F ': ' '$2 != "lo" && $2 != "sit0@NONE" {print}')" ] && [ "$(ip -o link show up | awk -F ': ' '{print $2}')" = lo ] && [ -z "$(ip route show default)" ] && [ -z "$(ip -6 route show default)" ] || { echo 'network-none isolation is required' >&2; exit 1; }
ip addr add 8.8.8.8/32 dev lo
exec sh scripts/e2e-open-registration-standalone.sh
