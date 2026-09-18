#!/bin/sh
# Probe only a disposable container network namespace; never the host network.
set -eu
docker run --rm --network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges --entrypoint /bin/bash \
  kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5 -ec '
    ip link set lo up
    tc qdisc add dev lo clsact
    tc filter add dev lo egress protocol ip pref 1 flower ip_proto udp dst_port 8444 action drop
    printf probe >/dev/udp/127.0.0.1/8444
    blocked=$(tc -s filter show dev lo egress)
    printf "%s\n" "$blocked" | grep -q "1 pkt (dropped 1,"
    printf control >/dev/udp/127.0.0.1/9000
    control=$(tc -s filter show dev lo egress)
    [ "$blocked" = "$control" ]
    tc qdisc del dev lo clsact
    [ -z "$(tc filter show dev lo egress)" ]
    echo "native tc isolated UDP port/drop-counter probe passed"
  '
