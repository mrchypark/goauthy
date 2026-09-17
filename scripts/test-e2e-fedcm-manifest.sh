#!/bin/sh
set -eu

command -v kustomize >/dev/null || { echo 'missing required tool: kustomize' >&2; exit 1; }

rendered=$(mktemp)
trap 'rm -f "$rendered"' 0 1 2 15
kustomize build deploy/e2e-fedcm >"$rendered"

goauthy_statefulset=$(awk '
  function finish() {
    if (block ~ /(^|\n)kind: StatefulSet\n/ && block ~ /(^|\n)  name: goauthy\n/) print block
    block = ""
  }
  /^---$/ { finish(); next }
  { block = block $0 "\n" }
  END { finish() }
' "$rendered")

[ "$(printf '%s\n' "$goauthy_statefulset" | grep -c '^kind: StatefulSet$')" -eq 1 ] || {
	echo 'expected exactly one goauthy StatefulSet in rendered FedCM manifest' >&2
	exit 1
}

[ "$(printf '%s\n' "$goauthy_statefulset" | grep -c 'path: /readyz')" -eq 3 ] || {
	echo 'expected startup, liveness, and readiness probes to use /readyz' >&2
	exit 1
}
[ "$(printf '%s\n' "$goauthy_statefulset" | grep -c 'scheme: HTTPS')" -eq 3 ] || {
	echo 'expected all FedCM probes to use HTTPS' >&2
	exit 1
}
if printf '%s\n' "$goauthy_statefulset" | grep -q 'tcpSocket:'; then
	echo 'FedCM StatefulSet still contains a TCP probe' >&2
	exit 1
fi

echo 'FedCM rendered probe manifest regression passed'
