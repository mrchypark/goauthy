#!/bin/sh
set -eu

for tool in kustomize yq awk; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "required tool not found: $tool" >&2
		exit 1
	}
done

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
render=$(mktemp)
ha_render=$(mktemp)
trap 'rm -f "$render" "$ha_render"' EXIT

kustomize build "$root/deploy/standalone" >"$render"
kustomize build "$root/deploy/k8s" >"$ha_render"

test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.replicas' "$render")" = 1
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | (.spec.volumeClaimTemplates // [] | length)' "$render")" = 0
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.volumes[] | select(.name == "data") | .emptyDir.sizeLimit' "$render")" = 1Gi
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | (.spec.template.spec.initContainers // [] | length)' "$render")" = 1
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | (.spec.template.spec.containers[0].ports | length)' "$render")" = 1
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[0].env | map(select(.name == "GOAUTHY_RHIZA_PROFILE") | .value) | .[]' "$render")" = standalone
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[0].ports[0].name' "$render")" = http
# minio-ingress admits TCP/9000 only from pods carrying
# app.kubernetes.io/component: object-store-client, so the pod template must keep it.
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.metadata.labels."app.kubernetes.io/component"' "$render")" = object-store-client
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "PodDisruptionBudget" and .metadata.name == "goauthy") | .spec.minAvailable' "$render")" = 1
if grep -E -n 'GOAUTHY_RHIZA_(PEER_ADDR|MEMBERS|ADMIN_TOKEN)|name: peer|targetPort: peer' "$render"; then
	echo "standalone render contains forbidden peer settings" >&2
	exit 1
fi
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[0].env | map(select(.name == "GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE") | .value) | .[]' "$render")" = true
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "minio") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "Service" and .metadata.name == "minio") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "Job" and .metadata.name == "minio-init") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "NetworkPolicy" and .metadata.name == "minio-ingress") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "NetworkPolicy" and .metadata.name == "object-store-client-egress") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "NetworkPolicy" and .metadata.name == "standalone-goauthy-ingress") | .spec.egress[]?.ports[]? | select(.protocol == "TCP" and .port == 9000) | .port' "$render")" = 9000

# Standalone is a topology overlay, not a reduced feature profile.  Every
# application setting from HA must remain present except Rhiza's cluster-only
# peer and membership credentials.
ha_env=$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[0].env[].name' "$ha_render" |
	awk '$0 !~ /^GOAUTHY_RHIZA_(PEER_ADDR|MEMBERS|ADMIN_TOKEN)$/' | sort)
standalone_env=$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy") | .spec.template.spec.containers[0].env[].name' "$render" | sort)
test "$standalone_env" = "$ha_env" || {
	echo "standalone and HA application settings differ" >&2
	diff -u /dev/fd/3 /dev/fd/4 3<<EOF 4<<EOF2
$ha_env
EOF
$standalone_env
EOF2
	exit 1
}

echo "standalone manifest checks passed"
