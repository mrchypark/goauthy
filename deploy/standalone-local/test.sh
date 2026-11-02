#!/bin/sh
set -eu

for tool in kustomize yq; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 1; }
done
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
render=$(mktemp)
trap 'rm -f "$render"' EXIT HUP INT TERM
kustomize build "$root/deploy/standalone-local" >"$render"
workload='select(.kind == "StatefulSet" and .metadata.name == "goauthy")'
test "$(yq -r "$workload | .spec.replicas" "$render")" = 1
test "$(yq -r "$workload | (.spec.volumeClaimTemplates | length)" "$render")" = 0
test "$(yq -r "$workload | (.spec.template.spec.initContainers | length)" "$render")" = 1
test "$(yq -r "$workload | .spec.template.spec.initContainers[0].name" "$render")" = restore-local-archive
test "$(yq -r "$workload | .spec.template.spec.initContainers[0].command[0]" "$render")" = /goauthy-rhiza-init
test "$(yq -r "$workload | (.spec.template.spec.initContainers[0].args | length)" "$render")" = 0
test "$(yq -r "$workload | .spec.template.spec.initContainers[0].image" "$render")" = "$(yq -r "$workload | .spec.template.spec.containers[0].image" "$render")"
test "$(yq -r "$workload | .spec.template.spec.initContainers[0].securityContext.runAsUser" "$render")" = 65532
test "$(yq -r "$workload | .spec.template.spec.initContainers[0].securityContext.readOnlyRootFilesystem" "$render")" = true
test "$(yq -r "$workload | (.spec.template.spec.initContainers[0].volumeMounts | length)" "$render")" = 2
for volume in data sqlite-tmp; do
	init=$(yq -o=json -I=0 "$workload | .spec.template.spec.initContainers[0].volumeMounts[] | select(.name == \"$volume\")" "$render")
	main=$(yq -o=json -I=0 "$workload | .spec.template.spec.containers[0].volumeMounts[] | select(.name == \"$volume\")" "$render")
	test -n "$init" && test "$init" = "$main" || { echo "init/main mount differs: $volume" >&2; exit 1; }
done
test "$(yq -r "$workload | .spec.template.spec.volumes[] | select(.name == \"data\") | .emptyDir.sizeLimit" "$render")" = 1Gi
# Init and main must use the same identity, durable store, and local path.
for name in SQLITE_TMPDIR GOAUTHY_RHIZA_PROFILE GOAUTHY_CLUSTER_ID GOAUTHY_NODE_ID GOAUTHY_DATA_DIR GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER GOAUTHY_RHIZA_OBJECT_STORE_PREFIX GOAUTHY_RHIZA_OBJECT_STORE_BUCKET GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT GOAUTHY_RHIZA_OBJECT_STORE_REGION GOAUTHY_RHIZA_OBJECT_STORE_INSECURE GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY; do
	init=$(yq -o=json -I=0 "$workload | .spec.template.spec.initContainers[0].env[] | select(.name == \"$name\")" "$render")
	main=$(yq -o=json -I=0 "$workload | .spec.template.spec.containers[0].env[] | select(.name == \"$name\")" "$render")
	test -n "$init" && test "$init" = "$main" || { echo "init/main configuration differs: $name" >&2; exit 1; }
done
if yq -r "$workload" "$render" | grep -E 'name: peer|GOAUTHY_RHIZA_(MEMBERS|PEER_ADDR|ADMIN_TOKEN|INIT_EVIDENCE_FILE)|rhiza-operator|RHIZA_ROLE|--staging-dir|--mode=|name: rhiza-init'; then
	echo "Local singleton retains an operator, peer, or obsolete staging setting" >&2; exit 1
fi
if yq -r 'select(.kind == "CustomResourceDefinition" or .kind == "RhizaCluster") | .kind' "$render" | grep .; then
	echo "Local singleton requires an operator resource" >&2; exit 1
fi
echo "standalone-local shared-DataDir init checks passed"
