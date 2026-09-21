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
standalone_render=$(mktemp)
gcs_standalone_render=$(mktemp)
gcs_ha_render=$(mktemp)
trap 'rm -f "$render" "$standalone_render" "$gcs_standalone_render" "$gcs_ha_render"' EXIT
kustomize build "$root/deploy/ternal-no-pvc" >"$render"
kustomize build "$root/deploy/ternal-no-pvc/standalone" >"$standalone_render"
kustomize build "$root/deploy/ternal-no-pvc/gcs-standalone" >"$gcs_standalone_render"
kustomize build "$root/deploy/ternal-no-pvc/gcs-ha" >"$gcs_ha_render"

statefulset='select(.kind == "StatefulSet" and .metadata.name == "ternal-goauthy")'
test "$(yq -r "$statefulset | .metadata.namespace" "$render")" = ternal-auth
test "$(yq -r "$statefulset | .spec.replicas" "$render")" = 3
test "$(yq -r "$statefulset | (.spec.volumeClaimTemplates | length)" "$render")" = 0
test "$(yq -r "$statefulset | .spec.template.spec.volumes[] | select(.name == \"data\") | has(\"emptyDir\")" "$render")" = true
test "$(yq -r "$statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_PROFILE\") | .value" "$render")" = cluster
test "$(yq -r "$statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE\") | .value" "$render")" = true
test "$(yq -r "$statefulset | .spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem" "$render")" = true
test "$(yq -r "$statefulset | .spec.template.spec.automountServiceAccountToken" "$render")" = false
test "$(yq -r 'select(.kind == "PodDisruptionBudget" and .metadata.name == "ternal-goauthy") | .spec.minAvailable' "$render")" = 2

for key in issuer s3-endpoint s3-bucket s3-prefix s3-region bootstrap-client-id bootstrap-redirect-uri bootstrap-username; do
	test "$(yq -r "$statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.configMapKeyRef.key == \"$key\") | .valueFrom.configMapKeyRef.name" "$render")" = ternal-goauthy-config
done
for key in rhiza-members rhiza-admin-token s3-access-key s3-secret-key; do
	test "$(yq -r "$statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.secretKeyRef.key == \"$key\") | .valueFrom.secretKeyRef.name" "$render")" = ternal-goauthy-secrets
done
for key in master-key-ternal-1 oauth-hmac bootstrap-client bootstrap-user-password-phc; do
	test "$(yq -r "$statefulset | .spec.template.spec.volumes[] | select(.name == \"secrets\") | .secret.items[] | select(.key == \"$key\") | .key" "$render")" = "$key"
done

if grep -E -n 'volumeClaimTemplates|kind: (Job|PersistentVolumeClaim)|name: minio|image: .*:latest|<[^>]+>|CHANGEME|TODO' "$render"; then
	echo "Ternal no-PVC render contains a forbidden resource or placeholder" >&2
	exit 1
fi

test "$(yq -r 'select(.kind == "StatefulSet") | .metadata.name' "$render" | awk 'END { print NR }')" = 1
test "$(yq -r 'select(.kind == "StatefulSet") | .metadata.namespace' "$render")" = ternal-auth

standalone_statefulset='select(.kind == "StatefulSet" and .metadata.name == "ternal-goauthy")'
test "$(yq -r "$standalone_statefulset | .spec.replicas" "$standalone_render")" = 1
test "$(yq -r "$standalone_statefulset | (.spec.volumeClaimTemplates | length)" "$standalone_render")" = 0
test "$(yq -r "$standalone_statefulset | .spec.template.spec.volumes[] | select(.name == \"data\") | has(\"emptyDir\")" "$standalone_render")" = true
test "$(yq -r "$standalone_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_PROFILE\") | .value" "$standalone_render")" = standalone
test "$(yq -r "$standalone_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE\") | .value" "$standalone_render")" = true
test "$(yq -r 'select(.kind == "PodDisruptionBudget" and .metadata.name == "ternal-goauthy") | .spec.minAvailable' "$standalone_render")" = 1
for key in s3-endpoint s3-bucket s3-prefix s3-region; do
	test "$(yq -r "$standalone_statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.configMapKeyRef.key == \"$key\") | .valueFrom.configMapKeyRef.name" "$standalone_render")" = ternal-goauthy-config
done
for key in s3-access-key s3-secret-key; do
	test "$(yq -r "$standalone_statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.secretKeyRef.key == \"$key\") | .valueFrom.secretKeyRef.name" "$standalone_render")" = ternal-goauthy-secrets
done
if grep -E -n 'GOAUTHY_RHIZA_(PEER|MEMBERS|ADMIN)|name: peer|targetPort: peer|containerPort: 8444|port: 8444' "$standalone_render"; then
	echo "Ternal standalone render retains a cluster-only peer setting" >&2
	exit 1
fi
if grep -E -n 'volumeClaimTemplates|kind: (Job|PersistentVolumeClaim)|name: minio|image: .*:latest|<[^>]+>|CHANGEME|TODO' "$standalone_render"; then
	echo "Ternal standalone render contains a forbidden resource or placeholder" >&2
	exit 1
fi

gcs_statefulset='select(.kind == "StatefulSet" and .metadata.name == "ternal-goauthy")'
test "$(yq -r "$gcs_statefulset | .spec.replicas" "$gcs_standalone_render")" = 1
test "$(yq -r "$gcs_statefulset | (.spec.volumeClaimTemplates | length)" "$gcs_standalone_render")" = 0
test "$(yq -r "$gcs_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_PROFILE\") | .value" "$gcs_standalone_render")" = standalone
test "$(yq -r "$gcs_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE\") | .value" "$gcs_standalone_render")" = true
test "$(yq -r "$gcs_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER\") | .value" "$gcs_standalone_render")" = gcs
for key in object-store-bucket object-store-prefix; do
	test "$(yq -r "$gcs_statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.configMapKeyRef.key == \"$key\") | .valueFrom.configMapKeyRef.name" "$gcs_standalone_render")" = ternal-goauthy-config
done
if yq -e "$gcs_statefulset | .spec.template.spec.containers[0].env[] | select(.name | test(\"GOAUTHY_RHIZA_OBJECT_STORE_(ENDPOINT|REGION|ACCESS_KEY|SECRET_KEY)\"))" "$gcs_standalone_render" >/dev/null 2>&1; then
	echo "Ternal GCS standalone render retains S3 configuration" >&2
	exit 1
fi
if grep -E -n 'volumeClaimTemplates|kind: (Job|PersistentVolumeClaim)|name: minio|s3-access-key|s3-secret-key|service-account\.json|GOOGLE_APPLICATION_CREDENTIALS' "$gcs_standalone_render"; then
	echo "Ternal GCS standalone render contains a forbidden storage fallback" >&2
	exit 1
fi

gcs_ha_statefulset='select(.kind == "StatefulSet" and .metadata.name == "ternal-goauthy")'
test "$(yq -r "$gcs_ha_statefulset | .spec.replicas" "$gcs_ha_render")" = 3
test "$(yq -r "$gcs_ha_statefulset | (.spec.volumeClaimTemplates | length)" "$gcs_ha_render")" = 0
test "$(yq -r "$gcs_ha_statefulset | .spec.template.spec.volumes[] | select(.name == \"data\") | has(\"emptyDir\")" "$gcs_ha_render")" = true
test "$(yq -r "$gcs_ha_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_PROFILE\") | .value" "$gcs_ha_render")" = cluster
test "$(yq -r "$gcs_ha_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE\") | .value" "$gcs_ha_render")" = true
test "$(yq -r "$gcs_ha_statefulset | .spec.template.spec.containers[0].env[] | select(.name == \"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER\") | .value" "$gcs_ha_render")" = gcs
for key in object-store-bucket object-store-prefix; do
	test "$(yq -r "$gcs_ha_statefulset | .spec.template.spec.containers[0].env[] | select(.valueFrom.configMapKeyRef.key == \"$key\") | .valueFrom.configMapKeyRef.name" "$gcs_ha_render")" = ternal-goauthy-config
done
if yq -e "$gcs_ha_statefulset | .spec.template.spec.containers[0].env[] | select(.name | test(\"GOAUTHY_RHIZA_OBJECT_STORE_(ENDPOINT|REGION|ACCESS_KEY|SECRET_KEY)\"))" "$gcs_ha_render" >/dev/null 2>&1; then
	echo "Ternal GCS HA render retains S3 configuration" >&2
	exit 1
fi
if grep -E -n 'volumeClaimTemplates|kind: (Job|PersistentVolumeClaim)|name: minio|s3-access-key|s3-secret-key|service-account\.json|GOOGLE_APPLICATION_CREDENTIALS' "$gcs_ha_render"; then
	echo "Ternal GCS HA render contains a forbidden storage fallback" >&2
	exit 1
fi
if grep -E -n 'GOAUTHY_RHIZA_(PEER|MEMBERS|ADMIN)|name: peer|targetPort: peer|containerPort: 8444|port: 8444' "$gcs_ha_render" >/dev/null; then
	: # peer retained expected in HA
else
	echo "Ternal GCS HA render lost peer configuration" >&2
	exit 1
fi
test "$(yq -r 'select(.kind == "PodDisruptionBudget" and .metadata.name == "ternal-goauthy") | .spec.minAvailable' "$gcs_ha_render")" = 2
echo "ternal no-PVC manifest checks passed"
