#!/bin/sh
set -eu

for tool in kustomize yq rg awk; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "required tool not found: $tool" >&2
		exit 1
	}
done

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
render=$(mktemp)
trap 'rm -f "$render"' EXIT

# Render all base manifests concatenated as separate YAML documents; without
# --- separators yq sees a single merged document and select() matches nothing.
for manifest in "$root"/deploy/ied-qualification/base/*.yaml; do
	printf '\n---\n'
	cat "$manifest"
done >"$render"

# --- HA3 checks ---
ha3='select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917")'

test "$(yq -r "$ha3 | .metadata.namespace" "$render")" = ternal-auth
test "$(yq -r "$ha3 | .spec.replicas" "$render")" = 3
test "$(yq -r "$ha3 | (.spec.volumeClaimTemplates // [] | length)" "$render")" = 0
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.volumes[] | select(.name == "data") | has("emptyDir")' "$render")" = true
test "$(yq -r "$ha3 | .spec.template.spec.serviceAccountName" "$render")" = ternal-goauthy
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_PROFILE") | .value' "$render")" = cluster
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE") | .value' "$render")" = true
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER") | .value' "$render")" = gcs
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_PEER_ADDR") | .value' "$render")" = ":8444"
test "$(yq -r "$ha3 | .spec.template.spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution | length" "$render")" = 1

# Verify peer container port
if ! yq -e 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.containers[0].ports[] | select(.name == "peer" and .containerPort == 8444 and .protocol == "UDP")' "$render" >/dev/null; then
	echo "HA3 missing peer UDP 8444 container port" >&2; exit 1
fi

# Verify readiness probe
if ! yq -e "$ha3 | .spec.template.spec.containers[0].readinessProbe.httpGet.path" "$render" | grep -q /readyz; then
	echo "HA3 missing /readyz readiness probe" >&2; exit 1
fi

# Verify labels — never part-of ternal
if yq -e 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .metadata.labels."app.kubernetes.io/part-of"' "$render" | grep -q ternal; then
	echo "HA3 label must not be part-of ternal" >&2; exit 1
fi
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .metadata.labels."app.kubernetes.io/part-of"' "$render")" = goauthy-qual-0917

# Verify secret references
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-0917") | .spec.template.spec.volumes[] | select(.name == "secrets") | .secret.secretName' "$render")" = goauthy-qual-secrets
for key in qual-0917 oauth-hmac bootstrap-client bootstrap-user-password-phc; do
	test "$(yq -e "$ha3 | .spec.template.spec.volumes[] | select(.name == \"secrets\") | .secret.items[] | select(.key == \"$key\")" "$render" >/dev/null 2>&1 && echo true || echo false)" = true
done

# Verify GCS provider env (no S3 keys)
for forbidden in GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT GOAUTHY_RHIZA_OBJECT_STORE_REGION GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY; do
	if yq -e "$ha3 | .spec.template.spec.containers[0].env[] | select(.name == \"$forbidden\")" "$render" >/dev/null 2>&1; then
		echo "HA3 must not contain S3 env $forbidden" >&2; exit 1
	fi
done

# --- Standalone1 checks ---
s1='select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917")'

test "$(yq -r "$s1 | .metadata.namespace" "$render")" = ternal-auth
test "$(yq -r "$s1 | .spec.replicas" "$render")" = 1
test "$(yq -r "$s1 | (.spec.volumeClaimTemplates // [] | length)" "$render")" = 0
test "$(yq -r "$s1 | .spec.template.spec.serviceAccountName" "$render")" = ternal-goauthy
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_PROFILE") | .value' "$render")" = standalone
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917") | .spec.template.spec.containers[0].env[] | select(.name == "GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER") | .value' "$render")" = gcs
test "$(yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917") | .metadata.labels."app.kubernetes.io/part-of"' "$render")" = goauthy-qual-s1-0917

# No peer ports on standalone1
if yq -e 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917") | .spec.template.spec.containers[0].ports[] | select(.name == "peer")' "$render" >/dev/null 2>&1; then
	echo "standalone1 must not have peer port" >&2; exit 1
fi
# No peer env on standalone1 (scoped to its document: the same names
# legitimately exist in the HA3 StatefulSet, whose env lines do not carry
# the release name for a render-wide grep -v to exclude).
if yq -r 'select(.kind == "StatefulSet" and .metadata.name == "goauthy-qual-s1-0917") | .spec.template.spec.containers[].env[].name' "$render" | grep -E 'GOAUTHY_RHIZA_(PEER_ADDR|MEMBERS|ADMIN_TOKEN)'; then
	echo "standalone1 render retains cluster-only peer setting" >&2; exit 1
fi

# --- PDB checks ---
ha3_pdb='select(.kind == "PodDisruptionBudget" and .metadata.name == "goauthy-qual-0917")'
test "$(yq -r "$ha3_pdb | .spec.minAvailable" "$render")" = 2
s1_pdb='select(.kind == "PodDisruptionBudget" and .metadata.name == "goauthy-qual-s1-0917")'
test "$(yq -r "$s1_pdb | .spec.minAvailable" "$render")" = 1

# --- NetworkPolicy checks ---
if ! yq -e 'select(.kind == "NetworkPolicy" and .metadata.name == "goauthy-qual-ha3-ingress-peer")' "$render" >/dev/null 2>&1; then
	echo "missing HA3 network policy" >&2; exit 1
fi
if ! yq -e 'select(.kind == "NetworkPolicy" and .metadata.name == "goauthy-qual-s1-ingress")' "$render" >/dev/null 2>&1; then
	echo "missing standalone1 network policy" >&2; exit 1
fi

# --- Forbidden content ---
if rg -n 'volumeClaimTemplates|kind: Job|kind: PersistentVolumeClaim|name: minio|CHANGEME|TODO' "$render"; then
	echo "qualification render contains a forbidden resource or placeholder" >&2; exit 1
fi

# Verify no cross-label contamination
ha3_count=$(yq -r 'select(.metadata.labels."app.kubernetes.io/part-of" == "goauthy-qual-0917") | .metadata.name' "$render" | wc -l | tr -d ' ')
s1_count=$(yq -r 'select(.metadata.labels."app.kubernetes.io/part-of" == "goauthy-qual-s1-0917") | .metadata.name' "$render" | wc -l | tr -d ' ')
[ "$ha3_count" -ge 4 ] || { echo "HA3 resources (expected >=4: ss, svc, pdb, np) got $ha3_count" >&2; exit 1; }
[ "$s1_count" -ge 4 ] || { echo "S1 resources (expected >=4: ss, svc, pdb, np) got $s1_count" >&2; exit 1; }

echo "ied-qualification manifest checks passed"
