#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
render=$(mktemp)
trap 'rm -f "$render"' 0 1 2 15

command -v kustomize >/dev/null || {
	echo 'missing required tool: kustomize' >&2
	exit 1
}

kustomize build "$root/deploy/k8s" >"$render"

# Return only the named YAML document.  Kustomize renders MinIO alongside
# GoAuthy, so assertions must not accidentally match another StatefulSet or
# policy.
resource_block() {
	target_kind=$1
	target_name=$2
	awk -v target_kind="$target_kind" -v target_name="$target_name" '
		function reset() {
			doc = ""
			doc_kind = ""
			doc_name = ""
			in_metadata = 0
		}
		function finish() {
			if (doc_kind == target_kind && doc_name == target_name)
				printf "%s", doc
		}
		BEGIN { reset() }
		/^---[[:space:]]*$/ { finish(); reset(); next }
		{
			doc = doc $0 ORS
			if ($0 ~ /^kind:[[:space:]]*/) {
				line = $0
				sub(/^kind:[[:space:]]*/, "", line)
				doc_kind = line
			}
			if ($0 == "metadata:") {
				in_metadata = 1
				next
			}
			if (in_metadata && $0 ~ /^  name:[[:space:]]*/) {
				line = $0
				sub(/^  name:[[:space:]]*/, "", line)
				doc_name = line
				in_metadata = 0
				next
			}
			if (in_metadata && $0 !~ /^  /)
				in_metadata = 0
		}
		END { finish() }
	' "$render"
}

count_line() {
	line=$1
	awk -v line="$line" '$0 == line { count++ } END { print count + 0 }'
}

require_line() {
	label=$1
	line=$2
	text=$3
	if ! printf '%s\n' "$text" | grep -F -x -q -- "$line"; then
		echo "missing $label: $line" >&2
		exit 1
	fi
}

require_env_value() {
	env_name=$1
	expected=$2
	text=$3
	if ! printf '%s\n' "$text" | awk -v wanted="$env_name" -v expected="$expected" '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		line == "- name: " wanted { found = 1; next }
		found && line == "value: " expected { ok = 1; exit }
		found && line ~ /^-[[:space:]]+name:/ { found = 0 }
		END { exit !ok }
	'; then
		echo "missing $env_name=$expected" >&2
		exit 1
	fi
}

require_env_field() {
	env_name=$1
	field_path=$2
	text=$3
	if ! printf '%s\n' "$text" | awk -v wanted="$env_name" -v field_path="$field_path" '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		line == "- name: " wanted { state = 1; next }
		state == 1 && line == "valueFrom:" { state = 2; next }
		state == 2 && line == "fieldRef:" { state = 3; next }
		state == 3 && line == "fieldPath: " field_path { ok = 1; exit }
		state && line ~ /^-[[:space:]]+name:/ { state = 0 }
		END { exit !ok }
	'; then
		echo "missing $env_name fieldRef=$field_path" >&2
		exit 1
	fi
}

require_data_empty_dir() {
	text=$1
	if ! printf '%s\n' "$text" | awk '
		$0 == "      - emptyDir:" { state = 1; next }
		state == 1 && $0 == "          sizeLimit: 1Gi" { state = 2; next }
		state == 2 && $0 == "        name: data" { ok = 1; exit }
		state && $0 ~ /^      - / { state = 0 }
		END { exit !ok }
	'; then
		echo 'missing bounded GoAuthy data emptyDir' >&2
		exit 1
	fi
}

require_peer_container_port() {
	text=$1
	if ! printf '%s\n' "$text" | awk '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		line == "- containerPort: 8444" { state = 1; next }
		state == 1 && line == "name: peer" { state = 2; next }
		state == 2 && line == "protocol: UDP" { ok = 1; exit }
		state && line ~ /^-[[:space:]]+(containerPort|name):/ { state = 0 }
		END { exit !ok }
	'; then
		echo 'missing GoAuthy peer UDP container port 8444' >&2
		exit 1
	fi
}

require_readiness_http_probe() {
	text=$1
	if ! printf '%s\n' "$text" | awk '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		line == "readinessProbe:" { state = 1; next }
		state == 1 && line == "httpGet:" { state = 2; next }
		state == 2 && line == "path: /readyz" { ok = 1; exit }
		state && line ~ /^(startupProbe|livenessProbe|readinessProbe):$/ { state = 0 }
		END { exit !ok }
	'; then
		echo 'missing HTTP GET /readyz GoAuthy readiness probe' >&2
		exit 1
	fi
}

require_service_peer_port() {
	text=$1
	if ! printf '%s\n' "$text" | awk '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		line == "- name: peer" { state = 1; next }
		state == 1 && line == "port: 8444" { state = 2; next }
		state == 2 && line == "protocol: UDP" { state = 3; next }
		state == 3 && line == "targetPort: peer" { ok = 1; exit }
		state && line ~ /^-[[:space:]]+name:/ { state = 0 }
		END { exit !ok }
	'; then
		echo 'missing headless GoAuthy peer UDP service port 8444' >&2
		exit 1
	fi
}

require_peer_policy_rules() {
	text=$1
	if ! printf '%s\n' "$text" | awk '
		{
			line = $0
			sub(/^[[:space:]]*/, "", line)
		}
		$0 ~ /^  [[:alpha:]][[:alnum:]_-]*:/ {
			if (line == "ingress:") section = "ingress"
			else if (line == "egress:") section = "egress"
			else section = ""
		}
		section == "ingress" && line ~ /^- port:/ { ingress_port = (line == "- port: 8444"); next }
		section == "ingress" && ingress_port && line == "protocol: UDP" { ingress = 1; ingress_port = 0; next }
		section == "egress" && line ~ /^- port:/ { egress_port = (line == "- port: 8444"); next }
		section == "egress" && egress_port && line == "protocol: UDP" { egress = 1; egress_port = 0; next }
		END { exit !(ingress && egress) }
	'; then
		echo 'missing GoAuthy peer UDP 8444 ingress and/or egress rule' >&2
		exit 1
	fi
}

goauthy_statefulset=$(resource_block StatefulSet goauthy)
[ "$(printf '%s\n' "$goauthy_statefulset" | count_line 'kind: StatefulSet')" -eq 1 ] || {
	echo 'expected exactly one goauthy StatefulSet in rendered HA manifest' >&2
	exit 1
}
require_line 'HA replicas' '  replicas: 3' "$goauthy_statefulset"
[ "$(printf '%s\n' "$goauthy_statefulset" | count_line '  volumeClaimTemplates:')" -eq 0 ] || {
	echo 'GoAuthy data must not use a PVC template' >&2
	exit 1
}
require_data_empty_dir "$goauthy_statefulset"
require_env_value GOAUTHY_RHIZA_PROFILE cluster "$goauthy_statefulset"
require_env_value GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE '"true"' "$goauthy_statefulset"
require_env_field GOAUTHY_NODE_ID metadata.name "$goauthy_statefulset"
require_peer_container_port "$goauthy_statefulset"

# One StatefulSet template is instantiated three times; its single readiness
# probe therefore supplies the /readyz probe for each of the three replicas.
[ "$(printf '%s\n' "$goauthy_statefulset" | count_line '        readinessProbe:')" -eq 1 ] || {
	echo 'expected one GoAuthy readinessProbe template' >&2
	exit 1
}
require_readiness_http_probe "$goauthy_statefulset"

goauthy_service=$(resource_block Service goauthy)
[ "$(printf '%s\n' "$goauthy_service" | count_line 'kind: Service')" -eq 1 ] || {
	echo 'expected exactly one headless goauthy Service' >&2
	exit 1
}
require_line 'headless service' '  clusterIP: None' "$goauthy_service"
require_service_peer_port "$goauthy_service"

goauthy_pdb=$(resource_block PodDisruptionBudget goauthy)
[ "$(printf '%s\n' "$goauthy_pdb" | count_line 'kind: PodDisruptionBudget')" -eq 1 ] || {
	echo 'expected exactly one goauthy PodDisruptionBudget' >&2
	exit 1
}
require_line 'HA PDB minAvailable' '  minAvailable: 2' "$goauthy_pdb"

goauthy_policy=$(resource_block NetworkPolicy goauthy-ingress)
[ "$(printf '%s\n' "$goauthy_policy" | count_line 'kind: NetworkPolicy')" -eq 1 ] || {
	echo 'expected exactly one goauthy-ingress NetworkPolicy' >&2
	exit 1
}
require_peer_policy_rules "$goauthy_policy"

# Profiles insert ConfigMap/Secret volumes in different orders. The patch must
# preserve existing key projections and guard the exact live volume snapshot.
for index in 0 1 3; do
	fixture=$(jq -nc --argjson index "$index" '{spec:{template:{spec:{volumes:([range($index) | {name:("config-" + tostring),configMap:{name:"templates"}}] + [{name:"secrets",secret:{secretName:"goauthy-secrets",items:[{key:"dev-1",path:"dev-1"}]}}])}}}}')
	patch=$(printf '%s\n' "$fixture" | jq -ce -f "$root/deploy/k8s/passkey-secret-items-patch.jq")
	printf '%s\n' "$patch" | jq -e --arg index "$index" 'length == 2 and .[0].op == "test" and .[0].path == ("/spec/template/spec/volumes/" + $index) and .[0].value.name == "secrets" and .[1].path == (.[0].path + "/secret/items") and .[1].value == [{key:"dev-1",path:"dev-1"},{key:"passkey-key",path:"passkey-key"}]' >/dev/null
done
for invalid in '[]' '[{name:"secrets"}]' '[{name:"secrets"},{name:"secrets"}]'; do
	if jq -nc "{spec:{template:{spec:{volumes:$invalid}}}}" | jq -e -f "$root/deploy/k8s/passkey-secret-items-patch.jq" >/dev/null 2>&1; then
		echo 'invalid secrets projection accepted' >&2; exit 1
	fi
done

echo 'HA rendered manifest regression passed'
