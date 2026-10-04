# shellcheck shell=sh
# Strict Kind-node CRI image pin snapshots for the issue #113 SaaS isolation
# diagnostic. Sourced by scripts/e2e-kind-saas-isolation-113.sh after
# `kind load` and by scripts/test-e2e-kind-saas-isolation-provenance.sh so
# the regression exercises the exact production validation.

# node_image_pin_snapshot takes exactly 3 arguments:
#   IMAGE_REF EXPECTED_CONFIG_DIGEST SNAPSHOT_FILE
# Requires KIND_CLUSTER. Inspects the exact image ref through the Kind node
# CRI and writes {config_digest, runtime_digests} to the private snapshot
# file. The CRI status.id must be a strict sha256 digest equal to the
# expected archive config digest; repoDigests entries must be strict
# repo@sha256:64hex and are stripped to unique sha256 digests. An absent
# repoDigests field is optional (treated as empty) because the later runtime
# pin predicate still accepts the known manifest/config digests, but a
# provided non-array value is rejected. Any missing/wrong/malformed field
# fails closed with a controlled message, removes both owned files, and
# leaves no snapshot file behind.
node_image_pin_snapshot() {
	image_ref=$1
	expected_config=$2
	snapshot_file=$3
	cri_file=$snapshot_file.cri
	docker exec "${KIND_CLUSTER}-control-plane" crictl inspecti -o json "$image_ref" >"$cri_file" 2>/dev/null ||
		{ echo "Kind node CRI image inspect failed for $image_ref" >&2; rm -f "$cri_file" "$snapshot_file"; return 1; }
	jq -e --arg config "$expected_config" '
		(.status.id // "") as $id
		| select(($id | type) == "string" and ($id | test("^sha256:[0-9a-f]{64}$")))
		| select($id == $config)
		| (if ((.status // {}) | has("repoDigests")) then .status.repoDigests else [] end) as $repo_digests
		| select(($repo_digests | type) == "array")
		| select(all($repo_digests[]; (. | type) == "string" and (. | test("^[^@]+@sha256:[0-9a-f]{64}$"))))
		| {config_digest: $id, runtime_digests: ([$repo_digests[] | sub("^.*@"; "")] | unique)}
	' "$cri_file" 2>/dev/null >"$snapshot_file" ||
		{ echo "Kind node CRI image pin validation failed for $image_ref" >&2; rm -f "$cri_file" "$snapshot_file"; return 1; }
	rm -f "$cri_file"
}

# assert_candidate_pods takes exactly 2 arguments:
#   POD_LINES NODE_DIGESTS
# POD_LINES is the five-column kubectl jsonpath output (name phase ready
# imageID image). NODE_DIGESTS is a space-separated list of sha256 digests
# from the verified candidate node pin snapshot. Accepts the known manifest
# or config digest, or a node hash present in the verified snapshot. Any
# other digest, a wrong ref, an unready pod, or a duplicate/missing pod
# fails. Requires candidate_config_digest, candidate_manifest_digest, and
# GOAUTHY_IMAGE from the caller.
assert_candidate_pods() {
	printf '%s\n' "$1" | awk -v expected_config="$candidate_config_digest" -v expected_manifest="$candidate_manifest_digest" -v expected_ref="$GOAUTHY_IMAGE" -v node_digests="${2:-}" '
		BEGIN {
			node_count = split(node_digests, node_arr, " ")
			for (i = 1; i <= node_count; i++) if (node_arr[i] != "") node_set[node_arr[i]] = 1
		}
		NF > 0 { rows++ }
		NF==5 && $1 ~ /^goauthy-[012]$/ && $2=="Running" && $3=="true" && $5==expected_ref {
			id=$4
			sub(/^containerd:\/\//, "", id)
			sub(/^docker-pullable:\/\//, "", id)
			if (index(id, "@sha256:") > 0) sub(/^.*@/, "", id)
			if ((id==expected_config || id==expected_manifest || (id in node_set)) && !seen[$1]++) n++
		}
		END {exit rows == 3 && n == 3 && seen["goauthy-0"] && seen["goauthy-1"] && seen["goauthy-2"] ? 0 : 1}'
}
