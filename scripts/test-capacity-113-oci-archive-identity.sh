#!/bin/sh
# Focused offline fixture control for scripts/capacity-113-oci-archive-identity.sh
# using real tar/sha256/jq. It never builds images, runs Docker/Kind, or
# dispatches. Every case asserts the production helper accepts a well-formed
# archive and fails closed on a wrong manifest hash, wrong config hash, wrong
# source label, malformed index, missing manifest blob, or multi-manifest index.
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15
. "$repo/scripts/capacity-113-oci-archive-identity.sh"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1" >&2; }
bad() { fail=$((fail + 1)); echo "not ok: $1" >&2; }

size_of() { wc -c <"$1" | tr -d ' '; }

# build_fixture DIR REV [MANIFEST_COUNT]
# Writes a real OCI layout tree and packs it into DIR.tar. Records the expected
# manifest/config digests in DIR.expected.
build_fixture() {
	dir=$1
	rev=$2
	count=${3:-1}
	rm -rf "$dir"
	mkdir -p "$dir/blobs/sha256"
	jq -nc --arg rev "$rev" '{architecture:"amd64",os:"linux",config:{Labels:{"org.opencontainers.image.revision":$rev}}}' >"$tmp/config-content"
	config_digest=$(oci_archive_sha256 "$tmp/config-content")
	config_hex=${config_digest#sha256:}
	jq -nc --arg cd "$config_digest" --argjson sz "$(size_of "$tmp/config-content")" \
		'{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$sz},layers:[]}' >"$tmp/manifest-content"
	manifest_digest=$(oci_archive_sha256 "$tmp/manifest-content")
	manifest_hex=${manifest_digest#sha256:}
	cp "$tmp/config-content" "$dir/blobs/sha256/$config_hex"
	cp "$tmp/manifest-content" "$dir/blobs/sha256/$manifest_hex"
	# Build the index with COUNT copies of the same platform manifest.
	idx='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":['
	i=1
	while [ "$i" -le "$count" ]; do
		[ "$i" -eq 1 ] || idx="$idx,"
		idx="$idx{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"$manifest_digest\",\"size\":$(size_of "$tmp/manifest-content"),\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}}"
		i=$((i + 1))
	done
	idx="$idx]}"
	printf '%s' "$idx" >"$dir/index.json"
	printf '{"imageLayoutVersion":"1.0.0"}' >"$dir/oci-layout"
	printf '%s\n%s\n' "$manifest_digest" "$config_digest" >"$dir.expected"
	tar -cf "$dir.tar" -C "$dir" index.json oci-layout blobs
}

# build_extra_fixture DIR REV EXTRA_MEDIATYPE
# One OCI manifest plus one non-OCI extra descriptor. The extra blob is
# intentionally absent; the helper must reject the index before reading it.
build_extra_fixture() {
	dir=$1
	rev=$2
	extra_media=$3
	rm -rf "$dir"
	mkdir -p "$dir/blobs/sha256"
	jq -nc --arg rev "$rev" '{architecture:"amd64",os:"linux",config:{Labels:{"org.opencontainers.image.revision":$rev}}}' >"$tmp/config-content"
	config_digest=$(oci_archive_sha256 "$tmp/config-content")
	config_hex=${config_digest#sha256:}
	jq -nc --arg cd "$config_digest" --argjson sz "$(size_of "$tmp/config-content")" \
		'{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$sz},layers:[]}' >"$tmp/manifest-content"
	manifest_digest=$(oci_archive_sha256 "$tmp/manifest-content")
	manifest_hex=${manifest_digest#sha256:}
	cp "$tmp/config-content" "$dir/blobs/sha256/$config_hex"
	cp "$tmp/manifest-content" "$dir/blobs/sha256/$manifest_hex"
	jq -nc --arg md "$manifest_digest" --argjson sz "$(size_of "$tmp/manifest-content")" --arg em "$extra_media" \
		'{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":$md,"size":$sz,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":$em,"digest":"sha256:000000000000000000000000000000000000000000000000000000000000009","size":1}]}' >"$dir/index.json"
	printf '{"imageLayoutVersion":"1.0.0"}' >"$dir/oci-layout"
	tar -cf "$dir.tar" -C "$dir" index.json oci-layout blobs
}

expect_ok() {
	desc=$1
	dir=$2
	rev=$3
	if out=$(oci_archive_identity "$dir.tar" "$rev" 2>"$tmp/err") && [ "$out" = "$(tr '\n' '\t' <"$dir.expected" | sed 's/\t$//')" ]; then
		ok "$desc"
	else
		bad "$desc"
		sed -n '1,2p' "$tmp/err" >&2 || true
	fi
}

expect_fail() {
	desc=$1
	dir=$2
	rev=$3
	if oci_archive_identity "$dir.tar" "$rev" >/dev/null 2>&1; then
		bad "$desc (helper accepted a bad archive)"
	else
		ok "$desc"
	fi
}

valid=$tmp/valid
build_fixture "$valid" source-aaa
expect_ok "valid archive identity" "$valid" source-aaa

wrong_manifest=$tmp/wrong-manifest
build_fixture "$wrong_manifest" source-aaa
mh=$(sed -n '1p' "$wrong_manifest.expected"); mh=${mh#sha256:}
printf 'tampered' >"$wrong_manifest/blobs/sha256/$mh"
tar -cf "$wrong_manifest.tar" -C "$wrong_manifest" index.json oci-layout blobs
expect_fail "wrong manifest blob hash" "$wrong_manifest" source-aaa

wrong_config=$tmp/wrong-config
build_fixture "$wrong_config" source-aaa
ch=$(sed -n '2p' "$wrong_config.expected"); ch=${ch#sha256:}
printf 'tampered' >"$wrong_config/blobs/sha256/$ch"
tar -cf "$wrong_config.tar" -C "$wrong_config" index.json oci-layout blobs
expect_fail "wrong config blob hash" "$wrong_config" source-aaa

expect_fail "wrong source label" "$valid" source-bbb

malformed=$tmp/malformed
mkdir -p "$malformed"
printf 'not json' >"$malformed/index.json"
tar -cf "$malformed.tar" -C "$malformed" index.json
expect_fail "malformed index" "$malformed" source-aaa

missing=$tmp/missing
build_fixture "$missing" source-aaa
rm -f "$missing/blobs/sha256/"*
tar -cf "$missing.tar" -C "$missing" index.json oci-layout blobs
expect_fail "missing manifest blob" "$missing" source-aaa

multi=$tmp/multi
build_fixture "$multi" source-aaa 2
expect_fail "multi-manifest index" "$multi" source-aaa

extra_docker=$tmp/extra-docker
build_extra_fixture "$extra_docker" source-aaa application/vnd.docker.distribution.manifest.v2+json
expect_fail "oci plus docker extra descriptor" "$extra_docker" source-aaa

extra_unknown=$tmp/extra-unknown
build_extra_fixture "$extra_unknown" source-aaa application/vnd.unknown.thing.v1+json
expect_fail "oci plus unknown extra descriptor" "$extra_unknown" source-aaa

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
