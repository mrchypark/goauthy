# shellcheck shell=sh
# Actual OCI archive identity for the issue #113 source-build candidate.
#
# With multiple buildx exporters the shared metadata key
# `containerimage.digest` merges exporter results and does not reliably
# identify the OCI emission, so it is not trusted. This helper derives the
# identity directly from the OCI image-layout archive:
#   - index.json must declare exactly one OCI platform manifest,
#   - the referenced manifest blob must exist at the fixed blobs/sha256 path
#     and re-hash to its declared digest,
#   - the manifest must reference a config blob that exists at its fixed
#     blobs/sha256 path and re-hashes to its declared digest,
#   - the config must carry the expected org.opencontainers.image.revision.
# Any malformed, missing, mismatched, or multi-manifest archive fails closed.

oci_archive_sha256() {
	_file=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$_file" | awk '{print "sha256:" $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$_file" | awk '{print "sha256:" $1}'
	else
		openssl dgst -sha256 "$_file" | awk '{print "sha256:" $NF}'
	fi
}

oci_archive_extract() {
	_archive=$1
	_member=$2
	_out=$3
	tar -xOf "$_archive" "$_member" >"$_out" 2>/dev/null ||
		tar -xOf "$_archive" "./$_member" >"$_out" 2>/dev/null
}

# oci_archive_identity ARCHIVE EXPECTED_SOURCE
# Prints "<manifest_digest>\t<config_digest>" on success, fails closed
# otherwise. Runs in a subshell so its private temp dir and trap do not leak.
oci_archive_identity() (
	set -eu
	archive=$1
	expected_source=$2
	[ -f "$archive" ] || { echo "oci_archive_identity: archive not found: $archive" >&2; exit 1; }
	work=$(mktemp -d) || { echo 'oci_archive_identity: cannot create work dir' >&2; exit 1; }
	chmod 700 "$work"
	trap 'rm -rf "$work"' 0 1 2 15

	oci_archive_extract "$archive" index.json "$work/index.json" || true
	[ -s "$work/index.json" ] || { echo 'oci_archive_identity: index.json missing' >&2; exit 1; }
	jq -e . "$work/index.json" >/dev/null 2>&1 || { echo 'oci_archive_identity: index.json malformed' >&2; exit 1; }

	manifest_count=$(jq -r '
		select(.schemaVersion == 2)
		| (.manifests // [])
		| length
	' "$work/index.json" 2>/dev/null) || { echo 'oci_archive_identity: index.json malformed' >&2; exit 1; }
	case "$manifest_count" in ''|*[!0-9]*) echo 'oci_archive_identity: index.json malformed' >&2; exit 1 ;; esac
	[ "$manifest_count" -eq 1 ] || { echo "oci_archive_identity: expected exactly one manifest descriptor, got $manifest_count" >&2; exit 1; }

	manifest_digest=$(jq -er '
		.manifests[0]
		| select(.mediaType == "application/vnd.oci.image.manifest.v1+json")
		| .digest
		| select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
	' "$work/index.json" 2>/dev/null) || { echo 'oci_archive_identity: manifest descriptor is not a strict OCI manifest' >&2; exit 1; }
	manifest_hex=${manifest_digest#sha256:}
	oci_archive_extract "$archive" "blobs/sha256/$manifest_hex" "$work/manifest.json" || true
	[ -s "$work/manifest.json" ] || { echo 'oci_archive_identity: manifest blob missing' >&2; exit 1; }
	[ "$(oci_archive_sha256 "$work/manifest.json")" = "$manifest_digest" ] ||
		{ echo 'oci_archive_identity: manifest blob sha mismatch' >&2; exit 1; }
	jq -e '.mediaType == "application/vnd.oci.image.manifest.v1+json"' "$work/manifest.json" >/dev/null 2>&1 ||
		{ echo 'oci_archive_identity: manifest blob media type mismatch' >&2; exit 1; }

	config_digest=$(jq -er '
		.config.digest
		| select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
	' "$work/manifest.json" 2>/dev/null) || { echo 'oci_archive_identity: config digest malformed' >&2; exit 1; }
	config_hex=${config_digest#sha256:}
	oci_archive_extract "$archive" "blobs/sha256/$config_hex" "$work/config.json" || true
	[ -s "$work/config.json" ] || { echo 'oci_archive_identity: config blob missing' >&2; exit 1; }
	[ "$(oci_archive_sha256 "$work/config.json")" = "$config_digest" ] ||
		{ echo 'oci_archive_identity: config blob sha mismatch' >&2; exit 1; }

	label=$(jq -r '.config.Labels["org.opencontainers.image.revision"] // ""' "$work/config.json" 2>/dev/null || true)
	[ "$label" = "$expected_source" ] ||
		{ echo 'oci_archive_identity: revision label mismatch' >&2; exit 1; }

	printf '%s\t%s\n' "$manifest_digest" "$config_digest"
)
