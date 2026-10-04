#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir -p "$tmp/bin" "$tmp/evidence"
mkdir -p "$tmp/archives/app/blobs/sha256" "$tmp/archives/fixture/blobs/sha256" "$tmp/archives/driver/blobs/sha256" "$tmp/archives/bad-fixture/blobs/sha256"
write_archive() {
	name=$1
	config=$2
	printf '[{"Config":"blobs/sha256/%s"}]\n' "$config" >"$tmp/archives/$name/manifest.json"
	tar -cf "$tmp/archives/$name.tar" -C "$tmp/archives/$name" manifest.json
}
write_archive app "$(printf '%064d' 3)"
write_archive fixture "$(printf '%064d' 1)"
write_archive driver "$(printf '%064d' 2)"
write_archive bad-fixture "$(printf '%064d' 9)"
cat >"$tmp/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
case "$1 $2" in
  'image inspect')
    if [ "${3-}" = --format ]; then
      case "$5" in
        goauthy-saas-isolation-fixture:e2e)
          if [ "${MOCK_BAD_LOADED-}" = fixture ]; then printf '%s\n' "sha256:$(printf '%064d' 9)"; else printf '%s\n' "sha256:$(printf '%064d' 4)"; fi
          ;;
        goauthy-saas-isolation-driver:e2e) printf '%s\n' "sha256:$(printf '%064d' 2)" ;;
        *) printf '%s\n' "sha256:$(printf '%064d' 3)" ;;
      esac
    fi
    exit 0
    ;;
  'image save')
    case "$3" in
      goauthy@sha256:*) cat "$MOCK_APP_ARCHIVE" ;;
      goauthy-saas-isolation-fixture:e2e)
        if [ "${MOCK_BAD_ARCHIVE-}" = fixture ]; then cat "$MOCK_BAD_FIXTURE_ARCHIVE"; else cat "$MOCK_FIXTURE_ARCHIVE"; fi
        ;;
      goauthy-saas-isolation-driver:e2e) cat "$MOCK_DRIVER_ARCHIVE" ;;
      *) exit 89 ;;
    esac
    ;;
  'buildx build')
    target=
    metadata=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --target) target=$2; shift 2 ;;
        --metadata-file) metadata=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s\n' "$target" >>"$MOCK_DOCKER_BUILDS"
    case "$target" in
      fixture) config=$(printf '%064d' 1); manifest=$(printf '%064d' 4) ;;
      driver) config=$(printf '%064d' 2); manifest=$(printf '%064d' 5) ;;
      *) exit 90 ;;
    esac
    config_field=
    if [ "${MOCK_BAD_CONFIG-}" = "$target" ]; then
      config_field=$(printf ',"containerimage.config.digest":"sha256:%s"' "$(printf '%064d' 9)")
    elif [ "${MOCK_CONFIG_PRESENT-}" = "$target" ]; then
      config_field=$(printf ',"containerimage.config.digest":"sha256:%s"' "$config")
    fi
    printf '{"buildx.build.provenance":{"buildType":"https://mobyproject.org/buildkit@v1","materials":[]},"buildx.build.ref":"ied-amd64/test","containerimage.descriptor":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","platform":{"architecture":"arm64","os":"linux"}},"containerimage.digest":"sha256:%s","image.name":"docker.io/library/goauthy-saas-isolation-%s:e2e"%s}\n' "$manifest" "$manifest" "$target" "$config_field" >"$metadata"
    ;;
  'create '*) exit 42 ;;
  'rm '*) exit 0 ;;
  'exec '*)
    case " $* " in
      *" crictl inspecti -o json "*)
        if [ "${MOCK_CRI_NO_ID:-}" = 1 ]; then
          printf '{"status":{"repoDigests":%s}}\n' "${MOCK_CRI_REPO_DIGESTS:-[]}"
        else
          printf '{"status":{"id":"%s","repoDigests":%s}}\n' "${MOCK_CRI_STATUS_ID:-}" "${MOCK_CRI_REPO_DIGESTS:-[]}"
        fi
        if [ "${MOCK_CRI_INSPECT_FAIL:-}" = 1 ]; then exit 95; fi
        ;;
      *) echo 'unexpected docker exec in provenance regression' >&2; exit 94 ;;
    esac
    ;;
  *) exit 91 ;;
esac
MOCK
cat >"$tmp/bin/kind" <<'MOCK'
#!/bin/sh
printf '%s\n' test-cluster
MOCK
cat >"$tmp/bin/git" <<'MOCK'
#!/bin/sh
case "$1" in
  rev-parse) printf '%s\n' "$(printf '%040d' 7)" ;;
  status) exit 0 ;;
  *) exit 92 ;;
esac
MOCK
cat >"$tmp/bin/nc" <<'MOCK'
#!/bin/sh
exit 1
MOCK
cat >"$tmp/bin/kubectl" <<'MOCK'
#!/bin/sh
case " $* " in
  *" get statefulset goauthy -o json "*)
    printf '{"metadata":{"name":"goauthy"},"spec":{"replicas":0,"template":{"spec":{"containers":[{"name":"goauthy","image":"%s"}]}}}}\n' "$GOAUTHY_IMAGE"
    ;;
  *) echo 'unexpected kubectl invocation in provenance regression' >&2; exit 93 ;;
esac
MOCK
chmod +x "$tmp/bin/"*

export MOCK_DOCKER_BUILDS="$tmp/builds"
export MOCK_APP_ARCHIVE="$tmp/archives/app.tar"
export MOCK_FIXTURE_ARCHIVE="$tmp/archives/fixture.tar"
export MOCK_DRIVER_ARCHIVE="$tmp/archives/driver.tar"
export MOCK_BAD_FIXTURE_ARCHIVE="$tmp/archives/bad-fixture.tar"
export PATH="$tmp/bin:$PATH"
run_runner() {
	run_name=$1
	shift
	if env "$@" \
		KIND_CLUSTER=test-cluster \
		GOAUTHY_IMAGE="goauthy@sha256:$(printf '%064d' 6)" \
		GOAUTHY_CANDIDATE_SOURCE="$(printf '%040d' 7)" \
		GOAUTHY_E2E_BROWSER_PASSWORD=synthetic \
		GOAUTHY_E2E_CLIENT_SECRET=synthetic \
		ISOLATION113_EVIDENCE_DIR="$tmp/evidence/$run_name" \
		"$repo/scripts/e2e-kind-saas-isolation-113.sh" >"$tmp/$run_name.log" 2>&1; then
		run_status=0
	else
		run_status=$?
	fi
	return "$run_status"
}
set +e
run_runner run MOCK_CONFIG_PRESENT=driver
status=$?
set -e
[ "$status" -eq 42 ] || { cat "$tmp/run.log" >&2; echo "expected deliberate stop at image create, got $status" >&2; exit 1; }
[ "$(cat "$tmp/builds")" = "$(printf 'fixture\ndriver')" ] || { echo 'helper images were not both rebuilt despite existing local tags' >&2; exit 1; }
jq -e '.fixture.config_digest == "sha256:0000000000000000000000000000000000000000000000000000000000000001" and .driver.config_digest == "sha256:0000000000000000000000000000000000000000000000000000000000000002"' "$tmp/evidence/run/helper-image-pins.json" >/dev/null
jq -e '.fixture.loaded_image_id == .fixture.manifest_digest and .driver.loaded_image_id == .driver.config_digest' "$tmp/evidence/run/helper-image-pins.json" >/dev/null

cat >"$tmp/pods.json" <<'PODS'
{"items":[
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"goauthy-0"},"spec":{"containers":[{"name":"sidecarfixture","image":"goauthy-saas-isolation-fixture:e2e"}]},"status":{"containerStatuses":[{"name":"sidecarfixture","imageID":"containerd://sha256:0000000000000000000000000000000000000000000000000000000000000004"}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"goauthy-1"},"spec":{"containers":[{"name":"sidecarfixture","image":"goauthy-saas-isolation-fixture:e2e"}]},"status":{"containerStatuses":[{"name":"sidecarfixture","imageID":"docker-pullable://goauthy-saas-isolation-fixture@sha256:0000000000000000000000000000000000000000000000000000000000000001"}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"goauthy-2"},"spec":{"containers":[{"name":"sidecarfixture","image":"goauthy-saas-isolation-fixture:e2e"}]},"status":{"containerStatuses":[{"name":"sidecarfixture","imageID":"sha256:0000000000000000000000000000000000000000000000000000000000000004"}]}}
]}
PODS
pin_args='--arg container sidecarfixture --arg ref goauthy-saas-isolation-fixture:e2e --arg manifest sha256:0000000000000000000000000000000000000000000000000000000000000004 --arg config sha256:0000000000000000000000000000000000000000000000000000000000000001 --argjson count 3'
snapshot_valid=$(jq -nc --arg config "sha256:$(printf '%064d' 1)" --arg d8 "sha256:$(printf '%064d' 8)" '{config_digest:$config, runtime_digests:[$d8]}')
jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/pods.json" >/dev/null
jq --arg id "sha256:$(printf '%064d' 9)" '.items[0].status.containerStatuses[0].imageID=$id' "$tmp/pods.json" >"$tmp/wrong-id.json"
if jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-id.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a wrong image ID' >&2; exit 1; fi
jq '.items[0].spec.containers[0].image="wrong:e2e"' "$tmp/pods.json" >"$tmp/wrong-spec.json"
if jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-spec.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a wrong pod image reference' >&2; exit 1; fi
jq 'del(.items[2])' "$tmp/pods.json" >"$tmp/wrong-count.json"
if jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-count.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted the wrong pod count' >&2; exit 1; fi
set +e
diag=$(jq $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-id.json" 2>&1 >/dev/null)
diag_status=$?
set -e
[ "$diag_status" -ne 0 ] || { echo 'mismatch diagnostics did not fail' >&2; exit 1; }
printf '%s\n' "$diag" | grep -F 'observed_count=3' >/dev/null || { echo 'mismatch diagnostics omit the observed count' >&2; exit 1; }
printf '%s\n' "$diag" | grep -F 'ref_matches=[true,true,true]' >/dev/null || { echo 'mismatch diagnostics omit the ref_matches booleans' >&2; exit 1; }
printf '%s\n' "$diag" | grep -F 'sha256:0000000000000000000000000000000000000000000000000000000000000009' >/dev/null || { echo 'mismatch diagnostics omit the observed wrong digest' >&2; exit 1; }
printf '%s\n' "$diag" | grep -F 'sha256:0000000000000000000000000000000000000000000000000000000000000004' >/dev/null || { echo 'mismatch diagnostics omit a valid observed digest' >&2; exit 1; }
private_string='goauthy-isolation113-private-canary-string'
jq --arg ps "$private_string" '.items[0].spec.containers[0].image=("registry.example.test/"+$ps+":e2e") | .items[0].status.containerStatuses[0].imageID=("containerd://"+$ps)' "$tmp/pods.json" >"$tmp/canary.json"
set +e
canary_err=$(jq $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/canary.json" 2>&1 >/dev/null)
canary_status=$?
set -e
[ "$canary_status" -ne 0 ] || { echo 'canary mismatch was not rejected' >&2; exit 1; }
printf '%s\n' "$canary_err" | grep -F "$private_string" >/dev/null && { echo 'mismatch diagnostics leaked a raw private string' >&2; exit 1; }
printf '%s\n' "$canary_err" | grep -F 'sha256:0000000000000000000000000000000000000000000000000000000000000004' >/dev/null || { echo 'mismatch diagnostics omit a valid observed digest' >&2; exit 1; }

. "$repo/scripts/e2e-kind-saas-isolation-113-node-pins.sh"
export KIND_CLUSTER=test-cluster
fixture_config=sha256:$(printf '%064d' 1)
d8=sha256:$(printf '%064d' 8)
MOCK_CRI_STATUS_ID=$fixture_config \
  MOCK_CRI_REPO_DIGESTS="[\"registry.example.test/goauthy-saas-isolation-fixture@$d8\",\"goauthy-saas-isolation-fixture@$d8\"]" \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-ok.json"
jq -e --arg config "$fixture_config" --arg d8 "$d8" '
  .config_digest == $config and (.runtime_digests | length) == 1 and .runtime_digests[0] == $d8
' "$tmp/snapshot-ok.json" >/dev/null
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='[]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-empty.json"
jq -e --arg config "$fixture_config" '.config_digest == $config and .runtime_digests == []' "$tmp/snapshot-empty.json" >/dev/null
set +e
MOCK_CRI_STATUS_ID="sha256:$(printf '%064d' 9)" MOCK_CRI_REPO_DIGESTS='[]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-wrong-config.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'wrong CRI config identity was not rejected' >&2; exit 1; }
[ ! -e "$tmp/snapshot-wrong-config.json" ] || { echo 'rejected CRI config left a snapshot file behind' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID='' MOCK_CRI_REPO_DIGESTS='[]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-missing-config.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'empty CRI config identity was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_NO_ID=1 MOCK_CRI_REPO_DIGESTS='[]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-no-id.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'missing CRI status.id was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='["goauthy-saas-isolation-fixture:e2e"]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-malformed-repo.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'malformed repoDigests entry was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='"not-an-array"' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-repo-not-array.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'non-array repoDigests was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='["repo@sha256:abc"]' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-short-digest.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'short repoDigest digest was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='false' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-repo-false.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'explicit false repoDigests was not rejected' >&2; exit 1; }
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='null' \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-repo-null.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'explicit null repoDigests was not rejected' >&2; exit 1; }
jq -nc --arg config "$fixture_config" '{config_digest:$config, runtime_digests:[]}' >"$tmp/snapshot-preexisting.json"
set +e
MOCK_CRI_STATUS_ID=$fixture_config MOCK_CRI_REPO_DIGESTS='[]' MOCK_CRI_INSPECT_FAIL=1 \
  node_image_pin_snapshot goauthy-saas-isolation-fixture:e2e "$fixture_config" "$tmp/snapshot-preexisting.json" 2>/dev/null
status=$?
set -e
[ "$status" -ne 0 ] || { echo 'failed CRI inspect was not rejected' >&2; exit 1; }
[ ! -e "$tmp/snapshot-preexisting.json" ] || { echo 'failed CRI inspect left the prior snapshot file behind' >&2; exit 1; }
jq --arg id "$d8" '.items[0].status.containerStatuses[0].imageID=("containerd://"+$id)' "$tmp/pods.json" >"$tmp/d8-pod.json"
jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/d8-pod.json" >/dev/null
jq --arg id "sha256:$(printf '%064d' 9)" '.items[0].status.containerStatuses[0].imageID=("containerd://"+$id)' "$tmp/pods.json" >"$tmp/d9-pod.json"
if jq -e $pin_args --argjson node_pins "$snapshot_valid" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/d9-pod.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a wrong pod digest outside the snapshot' >&2; exit 1; fi
jq -nc --arg d8 "$d8" '{runtime_digests:[$d8]}' >"$tmp/snapshot-missing-config.json"
if jq -e $pin_args --argjson node_pins "$(cat "$tmp/snapshot-missing-config.json")" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/pods.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a snapshot without config_digest' >&2; exit 1; fi
jq -nc --arg config "sha256:$(printf '%064d' 9)" --arg d8 "$d8" '{config_digest:$config, runtime_digests:[$d8]}' >"$tmp/snapshot-wrong-config.json"
if jq -e $pin_args --argjson node_pins "$(cat "$tmp/snapshot-wrong-config.json")" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/pods.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a snapshot with the wrong config_digest' >&2; exit 1; fi
jq -nc --arg config "$fixture_config" '{config_digest:$config, runtime_digests:"not-an-array"}' >"$tmp/snapshot-malformed.json"
if jq -e $pin_args --argjson node_pins "$(cat "$tmp/snapshot-malformed.json")" -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/pods.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a malformed snapshot' >&2; exit 1; fi
candidate_config_digest=sha256:$(printf '%064d' 3)
candidate_manifest_digest=sha256:$(printf '%064d' 6)
GOAUTHY_IMAGE=goauthy@sha256:$(printf '%064d' 6)
candidate_node_digests="sha256:$(printf '%064d' 8)"
c3=$candidate_config_digest
c6=$candidate_manifest_digest
c8=$candidate_node_digests
c9=sha256:$(printf '%064d' 9)

# Source-build OCI manifest binding: the manifest digest must be present in
# the node snapshot runtime_digests. A config-only snapshot is rejected and
# the config digest is never substituted for the manifest digest.
jq -nc --arg m "$c6" --arg c "$c3" '{config_digest:$c, runtime_digests:[$c,$m]}' >"$tmp/bind-ok.json"
assert_candidate_manifest_binding "$tmp/bind-ok.json" "$c6" || { echo 'manifest binding rejected a present OCI manifest digest' >&2; exit 1; }
jq -nc --arg c "$c3" '{config_digest:$c, runtime_digests:[$c]}' >"$tmp/bind-config-only.json"
if assert_candidate_manifest_binding "$tmp/bind-config-only.json" "$c6" >/dev/null 2>&1; then echo 'manifest binding accepted a config-only snapshot' >&2; exit 1; fi
jq -nc --arg c "$c3" '{config_digest:$c, runtime_digests:[]}' >"$tmp/bind-empty.json"
if assert_candidate_manifest_binding "$tmp/bind-empty.json" "$c6" >/dev/null 2>&1; then echo 'manifest binding accepted an empty snapshot' >&2; exit 1; fi
if assert_candidate_manifest_binding "$tmp/bind-ok.json" 'sha256:short' >/dev/null 2>&1; then echo 'manifest binding accepted a malformed expected digest' >&2; exit 1; fi
if assert_candidate_manifest_binding "$tmp/bind-missing-file.json" "$c6" >/dev/null 2>&1; then echo 'manifest binding accepted a missing snapshot' >&2; exit 1; fi
candidate_pod() {
	printf '%s %s %s %s %s\n' "$1" "$2" "$3" "$4" "$GOAUTHY_IMAGE"
}
candidate_pods_config=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-2 Running true "containerd://$c3")")
assert_candidate_pods "$candidate_pods_config" "" || { echo 'candidate pod validation rejected config digests' >&2; exit 1; }
candidate_pods_manifest=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c6")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c6")" \
	"$(candidate_pod goauthy-2 Running true "containerd://$c6")")
assert_candidate_pods "$candidate_pods_manifest" "" || { echo 'candidate pod validation rejected manifest digests' >&2; exit 1; }
candidate_pods_node=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://goauthy@$c8")" \
	"$(candidate_pod goauthy-1 Running true "containerd://goauthy@$c8")" \
	"$(candidate_pod goauthy-2 Running true "containerd://goauthy@$c8")")
assert_candidate_pods "$candidate_pods_node" "$candidate_node_digests" || { echo 'candidate pod validation rejected a verified node hash' >&2; exit 1; }
if assert_candidate_pods "$candidate_pods_node" "" >/dev/null 2>&1; then echo 'candidate pod validation trusted an unverified node hash' >&2; exit 1; fi
candidate_pods_wrong_ref=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"goauthy-2 Running true containerd://$c3 wrong@$c6")
if assert_candidate_pods "$candidate_pods_wrong_ref" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted a wrong image ref' >&2; exit 1; fi
candidate_pods_unready=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-2 Running false "containerd://$c3")")
if assert_candidate_pods "$candidate_pods_unready" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted an unready pod' >&2; exit 1; fi
candidate_pods_duplicate=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")")
if assert_candidate_pods "$candidate_pods_duplicate" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted a duplicate pod name' >&2; exit 1; fi
candidate_pods_extra4=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-2 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-2 Running true "containerd://$c3")")
if assert_candidate_pods "$candidate_pods_extra4" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted an extra fourth duplicate row' >&2; exit 1; fi
candidate_pods_wrong_d=$(printf '%s\n' \
	"$(candidate_pod goauthy-0 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-1 Running true "containerd://$c3")" \
	"$(candidate_pod goauthy-2 Running true "containerd://$c9")")
if assert_candidate_pods "$candidate_pods_wrong_d" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted a wrong digest' >&2; exit 1; fi
real_config=$candidate_config_digest
candidate_config_digest=$c9
if assert_candidate_pods "$candidate_pods_config" "" >/dev/null 2>&1; then echo 'candidate pod validation accepted a wrong config digest' >&2; exit 1; fi
candidate_config_digest=$real_config

set +e
run_runner bad-load MOCK_BAD_LOADED=fixture
status=$?
set -e
[ "$status" -eq 1 ] || { echo "wrong loaded image ID was not rejected (status $status)" >&2; exit 1; }
grep -F 'fixture loaded image ID matches neither BuildKit digest' "$tmp/bad-load.log" >/dev/null
set +e
run_runner bad-metadata MOCK_BAD_CONFIG=fixture
status=$?
set -e
[ "$status" -eq 1 ] || { echo "wrong optional BuildKit config digest was not rejected (status $status)" >&2; exit 1; }
grep -F 'fixture BuildKit config digest differs from the saved image archive' "$tmp/bad-metadata.log" >/dev/null
set +e
run_runner bad-archive MOCK_BAD_ARCHIVE=fixture MOCK_CONFIG_PRESENT=fixture
status=$?
set -e
[ "$status" -eq 1 ] || { echo "saved archive config mismatch was not rejected (status $status)" >&2; exit 1; }
grep -F 'fixture BuildKit config digest differs from the saved image archive' "$tmp/bad-archive.log" >/dev/null
echo 'PASS: native BuildKit metadata/archive pins validate; stale tags rebuild; wrong loaded ID, optional config, archive config, pod image, and pod count fail; CRI config binding, repoDigests strictness, snapshot validation, and snapshot-bound runtime pins fail closed'
