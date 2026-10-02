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
jq -e $pin_args -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/pods.json" >/dev/null
jq --arg id "sha256:$(printf '%064d' 9)" '.items[0].status.containerStatuses[0].imageID=$id' "$tmp/pods.json" >"$tmp/wrong-id.json"
if jq -e $pin_args -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-id.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a wrong image ID' >&2; exit 1; fi
jq '.items[0].spec.containers[0].image="wrong:e2e"' "$tmp/pods.json" >"$tmp/wrong-spec.json"
if jq -e $pin_args -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-spec.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted a wrong pod image reference' >&2; exit 1; fi
jq 'del(.items[2])' "$tmp/pods.json" >"$tmp/wrong-count.json"
if jq -e $pin_args -f "$repo/scripts/e2e-kind-saas-isolation-runtime-pins.jq" "$tmp/wrong-count.json" >/dev/null 2>&1; then echo 'runtime pin predicate accepted the wrong pod count' >&2; exit 1; fi

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
echo 'PASS: native BuildKit metadata/archive pins validate; stale tags rebuild; wrong loaded ID, optional config, archive config, pod image, and pod count fail'
