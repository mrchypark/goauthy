#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir -p "$tmp/bin" "$tmp/evidence"
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
  'image save') exit 0 ;;
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
    printf '{"containerimage.digest":"sha256:%s","containerimage.config.digest":"sha256:%s"}\n' "$manifest" "$config" >"$metadata"
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
cat >"$tmp/bin/tar" <<'MOCK'
#!/bin/sh
printf '[{"Config":"blobs/sha256/%s"}]\n' "$(printf '%064d' 3)"
MOCK
chmod +x "$tmp/bin/"*

export MOCK_DOCKER_BUILDS="$tmp/builds"
export PATH="$tmp/bin:$PATH"
set +e
KIND_CLUSTER=test-cluster \
GOAUTHY_IMAGE="goauthy@sha256:$(printf '%064d' 6)" \
GOAUTHY_CANDIDATE_SOURCE="$(printf '%040d' 7)" \
GOAUTHY_E2E_BROWSER_PASSWORD=synthetic \
GOAUTHY_E2E_CLIENT_SECRET=synthetic \
ISOLATION113_EVIDENCE_DIR="$tmp/evidence/run" \
"$repo/scripts/e2e-kind-saas-isolation-113.sh" >"$tmp/run.log" 2>&1
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
MOCK_BAD_LOADED=fixture KIND_CLUSTER=test-cluster \
GOAUTHY_IMAGE="goauthy@sha256:$(printf '%064d' 6)" \
GOAUTHY_CANDIDATE_SOURCE="$(printf '%040d' 7)" \
GOAUTHY_E2E_BROWSER_PASSWORD=synthetic \
GOAUTHY_E2E_CLIENT_SECRET=synthetic \
ISOLATION113_EVIDENCE_DIR="$tmp/evidence/bad-load" \
"$repo/scripts/e2e-kind-saas-isolation-113.sh" >"$tmp/bad-load.log" 2>&1
status=$?
set -e
[ "$status" -eq 1 ] || { echo "wrong loaded image ID was not rejected (status $status)" >&2; exit 1; }
grep -F 'fixture loaded image ID matches neither BuildKit digest' "$tmp/bad-load.log" >/dev/null
echo 'PASS: stale tags rebuild; manifest/config pins and real pod predicate pass; wrong image IDs, specs, and counts fail'
