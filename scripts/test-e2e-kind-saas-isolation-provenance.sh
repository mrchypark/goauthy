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
        goauthy-saas-isolation-fixture:e2e) printf '%s\n' "sha256:$(printf '%064d' 1)" ;;
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
echo 'PASS: stale local helper tags do not skip native fixture/driver rebuilds; loaded config pins match build metadata'
