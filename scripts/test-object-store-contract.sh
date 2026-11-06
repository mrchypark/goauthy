#!/bin/sh
# Isolated SDK archive contract, including generic Azure (not app Azure support).
set -eu
umask 077
[ "$#" -eq 0 ] || { echo 'usage: test-object-store-contract.sh' >&2; exit 2; }
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/goauthy-object-contract.XXXXXX")
logs=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/goauthy-object-contract-logs.XXXXXX")
owned_id=
build_pid=
owned_volumes=
record_volumes() {
  # No user mounts or named volumes are supplied to create; image-declared
  # volumes on this exact owned container are therefore disposable anonymous ones.
  owned_volumes=$(timeout -k 5s 30s docker inspect "$owned_id" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}') || return 1
  printf '%s\n' "$owned_volumes" > "$logs/owned-volumes.txt"
}
volumes_absent() {
  for volume in $owned_volumes; do
    remaining=$(timeout -k 5s 30s docker volume ls --filter "name=$volume" --format '{{.Name}}') || return 1
    if printf '%s\n' "$remaining" | grep -Fxq "$volume"; then
      echo "owned anonymous volume remains: $volume" >&2
      return 1
    fi
  done
}
assert_absent() {
  remaining=$(timeout -k 5s 30s docker container ls -a --no-trunc --filter "id=$owned_id" --format '{{.ID}}') || return 1
  [ -z "$remaining" ]
}
cleanup() {
  code=$?
  trap - 0 1 2 15
  if [ -n "$build_pid" ]; then
    # timeout forwards TERM to the supervisor, which owns the compiler group.
    kill -TERM "$build_pid" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt 95 ] && kill -0 "$build_pid" 2>/dev/null; do sleep 1; attempt=$((attempt + 1)); done
    if kill -0 "$build_pid" 2>/dev/null; then
      echo "owned build supervisor remains: PID=$build_pid; retained work=$work" >&2
      exit 1
    fi
    wait "$build_pid" 2>/dev/null || true
  fi
  if [ -n "$owned_id" ]; then
    record_volumes || code=1
    timeout -k 5s 30s docker logs "$owned_id" > "$logs/emulator-cleanup.log" 2>&1 || true
    if ! timeout -k 5s 30s docker rm -fv "$owned_id" > "$logs/cleanup.log" 2>&1; then
      echo "owned container cleanup failed: $owned_id; logs=$logs" >&2
      code=1
    elif ! assert_absent; then
      echo "owned container remains: $owned_id" >&2
      code=1
    fi
    volumes_absent || code=1
  fi
  rm -rf "$work"
  [ ! -e "$work" ] || code=1
  echo "SDK contract receipts: $logs"
  exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 1 15
cd "$root"
# Build on the Ubuntu runner; the test executes inside network-none emulators.
# No host credentials, directories or sockets are mounted into those containers.
timeout -k 90s 15m sh scripts/e2e-stage-supervisor.sh env CGO_ENABLED=0 \
  go test -tags=integration -mod=readonly -p 1 -c -o "$work/storage.test" ./internal/storage &
build_pid=$!
if wait "$build_pid"; then build_status=0; else build_status=$?; fi
build_pid=
[ "$build_status" -eq 0 ] || exit "$build_status"
go version -m "$work/storage.test" > "$logs/buildinfo.txt"
for provider in s3 gcs azure; do
  case "$provider" in
    s3) image='docker.io/floci/floci@sha256:2b60d1b3843084a366cc05d86f089f8e54271b4b62094ea6706831bbea277a00'; port=4566 ;;
    gcs) image='docker.io/floci/floci-gcp@sha256:3defb6e4b037c9ea0555e719c38ea5840159c15145a1872dc651b0c6bc9b2bbb'; port=4588 ;;
    azure) image='docker.io/floci/floci-az@sha256:6a48e35207f041f05aeede4ecba6291e0b26a0f18675a82d6465ddb8fbef00ce'; port=4577 ;;
  esac
  timeout -k 5s 3m docker pull "$image" > "$logs/$provider-pull.log" 2>&1
  timeout -k 5s 30s docker image inspect "$image" --format '{{json .RepoDigests}}' > "$logs/$provider-digests.json"
  # Record a unique owned name before create, so interruption cannot lose it.
  owned_id="goauthy-contract-$(basename "$work")-$provider"
  timeout -k 5s 30s docker create --name "$owned_id" --network none --label goauthy.fixture=object-contract "$image" > "$logs/$provider-container-id.txt"
  created_id=$(cat "$logs/$provider-container-id.txt")
  case "$created_id" in ''|*[!0-9a-f]*) echo 'invalid created container ID; retaining owned name for cleanup' >&2; exit 1 ;; esac
  [ "${#created_id}" -eq 64 ] || { echo 'incomplete container ID; retaining owned name for cleanup' >&2; exit 1; }
  owned_id=$created_id
  record_volumes
  cp "$logs/owned-volumes.txt" "$logs/$provider-volumes.txt"
  printf '%s\n' "$owned_id" > "$logs/$provider-container-id.txt"
  timeout -k 5s 30s docker cp "$work/storage.test" "$owned_id:/storage.test"
  timeout -k 5s 30s docker start "$owned_id" >/dev/null
  case "$provider" in
    s3) set -- -e GOAUTHY_RECOVERY_S3_ENDPOINT=127.0.0.1:4566 -e GOAUTHY_RECOVERY_S3_ACCESS_KEY=test -e GOAUTHY_RECOVERY_S3_SECRET_KEY=test ;;
    gcs) set -- ;;
    azure) set -- -e 'GOAUTHY_OBJECT_AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFeqCnb4Q==;BlobEndpoint=http://127.0.0.1:4577/devstoreaccount1;' ;;
  esac
  status=0
  # The owned Go test validates the loopback URL and waits up to 60s for TCP
  # readiness inside this container before any SDK call. SDK operations then
  # establish service readiness; no curl/shell tooling in the image is needed.
  timeout -k 5s 7m docker exec --user 0 \
    -e GOAUTHY_OBJECT_CONTRACT=1 -e "GOAUTHY_OBJECT_PROVIDER=$provider" \
    -e "GOAUTHY_OBJECT_ENDPOINT=http://127.0.0.1:$port" "$@" \
    "$owned_id" /storage.test -test.run '^TestObjectStoreDependencyContract$' -test.v -test.count=1 -test.timeout=6m \
    > "$logs/$provider-test.log" 2>&1 || status=$?
  printf '%s\n' "$status" > "$logs/$provider.exit"
  cat "$logs/$provider-test.log"
  timeout -k 5s 30s docker logs "$owned_id" > "$logs/$provider-emulator.log" 2>&1 || true
  timeout -k 5s 30s docker rm -fv "$owned_id" > "$logs/$provider-cleanup.log"
  if ! assert_absent; then
    echo "owned container remains: $owned_id" >&2
    exit 1
  fi
  volumes_absent
  owned_id=
  owned_volumes=
  [ "$status" -eq 0 ] && grep -q '^--- PASS: TestObjectStoreDependencyContract ' "$logs/$provider-test.log" && ! grep -q '^--- SKIP:' "$logs/$provider-test.log" || exit 1
  echo "$provider SDK archive contract PASS"
done
