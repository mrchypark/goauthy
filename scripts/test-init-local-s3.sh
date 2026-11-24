#!/bin/sh
# Run only against a disposable, loopback-only VersityGW fixture.
set -eu
umask 077
case "${1:-}" in
  '') test_pattern='^TestRestoreInitMainAbruptDataLossS3$' ;;
  --failure-control) test_pattern='^TestRestoreInitMainAbruptDataLossS3$' ;;
  --skip-control) test_pattern='^TestRestoreInitMainAbruptDataLossS3$' ;;
  *) echo 'usage: test-init-local-s3.sh [--failure-control|--skip-control]' >&2; exit 2 ;;
esac
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
nonce=$(openssl rand -hex 16)
secret=$(openssl rand -hex 32)
fixture=goauthy-init-test-$nonce
container_id=
runner_id=
runner_pid=
results_printed=0
work=$(mktemp -d)
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ -n "$runner_id" ]; then
    docker rm -f "$runner_id" >/dev/null || result=1
    if docker container inspect "$runner_id" >/dev/null 2>&1; then echo 'runner cleanup failed' >&2; result=1; fi
  fi
  if [ -n "$runner_pid" ]; then wait "$runner_pid" 2>/dev/null || :; fi
  if [ -n "$container_id" ]; then
    docker rm -f "$container_id" >/dev/null || result=1
    if docker container inspect "$container_id" >/dev/null 2>&1; then echo 'container cleanup failed' >&2; result=1; fi
  fi
  if [ "$result" -ne 0 ] && [ "${mode:-}" = --failure-control ] && [ "$results_printed" -eq 0 ] && [ -f "$work/results.json" ]; then
    cat "$work/results.json" >&2 || result=1
  fi
  rm -rf "$work" || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
container_id=$(docker create --name "$fixture" --network none --label "goauthy.init.fixture=$nonce" \
  --tmpfs /data:mode=0777 -e ROOT_ACCESS_KEY_ID=goauthy-init-test \
  -e "ROOT_SECRET_ACCESS_KEY=$secret" -e VGW_HEALTH=/_/health \
  versity/versitygw:v1.8.0 --port :9000 posix /data)
docker start "$container_id" >/dev/null
inspect=$(docker inspect --format '{{index .Config.Labels "goauthy.init.fixture"}}|{{.HostConfig.NetworkMode}}|{{len .NetworkSettings.Ports}}|{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$container_id")
[ "$inspect" = "$nonce|none|0|tmpfs" ] || { echo 'invalid isolated S3 fixture' >&2; exit 1; }
cd "$root"
go mod download
mode=${1:-}
# Go 1.27.4 runner shares the fixture's isolated loopback; no host port is published.
runner_id=$(docker create --network "container:$container_id" \
  -v "$root:/src:ro" -v "$(go env GOMODCACHE):/go/pkg/mod:ro" -v "$work:/control" -w /src \
  -e GOAUTHY_INIT_TEST_S3_CONTAINER="$container_id" -e GOAUTHY_INIT_TEST_S3_NONCE="$nonce" \
  -e GOAUTHY_INIT_TEST_S3_SECRET="$secret" -e TEST_MODE="$mode" -e TEST_PATTERN="$test_pattern" \
  golang@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf sh -c '
    set -eu
    export GOAUTHY_INIT_TEST_S3_ENDPOINT=127.0.0.1:9000 GOPROXY=off
    curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:9000/_/health >/dev/null
    printf "user = \"goauthy-init-test:%s\"\n" "$GOAUTHY_INIT_TEST_S3_SECRET" | curl --config - --fail --silent --show-error -X PUT --aws-sigv4 aws:amz:us-east-1:s3 "http://127.0.0.1:9000/goauthy-init-$GOAUTHY_INIT_TEST_S3_NONCE" >/dev/null
    if [ "$TEST_MODE" = --failure-control ]; then export GOAUTHY_INIT_TEST_S3_FAILURE_CONTROL=1; fi
    if [ "$TEST_MODE" = --skip-control ]; then unset GOAUTHY_INIT_TEST_S3_ENDPOINT; fi
    go test -json -race ./cmd/goauthy-rhiza-init -run "$TEST_PATTERN" -count=1 -timeout=5m
  ')
docker start -a "$runner_id" >"$work/results.json" &
runner_pid=$!
if [ "$mode" = --failure-control ]; then
  attempts=0
  while [ ! -f "$work/archive-ready" ]; do
    if [ "$attempts" -ge 600 ] || ! kill -0 "$runner_pid" 2>/dev/null; then
      echo 'runner did not reach archive removal' >&2
      exit 1
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  inspect=$(docker inspect --format '{{index .Config.Labels "goauthy.init.fixture"}}|{{.HostConfig.NetworkMode}}|{{len .NetworkSettings.Ports}}|{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$container_id")
  [ "$inspect" = "$nonce|none|0|tmpfs" ] || { echo 'invalid isolated S3 fixture' >&2; exit 1; }
  docker exec "$container_id" sh -c '
    set -eu
    bucket=/data/$1
    [ -d "$bucket" ] && [ ! -L "$bucket" ]
    [ -n "$(find "$bucket" -mindepth 1 -maxdepth 1 -print -quit)" ]
    find "$bucket" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    [ -z "$(find "$bucket" -mindepth 1 -maxdepth 1 -print -quit)" ]
  ' sh "goauthy-init-$nonce"
  mkdir "$work/archive-removed"
fi
if wait "$runner_pid"; then
  status=0
else
  status=$?
fi
runner_pid=
cat "$work/results.json"
results_printed=1
if [ "$status" -ne 0 ] || ! awk '
  /"Test":"TestRestoreInitMainAbruptDataLossS3"/ && /"Action":"pass"/ { pass++ }
  /"Test":"TestRestoreInitMainAbruptDataLossS3"/ && /"Action":"skip"/ { skip++ }
  END { exit !(pass == 1 && skip == 0) }
' "$work/results.json"; then
  echo 'S3 recovery test failed, skipped, or did not run' >&2
  exit 1
fi
echo 'S3 recovery test explicitly passed'
