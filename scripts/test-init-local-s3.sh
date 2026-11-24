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
network_id=
work=$(mktemp -d)
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ -n "$container_id" ]; then
    docker rm -f "$container_id" >/dev/null || result=1
    if docker container inspect "$container_id" >/dev/null 2>&1; then echo 'container cleanup failed' >&2; result=1; fi
  fi
  if [ -n "$network_id" ]; then
    docker network rm "$network_id" >/dev/null || result=1
    if docker network inspect "$network_id" >/dev/null 2>&1; then echo 'network cleanup failed' >&2; result=1; fi
  fi
  rm -rf "$work" || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
network_id=$(docker network create --internal "$fixture")
container_id=$(docker create --name "$fixture" --network "$network_id" --label "goauthy.init.fixture=$nonce" \
  --tmpfs /data:mode=0777 -p 127.0.0.1::9000 -e ROOT_ACCESS_KEY_ID=goauthy-init-test \
  -e "ROOT_SECRET_ACCESS_KEY=$secret" -e VGW_HEALTH=/_/health \
  versity/versitygw:v1.8.0 --port :9000 posix /data)
docker start "$container_id" >/dev/null
port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$container_id")
curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 "http://127.0.0.1:$port/_/health" >/dev/null
printf 'user = "goauthy-init-test:%s"\n' "$secret" | curl --config - --fail --silent --show-error -X PUT \
  --aws-sigv4 aws:amz:us-east-1:s3 "http://127.0.0.1:$port/goauthy-init-$nonce" >/dev/null
cd "$root"
unset GOAUTHY_INIT_LIFECYCLE_TEST_ROOT GOAUTHY_INIT_LIFECYCLE_TEST_PHASE GOAUTHY_INIT_TEST_S3_FAILURE_CONTROL
export GOAUTHY_INIT_TEST_S3_ENDPOINT="127.0.0.1:$port" GOAUTHY_INIT_TEST_S3_CONTAINER="$container_id"
export GOAUTHY_INIT_TEST_S3_NONCE="$nonce" GOAUTHY_INIT_TEST_S3_SECRET="$secret"
if [ "${1:-}" = --failure-control ]; then export GOAUTHY_INIT_TEST_S3_FAILURE_CONTROL=1; fi
if [ "${1:-}" = --skip-control ]; then unset GOAUTHY_INIT_TEST_S3_ENDPOINT; fi
if go test -json -race ./cmd/goauthy-rhiza-init -run "$test_pattern" -count=1 -timeout=5m >"$work/results.json"; then
  status=0
else
  status=$?
fi
cat "$work/results.json"
if [ "$status" -ne 0 ] || ! awk '
  /"Test":"TestRestoreInitMainAbruptDataLossS3"/ && /"Action":"pass"/ { pass++ }
  /"Test":"TestRestoreInitMainAbruptDataLossS3"/ && /"Action":"skip"/ { skip++ }
  END { exit !(pass == 1 && skip == 0) }
' "$work/results.json"; then
  echo 'S3 recovery test failed, skipped, or did not run' >&2
  exit 1
fi
echo 'S3 recovery test explicitly passed'
