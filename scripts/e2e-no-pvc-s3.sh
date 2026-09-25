#!/bin/sh
# Disposable real S3 transport test, not an IED persistence qualification.
set -eu
umask 077
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
test_package=./internal/storage
case "${1:-recovery}" in
  recovery) test_name=TestNoPVCAccountAndSigningKeyRecovery; test_timeout=3m ;;
  export) test_name=TestNoPVCPublicRhizaSnapshotCapture; test_timeout=6m ;;
  scheduled) test_name=TestScheduledBackupRuntimeS3; test_package=./cmd/goauthy; test_timeout=3m ;;
  checkpoint-busy) test_name=TestCreateCheckpointPublisherS3; test_package=./internal/backup; test_timeout=3m ;;
  operator) test_name=TestOperatorS3Roundtrip; test_package=./cmd/goauthy-backup; test_timeout=3m ;;
  *) echo 'usage: e2e-no-pvc-s3.sh [recovery|export|operator|scheduled|checkpoint-busy]' >&2; exit 2 ;;
esac
"$root/scripts/e2e-preflight.sh" host-capacity
context=${GOAUTHY_TEST_DOCKER_CONTEXT:-dory}
fixture=goauthy-no-pvc-$(openssl rand -hex 6)
network=$fixture
container=
cleanup() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ -n "$container" ]; then docker --context "$context" rm -fv "$container" >/dev/null; fi
  docker --context "$context" network rm "$network" >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup EXIT HUP INT TERM
s3_user=goauthy-test
s3_password=$(openssl rand -hex 32)
export ROOT_ACCESS_KEY_ID="$s3_user" ROOT_SECRET_ACCESS_KEY="$s3_password"
docker --context "$context" network create "$network" >/dev/null
container=$fixture
docker --context "$context" run -d --name "$fixture" --network "$network" \
  --tmpfs /data:mode=0777 -p 127.0.0.1::9000 -e ROOT_ACCESS_KEY_ID -e ROOT_SECRET_ACCESS_KEY -e VGW_HEALTH=/_/health \
  versity/versitygw:v1.8.0 --port :9000 posix /data >/dev/null
port=$(docker --context "$context" inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$container")
curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 \
  "http://127.0.0.1:$port/_/health" >/dev/null
printf 'user = "%s:%s"\n' "$s3_user" "$s3_password" |
  curl --config - --fail --silent --show-error -X PUT --aws-sigv4 aws:amz:us-east-1:s3 \
    "http://127.0.0.1:$port/goauthy-no-pvc" >/dev/null
export GOAUTHY_RECOVERY_S3_ENDPOINT="127.0.0.1:$port"
export GOAUTHY_RECOVERY_S3_BUCKET=goauthy-no-pvc
export GOAUTHY_RECOVERY_S3_ACCESS_KEY="$s3_user"
export GOAUTHY_RECOVERY_S3_SECRET_KEY="$s3_password"
cd "$root"
go test -race "$test_package" -run "^${test_name}$" -count=1 -timeout="$test_timeout"
printf 'Real S3 gate passed: %s\n' "$test_name"
