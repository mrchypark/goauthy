#!/bin/sh
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

for command in docker kind kubectl go openssl; do command -v "$command" >/dev/null || { echo "missing required tool: $command" >&2; exit 1; }; done
cluster=${KIND_CLUSTER:-goauthy-tls-e2e}
image=${GOAUTHY_IMAGE:-goauthy:e2e}
namespace=goauthy-tls-e2e
port=${GOAUTHY_TLS_E2E_PORT:-18443}
temp=$(mktemp -d)
forward=
created=false
cleanup() { status=$?; trap - 0 1 2 15; if [ -n "$forward" ]; then kill "$forward" 2>/dev/null || true; wait "$forward" 2>/dev/null || true; fi; [ "$created" != true ] || kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$temp"; e2e_port_lock_release; exit "$status"; }
trap cleanup 0 1 2 15
e2e_port_lock_acquire

make_leaf() {
  name=$1
  openssl genpkey -algorithm ED25519 -out "$temp/$name.key" >/dev/null 2>&1
  openssl req -new -key "$temp/$name.key" -subj /CN=localhost -out "$temp/$name.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$temp/$name.ext"
  openssl x509 -req -in "$temp/$name.csr" -CA "$temp/ca.crt" -CAkey "$temp/ca.key" -CAcreateserial -days 1 -out "$temp/$name.crt" -extfile "$temp/$name.ext" >/dev/null 2>&1
}
serial() { openssl x509 -in "$1" -noout -serial | cut -d= -f2; }
check() { GOAUTHY_TLS_E2E_URL="https://127.0.0.1:$port" GOAUTHY_TLS_E2E_CA_FILE="$temp/ca.crt" GOAUTHY_TLS_E2E_SERIAL="$1" go test -count=1 ./test/e2e_tls; }
wait_for() { expected=$1; for _ in $(seq 1 180); do check "$expected" >/dev/null 2>&1 && return; sleep 1; done; check "$expected"; }

openssl genpkey -algorithm ED25519 -out "$temp/ca.key" >/dev/null 2>&1
openssl req -x509 -new -key "$temp/ca.key" -subj /CN=goauthy-tls-e2e-ca -days 1 -out "$temp/ca.crt" >/dev/null 2>&1
make_leaf initial
if kind get clusters | grep -Fx "$cluster" >/dev/null; then
  echo "refusing to use existing kind cluster: $cluster" >&2
  exit 1
fi
./scripts/e2e-preflight.sh host-capacity
docker build --tag "$image" .
kind create cluster --name "$cluster" --wait 120s
created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
api_server=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='kind-$cluster')].cluster.server}")
case "$api_server" in https://0.0.0.0:*) kubectl config set-cluster "kind-$cluster" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac
kind load docker-image "$image" --name "$cluster"
context=kind-$cluster
kubectl --context "$context" apply -f deploy/e2e-tls/namespace.yaml
kubectl --context "$context" -n "$namespace" create secret generic goauthy-bootstrap --from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY --from-literal=bootstrap-client=correct-horse-battery-staple
kubectl --context "$context" -n "$namespace" create secret generic goauthy-tls --from-file=tls.crt="$temp/initial.crt" --from-file=tls.key="$temp/initial.key"
kubectl --context "$context" apply -f deploy/e2e-tls/deployment.yaml
kubectl --context "$context" -n "$namespace" rollout status deployment/goauthy-tls --timeout=120s
kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 service/goauthy-tls "$port:8443" >"$temp/port-forward.log" 2>&1 & forward=$!
for _ in $(seq 1 50); do grep -q '^Forwarding from 127.0.0.1:' "$temp/port-forward.log" && kill -0 "$forward" && break; kill -0 "$forward" 2>/dev/null || { cat "$temp/port-forward.log" >&2; exit 1; }; sleep 0.1; done
grep -q '^Forwarding from 127.0.0.1:' "$temp/port-forward.log"
wait_for "$(serial "$temp/initial.crt")"
make_leaf rotated
kubectl --context "$context" -n "$namespace" create secret generic goauthy-tls --from-file=tls.crt="$temp/rotated.crt" --from-file=tls.key="$temp/rotated.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
wait_for "$(serial "$temp/rotated.crt")"
printf invalid >"$temp/invalid.crt"; printf invalid >"$temp/invalid.key"
kubectl --context "$context" -n "$namespace" create secret generic goauthy-tls --from-file=tls.crt="$temp/invalid.crt" --from-file=tls.key="$temp/invalid.key" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
for _ in $(seq 1 180); do kubectl --context "$context" -n "$namespace" logs deployment/goauthy-tls | grep -q 'TLS certificate reload failed' && break; sleep 1; done
kubectl --context "$context" -n "$namespace" logs deployment/goauthy-tls | grep -q 'TLS certificate reload failed'
check "$(serial "$temp/rotated.crt")"
cleanup
