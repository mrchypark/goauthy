#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
: "${E2E_PORT:=20900}"
: "${KIND_CLUSTER:=goauthy-openapi-ha-e2e-$$}"
: "${K8S_NAMESPACE:=goauthy}"
: "${GOAUTHY_IMAGE:=goauthy:openapi-e2e-$$}"
: "${KIND_NODE_IMAGE:=kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
[ "$K8S_NAMESPACE" = goauthy ] || { echo 'this exact-three profile requires namespace goauthy' >&2; exit 1; }
. "$script_dir/lib-ha-kind.sh"
ha_kind_init
ha_kind_setup_cluster
ha_kind_create_secrets
kustomize build "$root/deploy/e2e-openapi-ha" | sed "s#goauthy:e2e#$GOAUTHY_IMAGE#g; s#http://127.0.0.1:18080#http://127.0.0.1:$E2E_PORT#g" | kubectl --context "$context" apply -f -
ha_kind_wait_rollout
ha_kind_wait_exact3_ready

run_phase() {
	GOAUTHY_E2E_OPENAPI=1 \
	GOAUTHY_E2E_OPENAPI_MODE="${2:-private}" \
	GOAUTHY_E2E_OPENAPI_PHASE="$1" \
	GOAUTHY_E2E_OPENAPI_STATE="$temp_dir/openapi-state.json" \
	GOAUTHY_E2E_OPENAPI_URLS="http://localhost:$E2E_PORT,http://localhost:$((E2E_PORT + 1)),http://localhost:$((E2E_PORT + 2))" \
	GOAUTHY_E2E_BROWSER_USERNAME=admin \
	GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple \
	go test -count=1 -v "$root/test/e2e/browser" -run '^TestOpenAPIDocs$'
}

ha_kind_start_forwards
ha_kind_wait_forwards
run_phase initial
ha_kind_stop_forwards
ha_kind_replace_pod0
ha_kind_wait_exact3_ready
ha_kind_start_forwards
ha_kind_wait_forwards
run_phase post-restart
for mode in public disabled; do
	ha_kind_stop_forwards
	if [ "$mode" = public ]; then enabled=true; public=true; else enabled=false; public=false; fi
	kubectl --context "$context" -n "$K8S_NAMESPACE" set env statefulset/goauthy GOAUTHY_SWAGGER_UI_ENABLE="$enabled" GOAUTHY_SWAGGER_UI_PUBLIC="$public"
	kubectl --context "$context" -n "$K8S_NAMESPACE" rollout status statefulset/goauthy --timeout=180s
	ha_kind_wait_exact3_ready
	ha_kind_start_forwards
	ha_kind_wait_forwards
	run_phase initial "$mode"
done
echo 'HA OpenAPI E2E passed'
