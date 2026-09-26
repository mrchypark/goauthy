GOAUTHY_IMAGE ?= goauthy:e2e
GOAUTHY_BACKCHANNEL_SINK_IMAGE ?= goauthy-backchannel-sink:e2e
GOAUTHY_CIMD_FIXTURE_IMAGE ?= goauthy-cimd-fixture:e2e
GOAUTHY_SCIM_FIXTURE_IMAGE ?= goauthy-scim-fixture:e2e
GOAUTHY_SMTP_SINK_IMAGE ?= goauthy-smtp-sink:e2e
GOAUTHY_UPSTREAM_FIXTURE_IMAGE ?= goauthy-upstream-fixture:e2e
GOAUTHY_CHECKPOINT_FAULT_IMAGE ?= goauthy-checkpoint-fault:e2e
KIND_CLUSTER ?= goauthy-e2e
BACKUP_RESTORE_KIND_CLUSTER ?= goauthy-backup-restore-e2e
CHAOS_KIND_CLUSTER ?= goauthy-restart-chaos-e2e
CIMD_KIND_CLUSTER ?= goauthy-cimd-e2e
CIMD_CILIUM_KIND_CLUSTER ?= goauthy-cimd-cilium-e2e
K8S_NAMESPACE ?= goauthy
E2E_PORT ?= 18080
E2E_PROFILE ?= full
GOAUTHY_STANDALONE_PORT ?= 18081
GOAUTHY_STANDALONE_WEBID_PORT ?= 18082
GOAUTHY_STANDALONE_ADMIN_PORT ?= 18085
GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT ?= 18083
GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT ?= 18084

# Pass user-provided Make values through the process environment.  Recipe
# expansion must never turn a value such as "$(...)" into shell syntax.
e2e_input_kind_cluster := $(value KIND_CLUSTER)
e2e_input_backup_restore_kind_cluster := $(value BACKUP_RESTORE_KIND_CLUSTER)
e2e_input_namespace := $(value K8S_NAMESPACE)
e2e_input_port := $(value E2E_PORT)
e2e_input_profile := $(value E2E_PROFILE)
e2e_input_image := $(value GOAUTHY_IMAGE)
e2e_input_backchannel_image := $(value GOAUTHY_BACKCHANNEL_SINK_IMAGE)
e2e_input_scim_fixture_image := $(value GOAUTHY_SCIM_FIXTURE_IMAGE)
e2e_input_smtp_image := $(value GOAUTHY_SMTP_SINK_IMAGE)
e2e_input_upstream_fixture_image := $(value GOAUTHY_UPSTREAM_FIXTURE_IMAGE)
e2e_input_checkpoint_fault_image := $(value GOAUTHY_CHECKPOINT_FAULT_IMAGE)
e2e_input_standalone_webid_port := $(value GOAUTHY_STANDALONE_WEBID_PORT)
e2e_input_standalone_admin_port := $(value GOAUTHY_STANDALONE_ADMIN_PORT)
export E2E_INPUT_KIND_CLUSTER := $(value e2e_input_kind_cluster)
export E2E_INPUT_BACKUP_RESTORE_KIND_CLUSTER := $(value e2e_input_backup_restore_kind_cluster)
export E2E_INPUT_NAMESPACE := $(value e2e_input_namespace)
export E2E_INPUT_PORT := $(value e2e_input_port)
export E2E_INPUT_PROFILE := $(value e2e_input_profile)
export E2E_INPUT_IMAGE := $(value e2e_input_image)
export E2E_INPUT_BACKCHANNEL_IMAGE := $(value e2e_input_backchannel_image)
export E2E_INPUT_SCIM_FIXTURE_IMAGE := $(value e2e_input_scim_fixture_image)
export E2E_INPUT_SMTP_IMAGE := $(value e2e_input_smtp_image)
export E2E_INPUT_UPSTREAM_FIXTURE_IMAGE := $(value e2e_input_upstream_fixture_image)
export E2E_INPUT_CHECKPOINT_FAULT_IMAGE := $(value e2e_input_checkpoint_fault_image)
export E2E_INPUT_STANDALONE_WEBID_PORT := $(value e2e_input_standalone_webid_port)
export E2E_INPUT_STANDALONE_ADMIN_PORT := $(value e2e_input_standalone_admin_port)
override KIND_CLUSTER = $${E2E_INPUT_KIND_CLUSTER}
override BACKUP_RESTORE_KIND_CLUSTER = $${E2E_INPUT_BACKUP_RESTORE_KIND_CLUSTER}
override K8S_NAMESPACE = $${E2E_INPUT_NAMESPACE}
override E2E_PORT = $${E2E_INPUT_PORT}
override E2E_PROFILE = $${E2E_INPUT_PROFILE}
override GOAUTHY_IMAGE = $${E2E_INPUT_IMAGE}
override GOAUTHY_BACKCHANNEL_SINK_IMAGE = $${E2E_INPUT_BACKCHANNEL_IMAGE}
override GOAUTHY_SCIM_FIXTURE_IMAGE = $${E2E_INPUT_SCIM_FIXTURE_IMAGE}
override GOAUTHY_SMTP_SINK_IMAGE = $${E2E_INPUT_SMTP_IMAGE}
override GOAUTHY_UPSTREAM_FIXTURE_IMAGE = $${E2E_INPUT_UPSTREAM_FIXTURE_IMAGE}
override GOAUTHY_CHECKPOINT_FAULT_IMAGE = $${E2E_INPUT_CHECKPOINT_FAULT_IMAGE}
override GOAUTHY_STANDALONE_WEBID_PORT = $${E2E_INPUT_STANDALONE_WEBID_PORT}
override GOAUTHY_STANDALONE_ADMIN_PORT = $${E2E_INPUT_STANDALONE_ADMIN_PORT}
e2e_kind_inputs = KIND_CLUSTER="$(KIND_CLUSTER)" K8S_NAMESPACE="$(K8S_NAMESPACE)" E2E_PORT="$(E2E_PORT)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" GOAUTHY_CHECKPOINT_FAULT_IMAGE="$(GOAUTHY_CHECKPOINT_FAULT_IMAGE)" GOAUTHY_BACKCHANNEL_SINK_IMAGE="$(GOAUTHY_BACKCHANNEL_SINK_IMAGE)" GOAUTHY_SMTP_SINK_IMAGE="$(GOAUTHY_SMTP_SINK_IMAGE)"

# Only explicit wall-clock expiry runs shorten sessions. Ordinary lifecycle
# checks must not race a ten-second idle deadline or the touch throttle.
define e2e_session_policy
browser_idle_timeout_value=90m; \
if [ "$$E2E_PROFILE" = wall-clock-idle-expiry ] || [ "$${GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY:-0}" = 1 ]; then browser_idle_timeout_value=10s; fi
endef

.PHONY: test-e2e-session-policy

.PHONY: test e2e-standalone e2e-standalone-webid e2e-standalone-admin e2e-standalone-backup-restore e2e-standalone-dcr e2e-standalone-scim e2e-kind e2e-kind-backup-restore e2e-kind-backchannel-https e2e-kind-dcr-anonymous e2e-kind-dcr-backchannel e2e-kind-fedcm e2e-kind-forward-auth e2e-kind-admission e2e-kind-open-registration e2e-kind-user-delete e2e-kind-roles-groups e2e-kind-client-credentials-claims e2e-kind-admin-api-keys e2e-kind-self-attributes e2e-kind-admin-passkey e2e-kind-default-aud e2e-kind-wall-clock-jwks e2e-kind-wall-clock-idle-expiry e2e-kind-password-grant e2e-kind-password-lifecycle e2e-kind-webid test-e2e-tls-cleanup e2e-kind-chaos e2e-kind-cimd e2e-kind-cimd-cilium e2e-kind-scim e2e-kind-upstream e2e-kind-issuer-path e2e-kind-favicon e2e-kind-tc-network-partition

e2e-standalone:
	GOAUTHY_STANDALONE_PORT="$(GOAUTHY_STANDALONE_PORT)" ./scripts/e2e-standalone.sh

# Evaluate only the rendered assignment/if block, never provisioning commands.
# Testing the shared macro alone misses later profile-specific overrides.
test-e2e-session-policy:
	@set -eu; \
	policy_config=$$($(MAKE) --no-print-directory -n e2e-kind | sed -n '/^[[:space:]]*e2e_kustomization=deploy\/k8s;/,/^[[:space:]]*created=false;/{s/\\$$//;p;}'); \
	case "$$policy_config" in *'e2e_kustomization=deploy/k8s;'*'created=false;'*) ;; *) echo 'missing rendered E2E configuration boundaries' >&2; exit 1;; esac; \
	for profile in full open-registration user-delete wall-clock-jwks wall-clock-idle-expiry roles-groups client-credentials-claims admin-api-keys self-attributes passkey forced-mfa admin-passkey; do \
		for explicit in 0 1; do \
			E2E_PROFILE=$$profile; E2E_INPUT_PROFILE=$$profile; E2E_INPUT_PORT=18080; GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=$$explicit; \
			eval "$$policy_config"; \
			case "$$profile/$$explicit" in wall-clock-idle-expiry/*|*/1) expected=10s;; *) expected=90m;; esac; \
			[ "$$browser_idle_timeout_value" = "$$expected" ] || { echo "unexpected session policy for $$profile/$$explicit" >&2; exit 1; }; \
		done; \
	done; \
	echo 'E2E session policy regression passed'

.PHONY: e2e-standalone-open-registration
e2e-standalone-open-registration:
	sh ./scripts/e2e-open-registration-standalone.sh

e2e-standalone-webid:
	GOAUTHY_STANDALONE_WEBID_PORT="$${E2E_INPUT_STANDALONE_WEBID_PORT}" ./scripts/e2e-webid-standalone.sh

e2e-standalone-admin:
	GOAUTHY_STANDALONE_ADMIN_PORT="$${E2E_INPUT_STANDALONE_ADMIN_PORT}" ./scripts/e2e-admin-standalone.sh

.PHONY: e2e-standalone-admin-passkey
e2e-standalone-admin-passkey:
	sh ./scripts/e2e-admin-passkey-standalone.sh

.PHONY: e2e-kind-admin e2e-standalone-kv e2e-kind-kv e2e-standalone-geoblock e2e-kind-geoblock e2e-standalone-openapi e2e-kind-openapi

e2e-standalone-openapi:
	./scripts/e2e-openapi-standalone.sh

e2e-kind-openapi:
	$(e2e_kind_inputs) ./scripts/e2e-openapi-ha-kind.sh

e2e-kind-admin:
	$(e2e_kind_inputs) ./scripts/e2e-admin-ha-kind.sh

e2e-standalone-kv:
	./scripts/e2e-kv-standalone.sh

e2e-kind-kv:
	$(e2e_kind_inputs) ./scripts/e2e-kv-ha-kind.sh

e2e-standalone-geoblock:
	./scripts/e2e-geoblock-standalone.sh

e2e-kind-geoblock:
	$(e2e_kind_inputs) ./scripts/e2e-geoblock-ha-kind.sh

e2e-standalone-backup-restore:
	GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT="$(GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT)" GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT="$(GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT)" ./scripts/e2e-standalone-backup-restore.sh

e2e-kind-backup-restore:
	E2E_PORT="$(E2E_PORT)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" GOAUTHY_CHECKPOINT_FAULT_IMAGE="$(GOAUTHY_CHECKPOINT_FAULT_IMAGE)" ./scripts/e2e-kind-backup-restore.sh

e2e-standalone-dcr:
	GOAUTHY_STANDALONE_PORT="$(GOAUTHY_STANDALONE_PORT)" ./scripts/e2e-standalone-dcr.sh

e2e-standalone-scim:
	GOAUTHY_STANDALONE_PORT="$(GOAUTHY_STANDALONE_PORT)" ./scripts/e2e-scim-standalone.sh

e2e-kind-dcr-anonymous:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-dcr-anonymous" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-dcr-anonymous-kind.sh

e2e-kind-fedcm:
	GOAUTHY_FEDCM_RUN_KIND=1 E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-fedcm" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-fedcm-kind.sh

e2e-kind-forward-auth:
	$(MAKE) e2e-kind E2E_PROFILE=forward-auth $(e2e_kind_inputs)

e2e-kind-backchannel-https:
	$(MAKE) e2e-kind E2E_PROFILE=backchannel-https $(e2e_kind_inputs)

test: test-e2e-session-policy
	# Actual suite exceeds default 10m; OAuth alone takes 1016s (see ledger row 10).
	go test -timeout=60m ./...
	go vet ./...
	go test -race -timeout=60m ./...

e2e-kind-chaos:
	E2E_PORT=$(E2E_PORT) KIND_CLUSTER=$(CHAOS_KIND_CLUSTER) GOAUTHY_IMAGE=$(GOAUTHY_IMAGE) ./scripts/e2e-pod-restart-chaos.sh

.PHONY: e2e-kind-network-partition
e2e-kind-network-partition:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER=goauthy-cilium-e2e GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-network-chaos.sh

e2e-kind-tc-network-partition:
	sh ./scripts/test-e2e-tc-capability.sh
	sh ./scripts/test-e2e-tc-oracles.sh
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER=goauthy-tc-network-e2e GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" GOAUTHY_NETWORK_CHAOS_BACKEND=tc ./scripts/e2e-network-chaos.sh

e2e-kind-admission:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-admission" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-admission-kind.sh

e2e-kind-cimd:
	E2E_PORT=$(E2E_PORT) KIND_CLUSTER=$(CIMD_KIND_CLUSTER) GOAUTHY_IMAGE=$(GOAUTHY_IMAGE) GOAUTHY_CIMD_FIXTURE_IMAGE=$(GOAUTHY_CIMD_FIXTURE_IMAGE) ./scripts/e2e-cimd-kind.sh

e2e-kind-cimd-cilium:
	E2E_PORT=$(E2E_PORT) KIND_CLUSTER=$(CIMD_CILIUM_KIND_CLUSTER) GOAUTHY_IMAGE=$(GOAUTHY_IMAGE) GOAUTHY_CIMD_FIXTURE_IMAGE=$(GOAUTHY_CIMD_FIXTURE_IMAGE) ./scripts/e2e-cimd-cilium-kind.sh

e2e-kind-scim:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-scim" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" GOAUTHY_SCIM_FIXTURE_IMAGE="$(GOAUTHY_SCIM_FIXTURE_IMAGE)" ./scripts/e2e-scim-kind.sh

e2e-kind-upstream:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-upstream" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" GOAUTHY_UPSTREAM_FIXTURE_IMAGE="$(GOAUTHY_UPSTREAM_FIXTURE_IMAGE)" ./scripts/e2e-upstream-kind.sh

e2e-kind-issuer-path:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-issuer-path" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-issuer-path-kind.sh

e2e-kind-favicon:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-favicon" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-favicon-kind.sh

e2e-kind-password-grant:
	$(e2e_kind_inputs) GOAUTHY_BACKCHANNEL_SINK_IMAGE="$(GOAUTHY_BACKCHANNEL_SINK_IMAGE)" ./scripts/e2e-password-grant-kind.sh

e2e-kind-dcr-backchannel:
	$(e2e_kind_inputs) GOAUTHY_BACKCHANNEL_SINK_IMAGE="$(GOAUTHY_BACKCHANNEL_SINK_IMAGE)" ./scripts/e2e-dcr-backchannel-kind.sh

e2e-kind-password-lifecycle:
	$(MAKE) e2e-kind E2E_PROFILE=password-lifecycle $(e2e_kind_inputs)

e2e-kind-webid:
	E2E_PORT="$(E2E_PORT)" KIND_CLUSTER="$(KIND_CLUSTER)-webid" K8S_NAMESPACE="$(K8S_NAMESPACE)" GOAUTHY_IMAGE="$(GOAUTHY_IMAGE)" ./scripts/e2e-webid-ha-kind.sh

e2e-kind-open-registration:
	$(MAKE) e2e-kind E2E_PROFILE=open-registration $(e2e_kind_inputs)

e2e-kind-user-delete:
	$(MAKE) e2e-kind E2E_PROFILE=user-delete $(e2e_kind_inputs)

e2e-kind-roles-groups:
	$(MAKE) e2e-kind E2E_PROFILE=roles-groups $(e2e_kind_inputs)

e2e-kind-client-credentials-claims:
	$(MAKE) e2e-kind E2E_PROFILE=client-credentials-claims $(e2e_kind_inputs)

e2e-kind-admin-api-keys:
	$(MAKE) e2e-kind E2E_PROFILE=admin-api-keys $(e2e_kind_inputs)

e2e-kind-default-aud:
	$(MAKE) e2e-kind E2E_PROFILE=default-aud $(e2e_kind_inputs)

e2e-kind-self-attributes:
	$(MAKE) e2e-kind E2E_PROFILE=self-attributes $(e2e_kind_inputs)

e2e-kind-admin-passkey:
	$(MAKE) e2e-kind E2E_PROFILE=admin-passkey $(e2e_kind_inputs)

e2e-kind-wall-clock-jwks:
	GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1 $(MAKE) e2e-kind E2E_PROFILE=wall-clock-jwks $(e2e_kind_inputs)

e2e-kind-wall-clock-idle-expiry:
	GOAUTHY_E2E_WALL_CLOCK_IDLE_EXPIRY=1 $(MAKE) e2e-kind E2E_PROFILE=wall-clock-idle-expiry $(e2e_kind_inputs)

test-e2e-tls-cleanup:
	@set -eu; temp_dir=$$(mktemp -d); log="$$temp_dir/kind.log"; trap 'rm -rf "$$temp_dir"' 0 1 2 15; \
	printf '%s\n' '#!/bin/sh' 'case "$$1" in' 'get) test "$${TLS_FAKE_KIND_MODE:-}" != existing || printf "%s\\n" "$$KIND_CLUSTER";;' 'create) exit 1;;' 'delete) printf delete >>"$$TLS_FAKE_KIND_LOG";;' '*) exit 0;;' 'esac' >"$$temp_dir/kind"; chmod +x "$$temp_dir/kind"; \
	printf '%s\n' '#!/bin/sh' 'exit 0' >"$$temp_dir/docker"; chmod +x "$$temp_dir/docker"; \
	printf '%s\n' '#!/bin/sh' 'printf "Filesystem 1024-blocks Used Available Capacity Mounted on\\nfixture 1 1 12582912 1%% /\\n"' >"$$temp_dir/df"; chmod +x "$$temp_dir/df"; \
	if PATH="$$temp_dir:$$PATH" TLS_FAKE_KIND_LOG="$$log" TLS_FAKE_KIND_MODE=existing KIND_CLUSTER=goauthy-tls-cleanup-fixture GOAUTHY_IMAGE=fixture ./scripts/e2e-tls.sh >/dev/null 2>&1; then echo 'expected existing-cluster rejection' >&2; exit 1; fi; \
	if PATH="$$temp_dir:$$PATH" TLS_FAKE_KIND_LOG="$$log" KIND_CLUSTER=goauthy-tls-cleanup-fixture GOAUTHY_IMAGE=fixture ./scripts/e2e-tls.sh >/dev/null 2>&1; then echo 'expected fake kind create failure' >&2; exit 1; fi; \
	test ! -s "$$log"

e2e-kind:
	@set -eu; \
	KIND_CLUSTER=$$E2E_INPUT_KIND_CLUSTER; K8S_NAMESPACE=$$E2E_INPUT_NAMESPACE; E2E_PORT=$$E2E_INPUT_PORT; E2E_PROFILE=$$E2E_INPUT_PROFILE; GOAUTHY_IMAGE=$$E2E_INPUT_IMAGE; GOAUTHY_BACKCHANNEL_SINK_IMAGE=$$E2E_INPUT_BACKCHANNEL_IMAGE; GOAUTHY_SMTP_SINK_IMAGE=$$E2E_INPUT_SMTP_IMAGE; \
	for command in docker kind kubectl curl go jq grep nc; do command -v $$command >/dev/null || { echo "missing required tool: $$command" >&2; exit 1; }; done; \
	valid_dns_label() { case "$$1" in ''|*[!a-z0-9-]*|-*|*-) return 1;; esac; [ $${#1} -le 63 ]; }; \
	valid_image() { case "$$1" in ''|*[!A-Za-z0-9./:_@-]*) return 1;; esac; }; \
	case "$$E2E_PORT" in ''|*[!0-9]*) echo 'E2E_PORT must be a decimal TCP port' >&2; exit 1;; esac; \
	[ "$$E2E_PORT" -ge 1024 ] && [ "$$E2E_PORT" -le 65531 ] || { echo 'E2E_PORT must leave room for five ports (1024..65531)' >&2; exit 1; }; \
	valid_dns_label "$$KIND_CLUSTER" || { echo 'KIND_CLUSTER must be a DNS label' >&2; exit 1; }; \
	valid_dns_label "$$K8S_NAMESPACE" || { echo 'K8S_NAMESPACE must be a DNS label' >&2; exit 1; }; \
	for image in "$$GOAUTHY_IMAGE" "$$GOAUTHY_BACKCHANNEL_SINK_IMAGE" "$$GOAUTHY_SMTP_SINK_IMAGE"; do valid_image "$$image" || { echo 'E2E image names contain unsupported characters' >&2; exit 1; }; done; \
	case "$$E2E_PROFILE" in full|backchannel-https|forward-auth|password-policy|password-lifecycle|password-reset|open-registration|user-delete|roles-groups|client-credentials-claims|admin-api-keys|self-attributes|passkey|forced-mfa|admin-passkey|default-aud|wall-clock-jwks|wall-clock-idle-expiry|ip-blacklist-events|backchannel-failure-events|global-logout) ;; *) echo 'unknown E2E_PROFILE' >&2; exit 1;; esac; \
	case "$${GOAUTHY_E2E_DCR_DPOP_CONTINUITY:-0}" in 0) ;; 1) [ "$$E2E_PROFILE" = full ] && [ "$${GOAUTHY_E2E_DPOP_CONTINUITY:-0}" = 1 ] && [ "$${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ] || { echo 'dynamic DPoP continuity requires full profile, DPOP_CONTINUITY=1 and DEVICE_LOGIN_FLOW=1' >&2; exit 1; };; *) echo 'GOAUTHY_E2E_DCR_DPOP_CONTINUITY must be 0 or 1' >&2; exit 1;; esac; \
	case "$${GOAUTHY_E2E_ACTOR_CONTINUITY:-0}" in 0) ;; 1) export GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR=1;; *) echo 'GOAUTHY_E2E_ACTOR_CONTINUITY must be 0 or 1' >&2; exit 1;; esac; \
	if [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then [ "$$E2E_PROFILE" = full ] || { echo 'actor exchange gate requires full profile' >&2; exit 1; }; fi; \
	policy_mode=$${GOAUTHY_E2E_USER_VALUES_MODE:-}; \
	if [ "$${GOAUTHY_E2E_ACCOUNT_LIFECYCLE_UI:-0}" = 1 ]; then export GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1; fi; \
	if [ "$${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then [ "$$E2E_PROFILE" = open-registration ] && [ "$${GOAUTHY_E2E_PROFILE_CLAIMS:-0}" = 1 ] || { echo 'account passkey UI requires open-registration profile batch' >&2; exit 1; }; fi; \
	case "$$policy_mode" in ''|required|optional|hidden) ;; *) echo 'invalid GOAUTHY_E2E_USER_VALUES_MODE' >&2; exit 1;; esac; \
	preferred_mode=$${GOAUTHY_E2E_PREFERRED_USERNAME_POLICY:-}; \
	case "$$preferred_mode" in ''|default|custom) ;; *) echo 'invalid GOAUTHY_E2E_PREFERRED_USERNAME_POLICY' >&2; exit 1;; esac; \
	if [ -n "$$preferred_mode" ]; then [ -z "$$policy_mode" ] && [ "$$E2E_PROFILE" = open-registration ] && [ "$${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" != 1 ] && [ "$${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" != 1 ] || { echo 'preferred username requires a separate open-registration fixture' >&2; exit 1; }; fi; \
	if [ -n "$$policy_mode" ]; then [ "$$E2E_PROFILE" = open-registration ] && [ "$${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" != 1 ] && [ "$${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" != 1 ] || { echo 'user-values policy requires a separate open-registration fixture' >&2; exit 1; }; fi; \
	if [ "$$E2E_PROFILE" = wall-clock-jwks ]; then [ "$${GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION:-}" = 1 ] || { echo 'JWKS E2E requires GOAUTHY_E2E_WALL_CLOCK_JWKS_ROTATION=1 (real five-minute cache boundary)' >&2; exit 1; }; fi; \
	port_available() { ! nc -z 127.0.0.1 "$$1" >/dev/null 2>&1; }; \
	for offset in 0 1 2 3; do port=$$(( $$E2E_PORT + $$offset )); port_available "$$port" || { echo "E2E host port $$port is already in use; choose E2E_PORT" >&2; exit 1; }; done; \
	case "$$E2E_PROFILE" in password-reset|open-registration|user-delete|self-attributes) port=$$(( $$E2E_PORT + 4 )); port_available "$$port" || { echo "E2E host port $$port is already in use; choose E2E_PORT" >&2; exit 1; };; esac; \
	if kind get clusters | grep -Fx "$$KIND_CLUSTER" >/dev/null; then echo "refusing to use existing kind cluster: $$KIND_CLUSTER" >&2; exit 1; fi; \
	./scripts/e2e-preflight.sh host-capacity; \
	temp_dir=$$(mktemp -d); \
	browser_password=correct-horse-browser-staple; \
	browser_phc=$$(printf '%s\n' "$$browser_password" | go run ./cmd/goauthy-password); \
	backchannel_uri=http://goauthy-backchannel-sink.goauthy.svc.cluster.local:8081/backchannel; backchannel_allow_private=true; backchannel_allow_http=true; backchannel_ca_file=; sink_tls_cert_file=; sink_tls_key_file=; \
	if [ "$(E2E_PROFILE)" = backchannel-https ]; then \
		openssl genrsa -out "$$temp_dir/backchannel-ca.key" 2048 >/dev/null 2>&1; \
		openssl req -x509 -new -sha256 -key "$$temp_dir/backchannel-ca.key" -out "$$temp_dir/backchannel-ca.crt" -days 1 -subj '/CN=GoAuthy Backchannel E2E Test CA' >/dev/null 2>&1; \
		openssl req -new -newkey rsa:2048 -nodes -keyout "$$temp_dir/backchannel-sink.key" -out "$$temp_dir/backchannel-sink.csr" -subj '/CN=goauthy-backchannel-sink.goauthy.svc.cluster.local' -addext 'subjectAltName=DNS:goauthy-backchannel-sink.goauthy.svc,DNS:goauthy-backchannel-sink.goauthy.svc.cluster.local,IP:127.0.0.1' >/dev/null 2>&1; \
		openssl x509 -req -in "$$temp_dir/backchannel-sink.csr" -CA "$$temp_dir/backchannel-ca.crt" -CAkey "$$temp_dir/backchannel-ca.key" -CAcreateserial -out "$$temp_dir/backchannel-sink.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1; \
		backchannel_uri=https://goauthy-backchannel-sink.goauthy.svc.cluster.local:8081/backchannel; backchannel_allow_private=true; backchannel_allow_http=false; backchannel_ca_file=/run/backchannel-ca/ca.crt; sink_tls_cert_file=/run/backchannel-tls/tls.crt; sink_tls_key_file=/run/backchannel-tls/tls.key; \
	fi; \
	e2e_kustomization=deploy/k8s; \
	kustomize_load_restrictor=; \
	$(e2e_session_policy); \
	reset_secret_arg=; \
	passkey_secret_arg=; forward_auth_env=; e2e_issuer=http://127.0.0.1:$(E2E_PORT); \
	if [ "$(E2E_PROFILE)" = forward-auth ]; then e2e_kustomization=deploy/k8s/forward-auth; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; fi; \
	if [ "$(E2E_PROFILE)" = forward-auth ]; then forward_auth_env=GOAUTHY_FORWARD_AUTH_HEADERS=true; fi; \
	if [ "$(E2E_PROFILE)" = password-reset ] || [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then e2e_kustomization=deploy/k8s/password-reset; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; reset_secret_arg=--from-literal=password-reset-key=0123456789abcdef0123456789abcdef; fi; \
	if [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ]; then e2e_kustomization=deploy/k8s/open-registration; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; reset_secret_arg=--from-literal=password-reset-key=0123456789abcdef0123456789abcdef; fi; \
	if [ "$(E2E_PROFILE)" = roles-groups ] || [ "$(E2E_PROFILE)" = client-credentials-claims ] || [ "$(E2E_PROFILE)" = admin-api-keys ]; then e2e_kustomization=deploy/k8s/roles-groups; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; fi; \
	if [ "$(E2E_PROFILE)" = default-aud ]; then e2e_kustomization=deploy/defaultaud; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; fi; \
	if [ "$(E2E_PROFILE)" = self-attributes ]; then e2e_kustomization=deploy/k8s/self-attributes; kustomize_load_restrictor='--load-restrictor LoadRestrictionsNone'; reset_secret_arg=--from-literal=password-reset-key=0123456789abcdef0123456789abcdef; fi; \
	if [ "$(E2E_PROFILE)" = passkey ] || [ "$(E2E_PROFILE)" = forced-mfa ] || [ "$(E2E_PROFILE)" = admin-passkey ] || [ "$(E2E_PROFILE)" = forward-auth ] || [ "$${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then passkey_secret_arg=--from-literal=passkey-key=0123456789abcdef0123456789abcdef; e2e_issuer=http://localhost:$(E2E_PORT); fi; \
	created=false; \
	port_forward=; \
	secondary_forward=; \
	tertiary_forward=; \
	quaternary_forward=; \
	quinary_forward=; \
	cleanup() { \
		status=$$?; \
		trap - 0 1 2 15; \
		if [ -n "$$port_forward" ]; then kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; fi; \
		if [ -n "$$secondary_forward" ]; then kill $$secondary_forward >/dev/null 2>&1 || true; wait $$secondary_forward 2>/dev/null || true; fi; \
		if [ -n "$$tertiary_forward" ]; then kill $$tertiary_forward >/dev/null 2>&1 || true; wait $$tertiary_forward 2>/dev/null || true; fi; \
		if [ -n "$$quaternary_forward" ]; then kill $$quaternary_forward >/dev/null 2>&1 || true; wait $$quaternary_forward 2>/dev/null || true; fi; \
		if [ -n "$$quinary_forward" ]; then kill $$quinary_forward >/dev/null 2>&1 || true; wait $$quinary_forward 2>/dev/null || true; fi; \
		if [ "$$status" -ne 0 ] && kubectl config get-contexts -o name | grep -qx "kind-$(KIND_CLUSTER)"; then \
			for log in "$$temp_dir/port-forward.log" "$$temp_dir/secondary-forward.log" "$$temp_dir/tertiary-forward.log" "$$temp_dir/quaternary-forward.log" "$$temp_dir/smtp-forward.log"; do test ! -s "$$log" || sed "s/^/[port-forward] /" "$$log" >&2; done; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get all 2>&1 | sed 's/^/[resources] /' || true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true; \
			for pod in goauthy-0 goauthy-1 goauthy-2; do \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) logs pod/$$pod --all-containers=true 2>&1 | sed "s/^/[$$pod current] /" || true; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) logs pod/$$pod --all-containers=true --previous 2>&1 | sed "s/^/[$$pod previous] /" || true; \
			done; \
		fi; \
		if [ "$$created" = true ]; then kind delete cluster --name $(KIND_CLUSTER) >/dev/null 2>&1 || true; fi; \
		rm -rf "$$temp_dir"; \
		exit $$status; \
	}; \
	trap cleanup 0 1 2 15; \
	docker build --tag $(GOAUTHY_IMAGE) .; \
	docker build --target backchannel-sink --tag $(GOAUTHY_BACKCHANNEL_SINK_IMAGE) .; \
	if [ "$(E2E_PROFILE)" = password-reset ] || [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ] || [ "$(E2E_PROFILE)" = self-attributes ] || [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then docker build --target smtp-sink --tag $(GOAUTHY_SMTP_SINK_IMAGE) .; fi; \
	kind create cluster --name $(KIND_CLUSTER) --wait 120s; \
	created=true; \
	api_server=$$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"kind-$$KIND_CLUSTER\")].cluster.server}"); \
	case "$$api_server" in https://0.0.0.0:*) kubectl config set-cluster kind-$(KIND_CLUSTER) --server="$$(printf '%s' "$$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null;; esac; \
	./scripts/e2e-preflight.sh kind-inotify --cluster $(KIND_CLUSTER); \
	kind load docker-image $(GOAUTHY_IMAGE) --name $(KIND_CLUSTER); \
	kind load docker-image $(GOAUTHY_BACKCHANNEL_SINK_IMAGE) --name $(KIND_CLUSTER); \
	if [ "$(E2E_PROFILE)" = password-reset ] || [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ] || [ "$(E2E_PROFILE)" = self-attributes ] || [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then kind load docker-image $(GOAUTHY_SMTP_SINK_IMAGE) --name $(KIND_CLUSTER); fi; \
	kubectl --context kind-$(KIND_CLUSTER) apply -f deploy/k8s/namespace.yaml; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create secret generic goauthy-secrets \
		--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
		--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
		--from-literal=bootstrap-client=correct-horse-battery-staple \
		--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
		$$reset_secret_arg \
		$$passkey_secret_arg \
		--from-literal=bootstrap-user-password-phc="$$browser_phc" \
		--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
		--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
		--from-literal=versity-root-user=goauthy-e2e \
		--from-literal=versity-root-password=goauthy-e2e-versity-password \
		--dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
	if [ "$(E2E_PROFILE)" = backchannel-https ]; then \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create secret generic goauthy-backchannel-ca --from-file=ca.crt="$$temp_dir/backchannel-ca.crt" --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create secret generic goauthy-backchannel-sink-tls --from-file=tls.crt="$$temp_dir/backchannel-sink.crt" --from-file=tls.key="$$temp_dir/backchannel-sink.key" --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
	fi; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create configmap goauthy-backchannel \
		--from-literal=logout-uri="$$backchannel_uri" \
		--from-literal=allow-private="$$backchannel_allow_private" \
		--from-literal=allow-http="$$backchannel_allow_http" \
		--from-literal=retry-base=1s \
		--from-literal=ca-file="$$backchannel_ca_file" \
		--from-literal=tls-cert-file="$$sink_tls_cert_file" \
		--from-literal=tls-key-file="$$sink_tls_key_file" \
		--dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
	kustomize build $$kustomize_load_restrictor "$$e2e_kustomization" | sed -e "s#image: goauthy:e2e\$$#image: $$GOAUTHY_IMAGE#" -e "s#image: goauthy-smtp-sink:e2e\$$#image: $$GOAUTHY_SMTP_SINK_IMAGE#" -e "s#http://127.0.0.1:18080#$$e2e_issuer#g" -e '/name: GOAUTHY_SIGNING_KEY_ROTATION_PERIOD/{n;s#value: 720h#value: 5m#;}' -e "/name: GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT/{n;s#value: 90m#value: $$browser_idle_timeout_value#;}" -e '/name: GOAUTHY_RFC8252_LOOPBACK_REDIRECTS/{n;s#value: "false"#value: "true"#;}' -e '/name: GOAUTHY_BOOTSTRAP_CLIENT_CREDENTIALS_TOKEN_LIFETIME/{n;s#value: 1h#value: 10s#;}' | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
	if [ "$(E2E_PROFILE)" = user-delete ] || [ "$${GOAUTHY_E2E_ACCOUNT_LIFECYCLE_UI:-0}" = 1 ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy GOAUTHY_ENABLE_SELF_DELETE=true; fi; \
	if [ "$${GOAUTHY_E2E_MACHINE_EXCHANGE:-0}" = 1 ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env --containers=goauthy statefulset/goauthy "GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB=$${GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB:-false}"; fi; \
	if [ "$${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env --containers=goauthy statefulset/goauthy 'GOAUTHY_DCR_ALLOWED_SCOPES=openid profile email groups goauthy.read offline_access'; fi; \
	if [ "$${GOAUTHY_E2E_EVENT_NOTIFICATIONS:-0}" = 1 ]; then [ "$(E2E_PROFILE)" = open-registration ] || { echo 'notification batch needs SMTP open-registration profile' >&2; exit 1; }; kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env --containers=goauthy statefulset/goauthy GOAUTHY_EVENT_NOTIFICATION_TARGETS=email GOAUTHY_EVENT_EMAIL_TO=events@goauthy.e2e GOAUTHY_EVENT_NOTIFICATION_EMAIL_LEVEL=info; fi; \
	if [ -n "$$policy_mode" ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env --containers=goauthy statefulset/goauthy GOAUTHY_USER_VALUES_GIVEN_NAME="$$policy_mode" GOAUTHY_USER_VALUES_FAMILY_NAME="$$policy_mode" GOAUTHY_USER_VALUES_BIRTHDATE="$$policy_mode" GOAUTHY_USER_VALUES_STREET="$$policy_mode" GOAUTHY_USER_VALUES_ZIP="$$policy_mode" GOAUTHY_USER_VALUES_CITY="$$policy_mode" GOAUTHY_USER_VALUES_COUNTRY="$$policy_mode" GOAUTHY_USER_VALUES_PHONE="$$policy_mode" GOAUTHY_USER_VALUES_TZ="$$policy_mode"; fi; \
	if [ "$$preferred_mode" = custom ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env --containers=goauthy statefulset/goauthy GOAUTHY_USER_VALUES_PREFERRED_USERNAME=required 'GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX=^Team_[0-9]{2}$$' 'GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST=["team_12"]' GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE=false 'GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML=^Team_[0-9]{2}$$' 'GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT=Team code'; fi; \
	if [ "$(E2E_PROFILE)" = ip-blacklist-events ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy GOAUTHY_IP_BLACKLIST_ENABLED=true GOAUTHY_TRUSTED_PROXIES=127.0.0.1/32,::1/128; fi; \
	if [ "$(E2E_PROFILE)" = passkey ] || [ "$(E2E_PROFILE)" = forced-mfa ] || [ "$(E2E_PROFILE)" = admin-passkey ] || [ "$(E2E_PROFILE)" = forward-auth ] || [ "$${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then \
		passkey_patch=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get statefulset/goauthy -o json | jq -ce -f deploy/k8s/passkey-secret-items-patch.jq); \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) patch statefulset/goauthy --type=json -p="$$passkey_patch"; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) patch statefulset/goauthy --type=strategic --patch-file=deploy/k8s/passkey-cookie-key-patch.yaml; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy GOAUTHY_PASSKEY_RP_ID=localhost GOAUTHY_PASSKEY_ORIGINS=http://localhost:$(E2E_PORT),http://localhost:$$(( $(E2E_PORT) + 1 )),http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_PASSKEY_KEY_FILE=/run/passkey/passkey-key GOAUTHY_PASSKEY_FORCE_UV=true $$forward_auth_env; \
	fi; \
	if [ "$(E2E_PROFILE)" = forced-mfa ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy GOAUTHY_BOOTSTRAP_FORCE_MFA=true; fi; \
	if [ "$(E2E_PROFILE)" = admin-passkey ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy "GOAUTHY_SSP_THRESHOLD=$${GOAUTHY_E2E_USER_LIST_THRESHOLD:-200}"; fi; \
	sed "s#image: goauthy-backchannel-sink:e2e\$$#image: $$GOAUTHY_BACKCHANNEL_SINK_IMAGE#" deploy/k8s/backchannel-sink.yaml | kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) apply -f -; \
	[ "$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get statefulset/goauthy -o jsonpath='{.spec.template.spec.containers[?(@.name=="goauthy")].image}')" = "$$GOAUTHY_IMAGE" ]; \
	[ "$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get deployment/goauthy-backchannel-sink -o jsonpath='{.spec.template.spec.containers[0].image}')" = "$$GOAUTHY_BACKCHANNEL_SINK_IMAGE" ]; \
	if [ "$(E2E_PROFILE)" = password-reset ] || [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ] || [ "$(E2E_PROFILE)" = self-attributes ] || [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then [ "$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get deployment/goauthy-smtp-sink -o jsonpath='{.spec.template.spec.containers[0].image}')" = "$$GOAUTHY_SMTP_SINK_IMAGE" ]; fi; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/versity --timeout=180s; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=complete job/versity-init --timeout=180s; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status deployment/goauthy-backchannel-sink --timeout=180s; \
	if [ "$(E2E_PROFILE)" = password-reset ] || [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ] || [ "$(E2E_PROFILE)" = self-attributes ] || [ "$${GOAUTHY_E2E_TOKEN_EXCHANGE_ACTOR:-0}" = 1 ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status deployment/goauthy-smtp-sink --timeout=180s; fi; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
	jwks_kid=; \
	wait_forward() { \
		pid=$$1; log=$$2; \
		for attempt in $$(seq 1 50); do \
			if grep -q '^Forwarding from 127.0.0.1:' "$$log"; then kill -0 "$$pid"; return; fi; \
			if ! kill -0 "$$pid" 2>/dev/null; then wait "$$pid" 2>/dev/null || true; cat "$$log" >&2; return 1; fi; \
			sleep 0.1; \
		done; \
		cat "$$log" >&2; return 1; \
	}; \
	run_smoke() { \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
		wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
		curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null; \
		GOAUTHY_E2E_MANAGED_CLIENTS=0 GOAUTHY_E2E_URL="$$e2e_issuer" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_CLIENT_CREDENTIALS_TOKEN_LIFETIME=10s GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_EXPECT_JWKS_KID=$$jwks_kid go test -count=1 ./test/e2e; \
		jwks_kid=$$(curl --fail --silent http://127.0.0.1:$(E2E_PORT)/oidc/jwks.json | jq -er '.keys[0].kid'); \
		kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
	}; \
	run_cross_pod() { \
		if [ "$(E2E_PROFILE)" = password-policy ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) set env statefulset/goauthy GOAUTHY_ARGON2_MEMORY_KIB=32768 GOAUTHY_ARGON2_ITERATIONS=3 GOAUTHY_ARGON2_PARALLELISM=2 GOAUTHY_ARGON2_MAX_CONCURRENCY=2; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
		fi; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-1 $$(( $(E2E_PORT) + 1 )):8080 >"$$temp_dir/secondary-forward.log" 2>&1 & secondary_forward=$$!; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-2 $$(( $(E2E_PORT) + 2 )):8080 >"$$temp_dir/tertiary-forward.log" 2>&1 & tertiary_forward=$$!; \
		wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
		wait_forward "$$secondary_forward" "$$temp_dir/secondary-forward.log"; \
		wait_forward "$$tertiary_forward" "$$temp_dir/tertiary-forward.log"; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 service/goauthy-backchannel-sink $$(( $(E2E_PORT) + 3 )):8081 >"$$temp_dir/quaternary-forward.log" 2>&1 & quaternary_forward=$$!; \
		wait_forward "$$quaternary_forward" "$$temp_dir/quaternary-forward.log"; \
		for attempt in $$(seq 1 30); do curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null && curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 1 ))/readyz >/dev/null && curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 2 ))/readyz >/dev/null && break; sleep 1; done; \
		curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null; curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 1 ))/readyz >/dev/null; curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 2 ))/readyz >/dev/null; \
		if [ "$(E2E_PROFILE)" = global-logout ]; then \
			export GOAUTHY_E2E_GLOBAL_LOGOUT_BACKCHANNEL=1 GOAUTHY_E2E_GLOBAL_LOGOUT_STATE="$$temp_dir/global-logout.json" GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )); \
			export GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple; \
			GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=prepare go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestGlobalLogoutBackchannel$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			GOAUTHY_E2E_GLOBAL_LOGOUT_PHASE=after-restart go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestGlobalLogoutBackchannel$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = backchannel-failure-events ]; then \
			export GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_STATE="$$temp_dir/backchannel-failure-event.json" GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )); \
			GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENTS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=8m ./test/e2e/browser -run '^TestBackchannelFailureEvents$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			GOAUTHY_E2E_BACKCHANNEL_FAILURE_EVENT_PERSISTENCE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=2m ./test/e2e/browser -run '^TestBackchannelFailureEventPersisted$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = ip-blacklist-events ]; then \
			export GOAUTHY_E2E_IP_BLACKLIST_EVENT_STATE="$$temp_dir/ip-blacklist-event.json" GOAUTHY_E2E_IP_BLACKLIST_TEST_IP=192.0.2.200; \
			GOAUTHY_E2E_IP_BLACKLIST_EVENTS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=4m ./test/e2e/browser -run '^TestIPBlacklistEvents$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			GOAUTHY_E2E_IP_BLACKLIST_EVENT_PERSISTENCE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=2m ./test/e2e/browser -run '^TestIPBlacklistEventPersisted$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = wall-clock-jwks ]; then \
			export GOAUTHY_E2E_JWKS_EVENT_STATE="$$temp_dir/jwks-event.json"; \
			GOAUTHY_E2E_JWKS_ROTATION_EVENTS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=10m ./test/e2e/browser -run '^TestJWKSRotationEvents$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			GOAUTHY_E2E_JWKS_EVENT_PERSISTENCE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v -timeout=2m ./test/e2e/browser -run '^TestJWKSRotationEventPersisted$$'; \
			return; \
		fi; \
			if [ "$(E2E_PROFILE)" = backchannel-https ]; then \
				GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=https://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_BACKCHANNEL_SINK_CA_FILE="$$temp_dir/backchannel-ca.crt" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestBackchannelLogoutDeliveryFailureModesAcrossPods$$'; \
				goauthy_pod_uids_before=$$(for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod $$pod -o jsonpath='{.metadata.uid}'; done); \
				openssl genrsa -out "$$temp_dir/backchannel-rotated-ca.key" 2048 >/dev/null 2>&1; \
				openssl req -x509 -new -sha256 -key "$$temp_dir/backchannel-rotated-ca.key" -out "$$temp_dir/backchannel-rotated-ca.crt" -days 1 -subj '/CN=GoAuthy Backchannel E2E Rotated Test CA' >/dev/null 2>&1; \
				openssl req -new -newkey rsa:2048 -nodes -keyout "$$temp_dir/backchannel-rotated-sink.key" -out "$$temp_dir/backchannel-rotated-sink.csr" -subj '/CN=goauthy-backchannel-sink.goauthy.svc.cluster.local' -addext 'subjectAltName=DNS:goauthy-backchannel-sink.goauthy.svc,DNS:goauthy-backchannel-sink.goauthy.svc.cluster.local,IP:127.0.0.1' >/dev/null 2>&1; \
				openssl x509 -req -in "$$temp_dir/backchannel-rotated-sink.csr" -CA "$$temp_dir/backchannel-rotated-ca.crt" -CAkey "$$temp_dir/backchannel-rotated-ca.key" -CAcreateserial -out "$$temp_dir/backchannel-rotated-sink.crt" -days 1 -sha256 -copy_extensions copy >/dev/null 2>&1; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create secret generic goauthy-backchannel-ca --from-file=ca.crt="$$temp_dir/backchannel-rotated-ca.crt" --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) create secret generic goauthy-backchannel-sink-tls --from-file=tls.crt="$$temp_dir/backchannel-rotated-sink.crt" --from-file=tls.key="$$temp_dir/backchannel-rotated-sink.key" --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout restart deployment/goauthy-backchannel-sink; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status deployment/goauthy-backchannel-sink --timeout=180s; \
				goauthy_pod_uids_after=$$(for pod in goauthy-0 goauthy-1 goauthy-2; do kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod $$pod -o jsonpath='{.metadata.uid}'; done); test "$$goauthy_pod_uids_before" = "$$goauthy_pod_uids_after"; \
				GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=https://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_BACKCHANNEL_SINK_CA_FILE="$$temp_dir/backchannel-rotated-ca.crt" GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestBackchannelLogoutDeliveryFailureModesAcrossPods$$'; \
				return; \
			fi; \
			if [ "$(E2E_PROFILE)" = forward-auth ]; then \
				GOAUTHY_E2E_PASSKEY=1 GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin@goauthy.e2e GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin go test -count=1 ./test/e2e/passkey -run '^TestPasskeyVirtualAuthenticatorAcrossPods$$'; \
				GOAUTHY_E2E_FORWARD_AUTH_HEADERS=1 GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin@goauthy.e2e GOAUTHY_E2E_BROWSER_PASSWORD=ReversedPassword2 GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestForwardAuthIdentityHeadersAcrossPods$$'; \
				old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
				kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
				new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
				wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
				curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null; \
				GOAUTHY_E2E_FORWARD_AUTH_HEADERS=1 GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin@goauthy.e2e GOAUTHY_E2E_BROWSER_PASSWORD=ReversedPassword2 GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestForwardAuthIdentityHeadersAcrossPods$$'; \
				return; \
			fi; \
		if [ "$(E2E_PROFILE)" = password-policy ]; then \
			GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestPasswordPolicyRolloutAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = password-lifecycle ]; then \
			GOAUTHY_E2E_PASSWORD_LIFECYCLE_PHASE=before-restart GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestPasswordLifecycleAcrossPods$$'; \
			kill $$secondary_forward >/dev/null 2>&1 || true; wait $$secondary_forward 2>/dev/null || true; secondary_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-1 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-1 --timeout=180s; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-1 $$(( $(E2E_PORT) + 1 )):8080 >"$$temp_dir/secondary-forward.log" 2>&1 & secondary_forward=$$!; \
			wait_forward "$$secondary_forward" "$$temp_dir/secondary-forward.log"; \
			GOAUTHY_E2E_PASSWORD_LIFECYCLE_PHASE=after-restart GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestPasswordLifecycleAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = password-reset ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 service/goauthy-smtp-sink $$(( $(E2E_PORT) + 4 )):8082 >"$$temp_dir/smtp-forward.log" 2>&1 & quinary_forward=$$!; \
			wait_forward "$$quinary_forward" "$$temp_dir/smtp-forward.log"; \
			GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_BROWSER_EMAIL=admin@goauthy.e2e GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestPasswordResetAcrossPods$$'; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod/goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			GOAUTHY_E2E_RESET_EVENT_PERSISTENCE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=Reset-Password-1A GOAUTHY_E2E_BROWSER_EMAIL=admin@goauthy.e2e GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestPasswordResetEventPersisted$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = open-registration ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 service/goauthy-smtp-sink $$(( $(E2E_PORT) + 4 )):8082 >"$$temp_dir/smtp-forward.log" 2>&1 & quinary_forward=$$!; \
			wait_forward "$$quinary_forward" "$$temp_dir/smtp-forward.log"; \
			if [ "$${GOAUTHY_E2E_MANAGED_CLIENTS:-0}" = 1 ] || [ "$${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ] || [ "$${GOAUTHY_E2E_AUTH_COLLECTIONS:-0}" = 1 ] || [ "$${GOAUTHY_E2E_AUTH_COLLECTIONS_UI:-0}" = 1 ] || [ "$${GOAUTHY_E2E_MANAGED_CLIENTS_UI:-0}" = 1 ]; then \
				pilot_host=127.0.0.1; pilot_tests='^Test(ManagedClientsHTTPWorkflow|DeviceAuthorizationBrowserLogin|DeviceAuthorizationPublicBrowserLogin|AuthCollectionsAcrossPods|AuthCollectionsUIAcrossPods|ManagedClientsUIAcrossPods)$$'; \
				if [ "$${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then pilot_host=localhost; pilot_tests="$$pilot_tests|^TestAccountPasskeyUIAcrossPods$$"; fi; \
				export GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )); \
				export GOAUTHY_E2E_URL=http://$$pilot_host:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://$$pilot_host:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://$$pilot_host:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple; \
				export GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef; \
				go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e ./test/e2e/browser -run "$$pilot_tests"; \
				old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
				if [ "$${GOAUTHY_E2E_AUTH_COLLECTIONS:-0}" = 1 ]; then GOAUTHY_E2E_AUTH_COLLECTIONS_CHAOS=1 GOAUTHY_E2E_CHAOS_CONTEXT=kind-$(KIND_CLUSTER) GOAUTHY_E2E_CHAOS_NAMESPACE=$(K8S_NAMESPACE) GOAUTHY_E2E_CHAOS_DELETE_POD=goauthy-0 GOAUTHY_E2E_CHAOS_POD_PREFIX=goauthy- go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e/browser -run '^TestAuthCollectionsAcrossPods$$'; fi; \
				kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
				if [ "$${GOAUTHY_E2E_AUTH_COLLECTIONS:-0}" != 1 ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; fi; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
				new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
				go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e ./test/e2e/browser -run "$$pilot_tests"; \
				if [ "$${GOAUTHY_E2E_MANAGED_CLIENTS_UI:-0}" = 1 ]; then \
					GOAUTHY_E2E_MANAGED_DEVICE_CHAOS=1 GOAUTHY_E2E_CHAOS_CONTEXT=kind-$(KIND_CLUSTER) GOAUTHY_E2E_CHAOS_NAMESPACE=$(K8S_NAMESPACE) GOAUTHY_E2E_CHAOS_DELETE_POD=goauthy-0 GOAUTHY_E2E_CHAOS_POD_PREFIX=goauthy- go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e/browser -run '^TestManagedDevicePendingGrantSurvivesPodReplacement$$'; \
					kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
					kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
				fi; \
				if [ "$${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ]; then GOAUTHY_E2E_DEVICE_PENDING_CHAOS=1 GOAUTHY_E2E_CHAOS_CONTEXT=kind-$(KIND_CLUSTER) GOAUTHY_E2E_CHAOS_NAMESPACE=$(K8S_NAMESPACE) GOAUTHY_E2E_CHAOS_DELETE_POD=goauthy-0 GOAUTHY_E2E_CHAOS_POD_PREFIX=goauthy- go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e/chaos -run '^TestDevicePendingGrantSurvivesPodReplacement$$'; fi; \
				echo 'HA selected client/device/collection pilot and post-replacement workflow passed'; \
				return; \
			fi; \
			if [ "$${GOAUTHY_E2E_PROFILE_CLAIMS:-0}" = 1 ]; then \
				batch_host=127.0.0.1; if [ "$${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then batch_host=localhost; fi; \
				export GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_URL=http://$$batch_host:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://$$batch_host:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://$$batch_host:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple; \
				if [ "$${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then export GOAUTHY_E2E_TOKEN_EVENT_FILE="$$temp_dir/token-events.json"; fi; \
				GOAUTHY_E2E_ADMIN_UI=1 go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e/browser -run '^Test(TokenIssuedEvents|ProfileClaimsLive|AdminUIHTTPAcrossPods|AdminUIBrowserAcrossPods|EventNotificationsAcrossPods|AccountDashboardAcrossPods|AdminAPIKeyUIAcrossPods|AdminCatalogSessionsUIAcrossPods|AccountPasskeyUIAcrossPods|AccountLifecycleUIAcrossPods)$$'; \
				if [ "$${GOAUTHY_E2E_EVENT_NOTIFICATIONS:-0}" = 1 ] || [ "$${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then \
					old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
					kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
					kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
					kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
					kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
					new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
					kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
					go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^Test(EventNotificationsAcrossPods|TokenIssuedEventsPersisted)$$'; \
					echo 'HA feature batch and event Pod replacement E2E passed'; \
				fi; \
				return; \
			fi; \
			if [ -n "$$policy_mode" ] || [ -n "$$preferred_mode" ]; then \
				test_prefix=UserValuesPolicy; policy_label="user-values $$policy_mode"; \
				if [ -n "$$preferred_mode" ]; then test_prefix=PreferredUsernamePolicy; policy_label="preferred-username $$preferred_mode"; fi; \
				if [ -n "$$policy_mode" ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pods goauthy-0 goauthy-1 goauthy-2 -o json | jq -e --arg mode "$$policy_mode" '[.items[].spec.containers[] | select(.name == "goauthy") | [.env[] | select(.name | startswith("GOAUTHY_USER_VALUES_"))]] | length == 3 and all(.[]; length == 9 and all(.[]; .value == $$mode))' >/dev/null; fi; \
				if [ -n "$$preferred_mode" ]; then kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pods goauthy-0 goauthy-1 goauthy-2 -o json | jq -e --arg mode "$$preferred_mode" '[.items[].spec.containers[] | select(.name == "goauthy") | [.env[] | select(.name | startswith("GOAUTHY_USER_VALUES_PREFERRED_USERNAME"))] | map({key:.name,value:.value}) | from_entries] | length == 3 and all(.[]; if $$mode == "default" then length == 0 else . == {"GOAUTHY_USER_VALUES_PREFERRED_USERNAME":"required","GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX":"^Team_[0-9]{2}$$","GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST":"[\"team_12\"]","GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE":"false","GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML":"^Team_[0-9]{2}$$","GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT":"Team code"} end)' >/dev/null; fi; \
				export GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple; \
				go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^Test$${test_prefix}AcrossPods\$$"; \
				old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
				kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
				new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
				go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^Test$${test_prefix}Persisted\$$"; \
				echo "HA $$policy_label policy and Pod replacement E2E passed"; \
				return; \
			fi; \
			if [ "$${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" = 1 ] || [ "$${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" = 1 ]; then \
				export GOAUTHY_E2E_FORCE_LOGOUT_STATE="$$temp_dir/force-logout.json" GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )); \
				export GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple; \
				logout_test=TestForceLogoutBackchannel; logout_phase_key=GOAUTHY_E2E_FORCE_LOGOUT_PHASE; logout_phases=after-restart; \
				if [ "$${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" = 1 ]; then logout_test=TestUserDeleteBackchannel; logout_phase_key=GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_PHASE; logout_phases='after-restart after-delete-restart'; export GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_STATE="$$temp_dir/user-delete.json"; fi; \
				env "$$logout_phase_key=prepare" go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^$$logout_test\$$"; \
				for logout_phase in $$logout_phases; do \
				old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
				kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 pod/goauthy-1 pod/goauthy-2 --timeout=180s; \
				new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
				kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
				env "$$logout_phase_key=$$logout_phase" go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^$$logout_test\$$"; \
				done; \
				return; \
			fi; \
			GOAUTHY_E2E_ADMIN_USER_CREATE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^Test(OpenRegistrationAcrossPods|AdminUserCreateLifecycle|AdminUserUpdateAcrossPods)$$'; \
			GOAUTHY_E2E_EVENTS_STREAM=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestCreationEventsStream$$'; \
			GOAUTHY_E2E_EVENT_TEST=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestEventTestEndpoint$$'; \
			GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_OPEN_REG_EMAIL=chaos-open@goauthy.e2e GOAUTHY_E2E_CHAOS_CONTEXT=kind-$(KIND_CLUSTER) GOAUTHY_E2E_CHAOS_NAMESPACE=$(K8S_NAMESPACE) GOAUTHY_E2E_CHAOS_DELETE_POD=goauthy-0 go test -count=1 -v ./test/e2e/chaos -run '^TestOpenRegistrationPendingPasswordSurvivesPodReplacement$$'; \
			GOAUTHY_E2E_EVENTS_PERSISTENCE=1 GOAUTHY_E2E_EVENT_TEST_PERSISTENCE=1 GOAUTHY_E2E_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^Test(CreationEventsPersisted|EventTestPersisted|AdminUserUpdatePersisted)$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = user-delete ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 service/goauthy-smtp-sink $$(( $(E2E_PORT) + 4 )):8082 >"$$temp_dir/smtp-forward.log" 2>&1 & quinary_forward=$$!; \
			wait_forward "$$quinary_forward" "$$temp_dir/smtp-forward.log"; \
			GOAUTHY_E2E_USER_DELETE_PHASE=before-replacement GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestUserDeletionAcrossPods$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
			wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null; \
			curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 1 ))/readyz >/dev/null; \
			curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 2 ))/readyz >/dev/null; \
			GOAUTHY_E2E_USER_DELETE_PHASE=after-replacement GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestUserDeletionAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = self-attributes ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 service/goauthy-smtp-sink $$(( $(E2E_PORT) + 4 )):8082 >"$$temp_dir/smtp-forward.log" 2>&1 & quinary_forward=$$!; \
			wait_forward "$$quinary_forward" "$$temp_dir/smtp-forward.log"; \
			GOAUTHY_E2E_SELF_ATTRIBUTES=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_SMTP_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 4 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestUserAttributesAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = roles-groups ]; then \
			GOAUTHY_E2E_ROLES_GROUPS_PHASE=before-replacement GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestRolesGroupsAcrossPods$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-0 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-0 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-0 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
			wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
			curl --fail --silent http://127.0.0.1:$(E2E_PORT)/readyz >/dev/null; \
			curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 1 ))/readyz >/dev/null; \
			curl --fail --silent http://127.0.0.1:$$(( $(E2E_PORT) + 2 ))/readyz >/dev/null; \
			GOAUTHY_E2E_ROLES_GROUPS_PHASE=after-replacement GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestRolesGroupsAcrossPods$$'; \
			GOAUTHY_E2E_ROLES_GROUPS_PHASE=claims GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestRolesGroupsAcrossPods$$'; \
			GOAUTHY_E2E_CLIENT_GROUP_RESTRICTION=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestBootstrapClientGroupRestrictionAcrossPods$$'; \
			GOAUTHY_E2E_USER_ATTRIBUTES=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestUserAttributesAcrossPods$$'; \
			GOAUTHY_E2E_CUSTOM_CLAIMS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestCustomClaimsAcrossPods$$'; \
			GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS=1 GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS_CLIENT_ID=goauthy-dev GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestBootstrapClientCredentialsClaimsAcrossPods$$'; \
			GOAUTHY_E2E_ADMIN_API_KEYS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestAdminAPIKeysAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = client-credentials-claims ]; then \
			GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS=1 GOAUTHY_E2E_CLIENT_CREDENTIALS_CLAIMS_CLIENT_ID=goauthy-dev GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestBootstrapClientCredentialsClaimsAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = default-aud ]; then \
			GOAUTHY_E2E_RESOURCE_INDICATORS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestAuthorizationCodeResourceIndicatorAcrossPods$$'; \
			GOAUTHY_E2E_DEFAULT_AUD_PHASE=before-replacement GOAUTHY_E2E_DEFAULT_AUD_STATE="$$temp_dir/default-aud.json" GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestDefaultResourceAudienceAcrossPods$$'; \
			old_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-1 -o jsonpath='{.metadata.uid}'); test -n "$$old_pod_uid"; \
			kill $$secondary_forward >/dev/null 2>&1 || true; wait $$secondary_forward 2>/dev/null || true; secondary_forward=; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-1 --wait=true; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=condition=ready pod/goauthy-1 --timeout=180s; \
			new_pod_uid=$$(kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) get pod goauthy-1 -o jsonpath='{.metadata.uid}'); test -n "$$new_pod_uid" && test "$$new_pod_uid" != "$$old_pod_uid"; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-1 $$(( $(E2E_PORT) + 1 )):8080 >"$$temp_dir/secondary-forward.log" 2>&1 & secondary_forward=$$!; wait_forward "$$secondary_forward" "$$temp_dir/secondary-forward.log"; \
			GOAUTHY_E2E_DEFAULT_AUD_PHASE=after-replacement GOAUTHY_E2E_DEFAULT_AUD_STATE="$$temp_dir/default-aud.json" GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestDefaultResourceAudienceAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = admin-api-keys ]; then \
			GOAUTHY_E2E_ADMIN_API_KEYS=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestAdminAPIKeysAcrossPods$$'; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = passkey ]; then \
			GOAUTHY_E2E_PASSKEY=1 GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin go test -count=1 ./test/e2e/passkey; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = forced-mfa ]; then \
			GOAUTHY_E2E_PASSKEY=1 GOAUTHY_E2E_PASSKEY_CASE=forced-mfa GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin go test -count=1 ./test/e2e/passkey; \
			return; \
		fi; \
		if [ "$(E2E_PROFILE)" = admin-passkey ]; then \
			GOAUTHY_E2E_ADMIN_PASSKEY=1 GOAUTHY_E2E_URL=http://localhost:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://localhost:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://localhost:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin go test -count=1 ./test/e2e/passkey -run '^TestAdminPasskeyManagementAcrossPods$$'; \
			return; \
		fi; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -run '^TestTokenExchangeAcrossPods$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_RFC8252_LOOPBACK_REDIRECTS=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -run '^TestRFC8252LoopbackDynamicClientAcrossPods$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 ./test/e2e/browser -run '^TestForwardAuthAcrossPods$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -run '^TestDPoPAuthorizationCodeRefreshAndUserInfoAcrossPods$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -run '^TestDeviceAuthorizationAcrossPods$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef go test -count=1 ./test/e2e -run '^(TestCrossPodRevocation|TestDynamicClientRegistrationAcrossPods)$$'; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -skip '^(TestTokenExchangeAcrossPods|TestRFC8252LoopbackDynamicClientAcrossPods|TestForwardAuthAcrossPods|TestLoginBruteForceBlockAcrossPods|TestDPoPAuthorizationCodeRefreshAndUserInfoAcrossPods|TestDeviceAuthorizationAcrossPods)$$'; \
		GOAUTHY_E2E_JWKS_ROTATION=1 GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) go test -count=1 ./test/e2e/jwks; \
		check_credential_continuity prepare http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) http://127.0.0.1:$$(( $(E2E_PORT) + 2 )); \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )) GOAUTHY_E2E_TERTIARY_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )) GOAUTHY_E2E_BACKCHANNEL_SINK_URL=http://127.0.0.1:$$(( $(E2E_PORT) + 3 )) GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_LOGIN_BLOCK=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SESSION_IDLE_TIMEOUT=10s GOAUTHY_E2E_POST_LOGOUT_REDIRECT_URI='http://localhost:5555/logout?from=goauthy' go test -count=1 ./test/e2e/browser -run '^TestLoginBruteForceBlockAcrossPods$$'; \
		kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
		kill $$secondary_forward >/dev/null 2>&1 || true; wait $$secondary_forward 2>/dev/null || true; secondary_forward=; \
		kill $$tertiary_forward >/dev/null 2>&1 || true; wait $$tertiary_forward 2>/dev/null || true; tertiary_forward=; \
		kill $$quaternary_forward >/dev/null 2>&1 || true; wait $$quaternary_forward 2>/dev/null || true; quaternary_forward=; \
	}; \
	check_credential_continuity() { \
		if [ "$${GOAUTHY_E2E_DPOP_CONTINUITY:-0}" = 1 ] && [ "$$1" != cleanup ]; then GOAUTHY_E2E_DPOP_CONTINUITY_PHASE=$$1 GOAUTHY_E2E_DPOP_CONTINUITY_FILE="$$temp_dir/dpop-continuity.json" GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=$$2 GOAUTHY_E2E_TERTIARY_URL=$$3 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestDPoPContinuityLive$$'; fi; \
		if [ "$${GOAUTHY_E2E_DCR_DPOP_CONTINUITY:-0}" = 1 ]; then GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_E2E_DPOP_CONTINUITY_PHASE=$$1 GOAUTHY_E2E_DPOP_CONTINUITY_FILE="$$temp_dir/dpop-dynamic-continuity.json" GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=$$2 GOAUTHY_E2E_TERTIARY_URL=$$3 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestDynamicDPoPContinuityLive$$'; fi; \
		if [ "$${GOAUTHY_E2E_ACTOR_CONTINUITY:-0}" = 1 ]; then GOAUTHY_E2E_ACTOR_CONTINUITY_PHASE=$$1 GOAUTHY_E2E_ACTOR_CONTINUITY_FILE="$$temp_dir/actor-continuity.json" GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_SECONDARY_URL=$$2 GOAUTHY_E2E_TERTIARY_URL=$$3 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD="$$browser_password" GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple go test -count=1 -v ./test/e2e/browser -run '^TestActorContinuityLive$$'; fi; \
	}; \
	run_credential_continuity() { \
		case "$${GOAUTHY_E2E_DPOP_CONTINUITY:-0}" in 0) [ "$${GOAUTHY_E2E_ACTOR_CONTINUITY:-0}" = 1 ] || return;; 1) ;; *) echo 'GOAUTHY_E2E_DPOP_CONTINUITY must be 0 or 1' >&2; return 1;; esac; \
		[ "$(E2E_PROFILE)" = full ] || { echo 'credential continuity requires the full Kind profile' >&2; return 1; }; \
		continuity_phase=$$1; \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
		wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
		continuity_secondary=http://127.0.0.1:$(E2E_PORT); continuity_tertiary=$$continuity_secondary; \
		if [ "$$continuity_phase" != unavailable ]; then \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-1 $$(( $(E2E_PORT) + 1 )):8080 >"$$temp_dir/secondary-forward.log" 2>&1 & secondary_forward=$$!; \
			kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-2 $$(( $(E2E_PORT) + 2 )):8080 >"$$temp_dir/tertiary-forward.log" 2>&1 & tertiary_forward=$$!; \
			wait_forward "$$secondary_forward" "$$temp_dir/secondary-forward.log"; wait_forward "$$tertiary_forward" "$$temp_dir/tertiary-forward.log"; \
			continuity_secondary=http://127.0.0.1:$$(( $(E2E_PORT) + 1 )); continuity_tertiary=http://127.0.0.1:$$(( $(E2E_PORT) + 2 )); \
		fi; \
		check_credential_continuity "$$continuity_phase" "$$continuity_secondary" "$$continuity_tertiary"; \
		kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
		if [ -n "$$secondary_forward" ]; then kill $$secondary_forward >/dev/null 2>&1 || true; wait $$secondary_forward 2>/dev/null || true; secondary_forward=; fi; \
		if [ -n "$$tertiary_forward" ]; then kill $$tertiary_forward >/dev/null 2>&1 || true; wait $$tertiary_forward 2>/dev/null || true; tertiary_forward=; fi; \
	}; \
	run_fail_closed() { \
		kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) port-forward --address=127.0.0.1 pod/goauthy-0 $(E2E_PORT):8080 >"$$temp_dir/port-forward.log" 2>&1 & port_forward=$$!; \
		wait_forward "$$port_forward" "$$temp_dir/port-forward.log"; \
		GOAUTHY_E2E_URL=http://127.0.0.1:$(E2E_PORT) GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_EXPECT_NOT_READY=true go test -count=1 ./test/e2e -run '^TestCurrentProfile$$'; \
		kill $$port_forward >/dev/null 2>&1 || true; wait $$port_forward 2>/dev/null || true; port_forward=; \
	}; \
	if [ "$(E2E_PROFILE)" != backchannel-https ] && [ "$(E2E_PROFILE)" != passkey ] && [ "$(E2E_PROFILE)" != forced-mfa ] && [ "$(E2E_PROFILE)" != admin-passkey ] && [ "$(E2E_PROFILE)" != forward-auth ] && [ "$(E2E_PROFILE)" != client-credentials-claims ] && [ "$(E2E_PROFILE)" != admin-api-keys ] && [ "$(E2E_PROFILE)" != default-aud ]; then run_smoke; fi; \
	run_cross_pod; \
	if [ "$(E2E_PROFILE)" = wall-clock-jwks ]; then exit 0; fi; \
	if [ "$(E2E_PROFILE)" = ip-blacklist-events ]; then exit 0; fi; \
	if [ "$(E2E_PROFILE)" = backchannel-failure-events ]; then exit 0; fi; \
	if [ "$(E2E_PROFILE)" = global-logout ]; then exit 0; fi; \
	if [ "$(E2E_PROFILE)" = backchannel-https ] || [ "$(E2E_PROFILE)" = forward-auth ] || [ "$(E2E_PROFILE)" = password-policy ] || [ "$(E2E_PROFILE)" = password-lifecycle ] || [ "$(E2E_PROFILE)" = password-reset ] || [ "$(E2E_PROFILE)" = open-registration ] || [ "$(E2E_PROFILE)" = user-delete ] || [ "$(E2E_PROFILE)" = roles-groups ] || [ "$(E2E_PROFILE)" = client-credentials-claims ] || [ "$(E2E_PROFILE)" = admin-api-keys ] || [ "$(E2E_PROFILE)" = self-attributes ] || [ "$(E2E_PROFILE)" = passkey ] || [ "$(E2E_PROFILE)" = forced-mfa ] || [ "$(E2E_PROFILE)" = admin-passkey ]; then exit 0; fi; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) delete pod goauthy-2 --wait=true; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
	run_smoke; \
	run_credential_continuity verify; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) scale statefulset/goauthy --replicas=1; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=delete pod/goauthy-1 --timeout=60s; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) wait --for=delete pod/goauthy-2 --timeout=60s; \
	run_fail_closed; \
	run_credential_continuity unavailable; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) scale statefulset/goauthy --replicas=3; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
	run_smoke; \
	run_credential_continuity verify; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout restart statefulset/goauthy; \
	kubectl --context kind-$(KIND_CLUSTER) -n $(K8S_NAMESPACE) rollout status statefulset/goauthy --timeout=180s; \
	run_smoke; \
	run_credential_continuity verify; \
	if [ "$${GOAUTHY_E2E_DCR_DPOP_CONTINUITY:-0}" = 1 ] || [ "$${GOAUTHY_E2E_ACTOR_CONTINUITY:-0}" = 1 ]; then run_credential_continuity cleanup; fi; \
	cleanup

.PHONY: e2e-standalone-generated-bootstrap e2e-kind-generated-bootstrap

e2e-standalone-generated-bootstrap:
	./scripts/e2e-generated-bootstrap-standalone.sh

e2e-kind-generated-bootstrap:
	$(e2e_kind_inputs) ./scripts/e2e-generated-bootstrap-kind.sh

.PHONY: e2e-standalone-generated-bootstrap-expiry

e2e-standalone-generated-bootstrap-expiry:
	GOAUTHY_E2E_GENERATED_EXPIRY=1 ./scripts/e2e-generated-bootstrap-standalone.sh

.PHONY: e2e-standalone-backup-restore-expiry

e2e-standalone-backup-restore-expiry:
	GOAUTHY_E2E_GENERATED_EXPIRY=1 GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT="$(GOAUTHY_STANDALONE_BACKUP_SOURCE_PORT)" GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT="$(GOAUTHY_STANDALONE_BACKUP_RESTORE_PORT)" ./scripts/e2e-standalone-backup-restore.sh

.PHONY: e2e-kind-generated-bootstrap-expiry

.PHONY: e2e-kind-backup-restore-expiry

e2e-kind-backup-restore-expiry:
	GOAUTHY_E2E_GENERATED_EXPIRY=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-no-pvc-crash-recovery

e2e-kind-no-pvc-crash-recovery:
	GOAUTHY_E2E_ALL_VOTERS_CRASH=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-object-store-outage

e2e-kind-object-store-outage:
	GOAUTHY_E2E_OBJECT_STORE_OUTAGE=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-archive-corruption
e2e-kind-archive-corruption:
	GOAUTHY_E2E_ARCHIVE_CORRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-archive-missing-blocks
e2e-kind-archive-missing-blocks:
	GOAUTHY_E2E_ARCHIVE_MISSING_BLOCKS=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-archive-block-corruption
e2e-kind-archive-block-corruption:
	GOAUTHY_E2E_ARCHIVE_BLOCK_CORRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-checkpoint-corruption
e2e-kind-checkpoint-corruption:
	GOAUTHY_E2E_CHECKPOINT_CORRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-checkpoint-root-corruption
e2e-kind-checkpoint-root-corruption:
	GOAUTHY_E2E_CHECKPOINT_ROOT_CORRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-checkpoint-block-corruption
e2e-kind-checkpoint-block-corruption:
	GOAUTHY_E2E_CHECKPOINT_BLOCK_CORRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-checkpoint-interruption
e2e-kind-checkpoint-interruption:
	GOAUTHY_E2E_CHECKPOINT_INTERRUPTION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-checkpoint-interruption-fresh-pods
e2e-kind-checkpoint-interruption-fresh-pods:
	GOAUTHY_E2E_CHECKPOINT_INTERRUPTION=1 GOAUTHY_E2E_CHECKPOINT_INTERRUPTION_REPLACE_PODS=1 $(MAKE) e2e-kind-backup-restore

.PHONY: docker-checkpoint-fault
docker-checkpoint-fault:
	docker build --target checkpoint-fault --tag "$(GOAUTHY_CHECKPOINT_FAULT_IMAGE)" .

.PHONY: test-no-pvc-journal-linux
test-no-pvc-journal-linux:
	./scripts/e2e-preflight.sh host-capacity
	docker build --target journal-test --tag goauthy-journal-test:e2e .
	docker run --rm --read-only --network=none --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:exec,size=512m goauthy-journal-test:e2e

.PHONY: test-e2e-journal-oracles
test-e2e-journal-oracles:
	sh scripts/test-e2e-journal-oracles.sh

.PHONY: e2e-kind-journal-interruption
e2e-kind-journal-interruption: test-e2e-journal-oracles
	GOAUTHY_E2E_JOURNAL_INTERRUPTION_PHASE="$${GOAUTHY_E2E_JOURNAL_INTERRUPTION_PHASE:-sqlite-installed}" $(MAKE) e2e-kind-backup-restore

e2e-kind-generated-bootstrap-expiry:
	$(e2e_kind_inputs) GOAUTHY_E2E_GENERATED_EXPIRY=1 ./scripts/e2e-generated-bootstrap-kind.sh

.PHONY: e2e-kind-generated-bootstrap-quorum

e2e-kind-generated-bootstrap-quorum:
	$(e2e_kind_inputs) GOAUTHY_E2E_GENERATED_QUORUM=1 ./scripts/e2e-generated-bootstrap-kind.sh

.PHONY: test-no-pvc-export-gc
test-no-pvc-export-gc:
	GOAUTHY_EXPORT_GC_TEST=1 go test -race -count=1 -timeout=6m ./internal/storage -run '^TestNoPVCPublicRhizaSnapshotCapture$$'

.PHONY: test-no-pvc-export-s3
test-no-pvc-export-s3:
	sh scripts/e2e-no-pvc-s3.sh export

.PHONY: test-backup-operator-s3
test-backup-operator-s3:
	sh scripts/e2e-no-pvc-s3.sh operator

.PHONY: test-backup-scheduled-s3
test-backup-scheduled-s3:
	sh scripts/e2e-no-pvc-s3.sh scheduled

.PHONY: e2e-kind-backup-scheduled
e2e-kind-backup-scheduled:
	GOAUTHY_E2E_SCHEDULED_BACKUP=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-backup-scheduled-outage
e2e-kind-backup-scheduled-outage:
	GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_OUTAGE=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-backup-scheduled-quorum
e2e-kind-backup-scheduled-quorum:
	GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_QUORUM=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-backup-scheduled-rotation
e2e-kind-backup-scheduled-rotation:
	GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_ROTATION=1 $(MAKE) e2e-kind-backup-restore

.PHONY: test-backup-checkpoint-busy-s3
test-backup-checkpoint-busy-s3:
	sh scripts/e2e-no-pvc-s3.sh checkpoint-busy

.PHONY: e2e-kind-backup-scheduled-pause
e2e-kind-backup-scheduled-pause:
	GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER=1 $(MAKE) e2e-kind-backup-restore

.PHONY: e2e-kind-backup-expire-all
e2e-kind-backup-expire-all:
	GOAUTHY_E2E_BACKUP_EXPIRE_ALL=1 $(MAKE) e2e-kind-backup-restore
