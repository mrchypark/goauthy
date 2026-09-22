#!/bin/sh
# Runs the open-registration lifecycle against one standalone GoAuthy node and
# a disposable local SMTP sink.
set -eu

# Parse the entire script before provisioning: shells may otherwise execute
# earlier commands before discovering a malformed quote near the end.
sh -n "$0"

if [ "${GOAUTHY_E2E_DEVICE_DPOP:-0}" = 1 ]; then
	[ "${GOAUTHY_E2E_TERNAL_DEVICE:-0}" != 1 ] && [ "${GOAUTHY_E2E_AUTHCODE_NATIVE_UI:-0}" != 1 ] || { echo 'Device DPoP requires a separate selected consumer fixture' >&2; exit 1; }
fi

if [ "${GOAUTHY_E2E_TERNAL_DEVICE:-0}" = 1 ]; then
	[ "$(uname -s)" = Linux ] || { echo 'Ternal Device CLI fixture requires Linux; native macOS/Windows config isolation is unsupported' >&2; exit 1; }
	case "${GOAUTHY_E2E_TERNAL_PROJECT_DIR:-}" in /*) ;; *) echo 'Ternal Device checkout must be an absolute path' >&2; exit 1;; esac
	[ -f "$GOAUTHY_E2E_TERNAL_PROJECT_DIR/cmd/ternal-api/main.go" ] && [ -f "$GOAUTHY_E2E_TERNAL_PROJECT_DIR/cmd/ternalctl/main.go" ] || { echo 'Ternal API/CLI source is missing' >&2; exit 1; }
	[ "${GOAUTHY_E2E_REGISTERED_OAUTH2:-0}" != 1 ] && [ "${GOAUTHY_E2E_COMPOS:-0}" != 1 ] && [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" != 1 ] && [ "${GOAUTHY_E2E_BEESUH:-0}" != 1 ] || { echo 'Ternal Device requires a separate consumer fixture' >&2; exit 1; }
	export GOAUTHY_BOOTSTRAP_USER_GROUPS='["ternal-admins","operators"]'
fi

if [ -n "${GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR:-}" ]; then
	case "$GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR" in /*) ;; *) echo 'Beesuh delivery checkout must be an absolute path' >&2; exit 1;; esac
	[ "${GOAUTHY_E2E_TLS:-0}" = 1 ] && [ "${GOAUTHY_E2E_USE_GRANTS:-0}" = 1 ] && [ "${GOAUTHY_E2E_CREDENTIAL_DELIVERY:-0}" = 1 ] && [ "${GOAUTHY_E2E_RAW_AUTHORIZATION:-0}" != 1 ] && [ -z "${GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR:-}" ] || { echo 'Beesuh delivery requires TLS, USE_GRANTS, CREDENTIAL_DELIVERY and a separate Bearer-prefix fixture' >&2; exit 1; }
	[ -f "$GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR/goauthy_delivery_integration_test.go" ] || { echo 'Beesuh delivery live harness is missing' >&2; exit 1; }
fi

if [ -n "${GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR:-}" ]; then
	case "$GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR" in /*) ;; *) echo 'Conductor delivery checkout must be an absolute path' >&2; exit 1;; esac
	[ "${GOAUTHY_E2E_TLS:-0}" = 1 ] && [ "${GOAUTHY_E2E_USE_GRANTS:-0}" = 1 ] && [ "${GOAUTHY_E2E_CREDENTIAL_DELIVERY:-0}" = 1 ] && [ "${GOAUTHY_E2E_RAW_AUTHORIZATION:-0}" = 1 ] || { echo 'Conductor delivery requires TLS, USE_GRANTS, CREDENTIAL_DELIVERY and RAW_AUTHORIZATION profiles' >&2; exit 1; }
	[ -f "$GOAUTHY_E2E_CONDUCTOR_DELIVERY_PROJECT_DIR/internal/connectors/delivery_live_test.go" ] || { echo 'Conductor delivery live harness is missing' >&2; exit 1; }
fi

if [ "${GOAUTHY_E2E_USE_GRANTS:-0}" = 1 ] || [ "${GOAUTHY_E2E_REGISTERED_OAUTH2:-0}" = 1 ]; then
	export GOAUTHY_E2E_AUTH_COLLECTIONS=1
	export GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://goauthy.connections.local.test"]'
	export GOAUTHY_CONNECTIONS_RESOURCE=https://goauthy.connections.local.test
fi
if [ "${GOAUTHY_E2E_BEESUH:-0}" = 1 ]; then
	[ "${GOAUTHY_E2E_COMPOS:-0}" != 1 ] && [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" != 1 ] || { echo 'Beesuh and Compos require separate disposable fixtures' >&2; exit 1; }
	export GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://beesuh.local.test","https://other-consumer.local.test"]'
fi

if [ "${GOAUTHY_E2E_DEVICE_RESOURCE:-0}" = 1 ]; then
	export GOAUTHY_E2E_PROVIDER_BEARER=1
fi
if [ "${GOAUTHY_E2E_PROVIDER_BEARER:-0}" = 1 ]; then
	[ "${GOAUTHY_E2E_BEESUH:-0}" != 1 ] && [ "${GOAUTHY_E2E_COMPOS:-0}" != 1 ] && [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" != 1 ] || { echo 'Provider Bearer requires a separate disposable fixture' >&2; exit 1; }
	export GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://goauthy.providers.local.test","https://other-consumer.local.test"]'
	export GOAUTHY_PROVIDERS_RESOURCE=https://goauthy.providers.local.test
	export GOAUTHY_E2E_PROVIDER_REGISTRATION=1
fi

if [ "${GOAUTHY_E2E_COMPOS:-0}" = 1 ] || [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" = 1 ]; then
	export GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://compos.local.test","https://other-consumer.local.test"]'
fi

policy_mode=${GOAUTHY_E2E_USER_VALUES_MODE:-}
if [ "${GOAUTHY_E2E_ACCOUNT_LIFECYCLE_UI:-0}" = 1 ]; then
	export GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1 GOAUTHY_ENABLE_SELF_DELETE=true
fi
if [ "${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then
	[ "${GOAUTHY_E2E_PROFILE_CLAIMS:-0}" = 1 ] || { echo 'account passkey UI requires the combined profile batch' >&2; exit 1; }
fi
case "$policy_mode" in ''|required|optional|hidden) ;; *) echo 'invalid GOAUTHY_E2E_USER_VALUES_MODE' >&2; exit 1;; esac
preferred_mode=${GOAUTHY_E2E_PREFERRED_USERNAME_POLICY:-}
case "$preferred_mode" in ''|default|custom) ;; *) echo 'invalid GOAUTHY_E2E_PREFERRED_USERNAME_POLICY' >&2; exit 1;; esac
if [ -n "$preferred_mode" ]; then
	[ -z "$policy_mode" ] && [ "${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" != 1 ] && [ "${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" != 1 ] || { echo 'preferred username requires a separate fixture' >&2; exit 1; }
	unset GOAUTHY_USER_VALUES_PREFERRED_USERNAME GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT
	if [ "$preferred_mode" = custom ]; then
		export GOAUTHY_USER_VALUES_PREFERRED_USERNAME=required GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX='^Team_[0-9]{2}$' GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST='["team_12"]' GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE=false GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HTML='^Team_[0-9]{2}$' GOAUTHY_USER_VALUES_PREFERRED_USERNAME_PATTERN_HINT='Team code'
	fi
fi
if [ -n "$policy_mode" ]; then
	[ "${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" != 1 ] && [ "${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" != 1 ] || { echo 'profile policy and backchannel fixtures are separate runs' >&2; exit 1; }
	for field in GIVEN_NAME FAMILY_NAME BIRTHDATE STREET ZIP CITY COUNTRY PHONE TZ; do
		export "GOAUTHY_USER_VALUES_$field=$policy_mode"
	done
fi

for command in curl go nc seq sleep dirname tail sed; do command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }; done
tls_mode=${GOAUTHY_E2E_TLS:-0}
case "$tls_mode" in
	0|1) ;;
	*) echo 'GOAUTHY_E2E_TLS must be 0 or 1' >&2; exit 1;;
esac
[ "$tls_mode" = 0 ] || command -v openssl >/dev/null 2>&1 || { echo 'missing required tool: openssl' >&2; exit 1; }
port=${GOAUTHY_STANDALONE_OPEN_REG_PORT:-18090}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_OPEN_REG_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65533 ] || { echo 'GOAUTHY_STANDALONE_OPEN_REG_PORT must leave room for SMTP ports' >&2; exit 1; }
smtp_port=$((port + 1)); smtp_http_port=$((port + 2))
scheme=http
[ "$tls_mode" = 1 ] && scheme=https
base_url="$scheme://localhost:$port"
backchannel_port=
if [ "${GOAUTHY_E2E_FORCE_LOGOUT_BACKCHANNEL:-0}" = 1 ] || [ "${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" = 1 ]; then
	[ "$port" -le 65532 ] || { echo 'force logout gate requires four ports' >&2; exit 1; }
	backchannel_port=$((port + 3))
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
. "$root/scripts/e2e-port-lock.sh"; e2e_port_lock_acquire
for candidate in "$port" "$smtp_port" "$smtp_http_port" $backchannel_port; do nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1 && { echo "port $candidate is already in use" >&2; e2e_port_lock_release; exit 1; }; done
umask 077; temp_dir=$(mktemp -d); pid=; smtp_pid=; backchannel_pid=; oauth_fixture_pid=; oauth_test_pid=
cleanup() { status=$?; trap - 0 1 2 15; for p in "$pid" "$smtp_pid" "$backchannel_pid" "$oauth_fixture_pid" "$oauth_test_pid"; do [ -z "$p" ] || { kill "$p" >/dev/null 2>&1 || true; wait "$p" 2>/dev/null || true; }; done; [ "$status" -eq 0 ] || tail -n 80 "$temp_dir"/*.log >&2 || true; rm -rf "$temp_dir"; e2e_port_lock_release; exit "$status"; }
trap cleanup 0 1 2 15
mkdir -p "$temp_dir/data" "$temp_dir/master-keys"
tls_cert_file=; tls_key_file=
if [ "$tls_mode" = 1 ]; then
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp_dir/ca.key" -out "$temp_dir/ca.pem" -subj '/CN=GoAuthy open-registration E2E CA' -days 1 >/dev/null 2>&1
	openssl req -new -newkey rsa:2048 -nodes -keyout "$temp_dir/goauthy.key" -out "$temp_dir/goauthy.csr" -subj '/CN=localhost' >/dev/null 2>&1
	printf '%s\n' 'subjectAltName=DNS:localhost,DNS:oauth-provider.e2e.test,IP:127.0.0.1' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' >"$temp_dir/goauthy.ext"
	openssl x509 -req -in "$temp_dir/goauthy.csr" -CA "$temp_dir/ca.pem" -CAkey "$temp_dir/ca.key" -CAcreateserial -out "$temp_dir/goauthy.pem" -days 1 -extfile "$temp_dir/goauthy.ext" >/dev/null 2>&1
	tls_cert_file=$temp_dir/goauthy.pem; tls_key_file=$temp_dir/goauthy.key
	export SSL_CERT_FILE="$temp_dir/ca.pem" CURL_CA_BUNDLE="$temp_dir/ca.pem"
fi
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/master-keys/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
printf '%s\n' correct-horse-browser-staple | go run "$root/cmd/goauthy-password" >"$temp_dir/password-phc"
printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/password-reset-key"
if [ "${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_DPOP:-0}" = 1 ]; then
	printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/dcr-registration-token"
	export GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-registration-token" GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef GOAUTHY_DCR_ALLOWED_SCOPES='openid profile email groups goauthy.read offline_access'
fi
if [ "${GOAUTHY_E2E_PROVIDER_BEARER:-0}" = 1 ]; then
	printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/dcr-registration-token"
	export GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-registration-token" GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef
	export GOAUTHY_DCR_ALLOWED_SCOPES='openid email profile goauthy.providers.read goauthy.providers.write'
fi
if [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" = 1 ]; then
	printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/dcr-registration-token"
	export GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-registration-token" GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef
	export GOAUTHY_DCR_ALLOWED_SCOPES='openid email profile compos.api'
fi
if [ "${GOAUTHY_E2E_BEESUH:-0}" = 1 ]; then
	printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/dcr-registration-token"
	export GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-registration-token" GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef
	export GOAUTHY_DCR_ALLOWED_SCOPES='openid email profile'
fi
if [ "${GOAUTHY_E2E_UPSTREAM_REGISTRY:-0}" = 1 ]; then
	printf '%s' 0123456789abcdef0123456789abcdef >"$temp_dir/dcr-registration-token"
	export GOAUTHY_DCR_REGISTRATION_TOKEN_FILE="$temp_dir/dcr-registration-token" GOAUTHY_E2E_DCR_REGISTRATION_TOKEN=0123456789abcdef0123456789abcdef
	export GOAUTHY_DCR_ALLOWED_SCOPES='openid profile email'
fi
if [ "${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ]; then
	printf '%s' abcdef0123456789abcdef0123456789 >"$temp_dir/passkey-key"
	export GOAUTHY_PASSKEY_RP_ID=localhost GOAUTHY_PASSKEY_ORIGINS="$base_url" GOAUTHY_PASSKEY_KEY_FILE="$temp_dir/passkey-key" GOAUTHY_PASSKEY_FORCE_UV=true GOAUTHY_BOOTSTRAP_FORCE_MFA=false
fi
# Reuse the exact local K8s fixture copy; only the block scalar has four-space indentation.
sed -n '/^    /s/^    //p' "$root/deploy/k8s/password-reset/email-templates.yaml" >"$temp_dir/email-templates.toml"
go build -trimpath -o "$temp_dir/goauthy" ./cmd/goauthy
go build -trimpath -o "$temp_dir/smtp-sink" ./cmd/goauthy-smtp-sink
if [ "${GOAUTHY_E2E_TERNAL_DEVICE:-0}" = 1 ]; then
	(cd "$GOAUTHY_E2E_TERNAL_PROJECT_DIR" && go build -mod=readonly -trimpath -o "$temp_dir/ternal-api" ./cmd/ternal-api && go build -mod=readonly -trimpath -o "$temp_dir/ternalctl" ./cmd/ternalctl)
	export GOAUTHY_E2E_TERNAL_API_BIN="$temp_dir/ternal-api" GOAUTHY_E2E_TERNAL_CLI_BIN="$temp_dir/ternalctl"
fi
if [ "${GOAUTHY_E2E_REGISTERED_OAUTH2:-0}" = 1 ]; then
	# This profile runs only in the runner's network-none Linux namespace.
	[ "$tls_mode" = 1 ] && [ -z "$(ip -o link show | awk -F ': ' '$2 != "lo" && $2 != "sit0@NONE" {print}')" ] && [ "$(ip -o link show up | awk -F ': ' '{print $2}')" = lo ] && [ -z "$(ip route show default)" ] && [ -z "$(ip -6 route show default)" ] || { echo 'registered OAuth fixture requires TLS and loopback-only isolation' >&2; exit 1; }
	ip -4 addr show dev lo | grep -q '8.8.8.8/32' || { echo 'isolated fixture address missing' >&2; exit 1; }
	export GOAUTHY_E2E_OAUTH2_PROVIDER_URL=https://oauth-provider.e2e.test:18443
	export GOAUTHY_E2E_OAUTH2_PROVIDER_ID=oauth-fixture
	export GOAUTHY_E2E_OAUTH2_CLIENT_ID=goauthy-saas-oauth-fixture
	export GOAUTHY_E2E_OAUTH2_CLIENT_SECRET=goauthy-saas-oauth-fixture-secret
	go build -trimpath -o "$temp_dir/oauth-fixture" ./cmd/goauthy-saas-oauth-fixture
	start_oauth_fixture() {
		SAAS_OAUTH_FIXTURE_ADDR=8.8.8.8:18443 SAAS_OAUTH_FIXTURE_TLS_CERT_FILE="$tls_cert_file" SAAS_OAUTH_FIXTURE_TLS_KEY_FILE="$tls_key_file" SAAS_OAUTH_FIXTURE_REDIRECT_URI="$base_url/auth/v1/saas/callback/$GOAUTHY_E2E_OAUTH2_PROVIDER_ID" "$temp_dir/oauth-fixture" >"$temp_dir/oauth-fixture.log" 2>&1 & oauth_fixture_pid=$!
		oauth_fixture_ready=
		for _ in $(seq 1 300); do kill -0 "$oauth_fixture_pid" 2>/dev/null || { cat "$temp_dir/oauth-fixture.log" >&2; exit 1; }; if curl --fail --silent "$GOAUTHY_E2E_OAUTH2_PROVIDER_URL/healthz" >/dev/null 2>&1; then oauth_fixture_ready=1; break; fi; sleep 0.1; done
		[ "$oauth_fixture_ready" = 1 ] || { echo 'OAuth fixture readiness timed out' >&2; exit 1; }
	}
	start_oauth_fixture
fi
"$temp_dir/smtp-sink" -smtp-addr "127.0.0.1:$smtp_port" -http-addr "127.0.0.1:$smtp_http_port" >"$temp_dir/smtp.log" 2>&1 & smtp_pid=$!
smtp_ready=
for _ in $(seq 1 300); do kill -0 "$smtp_pid" 2>/dev/null || { cat "$temp_dir/smtp.log" >&2; exit 1; }; if curl --fail --silent "http://localhost:$smtp_http_port/livez" >/dev/null 2>&1; then smtp_ready=1; break; fi; sleep 0.1; done
[ "$smtp_ready" = 1 ] || { echo 'SMTP sink readiness timed out' >&2; exit 1; }
if [ -n "$backchannel_port" ]; then
	go build -trimpath -o "$temp_dir/backchannel-sink" ./cmd/goauthy-backchannel-sink
	LISTEN_ADDR="127.0.0.1:$backchannel_port" "$temp_dir/backchannel-sink" >"$temp_dir/backchannel.log" 2>&1 & backchannel_pid=$!
	curl --fail --silent --show-error --retry 100 --retry-connrefused --retry-delay 0 --retry-max-time 10 "http://127.0.0.1:$backchannel_port/livez" >/dev/null
	export GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI="http://127.0.0.1:$backchannel_port/backchannel"
	export GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE=true GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP=true GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT=30m
fi
template_lang=en
open_reg_enabled=true
if [ "${GOAUTHY_E2E_EVENT_NOTIFICATIONS:-0}" = 1 ]; then
	export GOAUTHY_EVENT_NOTIFICATION_TARGETS=email GOAUTHY_EVENT_EMAIL_TO=events@goauthy.e2e
	if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then
		export GOAUTHY_EVENT_NOTIFICATION_EMAIL_LEVEL=info
	fi
fi
start_goauthy() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" GOAUTHY_ISSUER="$base_url" GOAUTHY_TLS_CERT_FILE="$tls_cert_file" GOAUTHY_TLS_KEY_FILE="$tls_key_file" GOAUTHY_RHIZA_PROFILE=standalone GOAUTHY_CLUSTER_ID=open-registration-standalone-e2e GOAUTHY_NODE_ID=open-registration-standalone-0 GOAUTHY_DATA_DIR="$temp_dir/data" GOAUTHY_MASTER_KEY_DIR="$temp_dir/master-keys" GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" GOAUTHY_BOOTSTRAP_USER=admin GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/password-phc" GOAUTHY_BOOTSTRAP_USER_EMAIL=admin@goauthy.e2e GOAUTHY_PASSWORD_RECOVERY_ENABLED=true GOAUTHY_PASSWORD_RESET_KEY_FILE="$temp_dir/password-reset-key" GOAUTHY_OPEN_USER_REG="$open_reg_enabled" GOAUTHY_USER_REG_DOMAIN_RESTRICTION=goauthy.e2e GOAUTHY_POW_DIFFICULTY=10 GOAUTHY_SMTP_HOST=127.0.0.1 GOAUTHY_SMTP_PORT="$smtp_port" GOAUTHY_SMTP_FROM=support@goauthy.e2e GOAUTHY_SMTP_ALLOW_INSECURE=true GOAUTHY_EMAIL_TEMPLATES_FILE="$temp_dir/email-templates.toml" GOAUTHY_EMAIL_TEMPLATE_LANG="$template_lang" "$temp_dir/goauthy" >"$temp_dir/goauthy.log" 2>&1 & pid=$!
	ready=
	for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || { cat "$temp_dir/goauthy.log" >&2; return 1; }; if curl --fail --silent "$base_url/livez" >/dev/null 2>&1 && curl --fail --silent "$base_url/readyz" >/dev/null 2>&1; then ready=1; break; fi; sleep 0.1; done
	[ "$ready" = 1 ] || { echo 'GoAuthy readiness timed out' >&2; return 1; }
}
stop_goauthy() {
	[ -z "$pid" ] || { kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true; }
	pid=
}
start_goauthy
if [ "${GOAUTHY_E2E_PROFILE_REVALIDATION:-}" = 1 ]; then
	export GOAUTHY_E2E_URL="$base_url"
	export GOAUTHY_E2E_SECONDARY_URL="$base_url"
	export GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin
	export GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple
	export GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -timeout=3m -v ./test/e2e/browser -run '^TestProfileRevalidationPrepareLive$'
	stop_goauthy
	export GOAUTHY_USER_VALUES_REVALIDATE_DURING_LOGIN=true
	export GOAUTHY_USER_VALUES_CITY=required
	start_goauthy
	go test -mod=readonly -count=1 -timeout=3m -v ./test/e2e/browser -run '^TestProfileRevalidationCompleteLive$'
	echo 'standalone profile revalidation E2E passed'
	exit 0
fi
if [ "${GOAUTHY_E2E_TERNAL_DEVICE:-0}" = 1 ] || [ "${GOAUTHY_E2E_AUTHCODE_NATIVE_UI:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_DPOP:-0}" = 1 ]; then
	consumer_test='^TestTernalDeviceCLILive$'
	if [ "${GOAUTHY_E2E_AUTHCODE_NATIVE_UI:-0}" = 1 ]; then
		consumer_test='^TestAuthorizationCodeNativePasswordSubmit$'
	fi
	if [ "${GOAUTHY_E2E_DEVICE_DPOP:-0}" = 1 ]; then
		consumer_test='^TestDeviceDPoP(Public)?Live$'
	fi
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "$consumer_test"
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "$consumer_test"
	echo 'Standalone selected consumer/browser workflow passed before/after GoAuthy restart'
	exit 0
fi
if [ "${GOAUTHY_E2E_REGISTERED_OAUTH2:-0}" = 1 ]; then
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	if [ "${GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART:-0}" = 1 ]; then
		oauth_restart_dir="$temp_dir/oauth-restart"
		mkdir -m 0700 "$oauth_restart_dir"
		export GOAUTHY_E2E_OAUTH2_RESTART_DIR="$oauth_restart_dir"
		# Track the test binary itself, not a go command with an untracked child.
		go test -mod=readonly -c -o "$temp_dir/oauth-browser.test" ./test/e2e/browser
		"$temp_dir/oauth-browser.test" -test.v -test.timeout=3m -test.run '^TestConnectionOAuth2RegisteredSuccess$' >"$temp_dir/oauth-test.log" 2>&1 & oauth_test_pid=$!
		wait_oauth_request() {
			request=$1
			for _ in $(seq 1 900); do
				[ -f "$oauth_restart_dir/request-$request" ] && return 0
				kill -0 "$oauth_test_pid" 2>/dev/null || { cat "$temp_dir/oauth-test.log" >&2; exit 1; }
				sleep 0.1
			done
			echo "OAuth2 restart request-$request timed out" >&2
			cat "$temp_dir/oauth-test.log" >&2 || true
			exit 1
		}
		wait_oauth_request 1
		stop_goauthy
		start_goauthy
		touch "$oauth_restart_dir/ready-1"
		wait_oauth_request 2
		stop_goauthy
		start_goauthy
		touch "$oauth_restart_dir/ready-2"
		for _ in $(seq 1 900); do
			kill -0 "$oauth_test_pid" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$oauth_test_pid" 2>/dev/null; then
			echo 'OAuth2 restart test timed out' >&2
			cat "$temp_dir/oauth-test.log" >&2 || true
			exit 1
		fi
		if wait "$oauth_test_pid"; then
			oauth_test_pid=
		else
			status=$?
			oauth_test_pid=
			cat "$temp_dir/oauth-test.log" >&2 || true
			exit "$status"
		fi
		cat "$temp_dir/oauth-test.log"
		echo 'Standalone registered OAuth connection/refresh public HTTP workflow passed across active restart'
		exit 0
	fi
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestConnectionOAuth2RegisteredSuccess$'
	stop_goauthy
	# Deleted provider IDs are tombstoned, not reusable. Register a new exact
	# callback for the second independent workflow against the persisted DB.
	kill "$oauth_fixture_pid"
	wait "$oauth_fixture_pid" 2>/dev/null || true
	oauth_fixture_pid=
	export GOAUTHY_E2E_OAUTH2_PROVIDER_ID=oauth-fixture-restarted
	start_oauth_fixture
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestConnectionOAuth2RegisteredSuccess$'
	echo 'Standalone registered OAuth connection/refresh public HTTP workflow passed before and after restart'
	exit 0
fi
if [ "${GOAUTHY_E2E_BEESUH:-0}" = 1 ]; then
	beesuh_dir=${GOAUTHY_E2E_BEESUH_PROJECT_DIR:-}
	case "$beesuh_dir" in /*) ;; *) echo 'GOAUTHY_E2E_BEESUH_PROJECT_DIR must be an absolute checkout path' >&2; exit 1;; esac
	[ -f "$beesuh_dir/httpapi/goauthy_e2e_test.go" ] || { echo 'Beesuh live harness is missing' >&2; exit 1; }
	mkdir "$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_BEESUH_CONSUMER_FIXTURE=1 GOAUTHY_E2E_CONSUMER_FIXTURE_DIR="$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestBeesuhConsumerFixture$'
	consumer_client_id=$(cat "$temp_dir/consumer-fixture/client-id")
	(
		cd "$beesuh_dir"
		BEESUH_E2E_GOAUTHY=1 BEESUH_E2E_GOAUTHY_ISSUER="$base_url" BEESUH_E2E_GOAUTHY_RESOURCE=https://beesuh.local.test BEESUH_E2E_GOAUTHY_CLIENT_ID="$consumer_client_id" BEESUH_E2E_GOAUTHY_CLIENT_SECRET_FILE="$temp_dir/consumer-fixture/client-secret" BEESUH_E2E_GOAUTHY_TOKEN_FILE="$temp_dir/consumer-fixture/access-token" BEESUH_E2E_GOAUTHY_MEMBERSHIPS_FILE="$temp_dir/consumer-fixture/memberships.json" BEESUH_E2E_GOAUTHY_WRONG_AUD_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-aud-token" BEESUH_E2E_GOAUTHY_WRONG_SCOPE_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-scope-token" BEESUH_E2E_GOAUTHY_REVOKED_TOKEN_FILE="$temp_dir/consumer-fixture/revoked-token" go test -mod=readonly -count=1 -v -timeout=3m ./httpapi -run '^TestGoAuthyLiveE2E$'
	)
	echo 'Standalone GoAuthy to Beesuh identity pilot passed; inspect subtest skips for gaps'
	exit 0
fi
if [ "${GOAUTHY_E2E_COMPOS_OAUTH2:-0}" = 1 ]; then
	compos_dir=${GOAUTHY_E2E_COMPOS_PROJECT_DIR:-}
	case "$compos_dir" in /*) ;; *) echo 'GOAUTHY_E2E_COMPOS_PROJECT_DIR must be an absolute checkout path' >&2; exit 1;; esac
	[ -f "$compos_dir/internal/server/oauth2_e2e_test.go" ] || { echo 'Compos OAuth2 live harness is missing' >&2; exit 1; }
	mkdir "$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_OAUTH2_CONSUMER_FIXTURE=1 GOAUTHY_E2E_CONSUMER_FIXTURE_DIR="$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestOAuth2ConsumerFixture$'
	consumer_client_id=$(cat "$temp_dir/consumer-fixture/client-id")
	(
		cd "$compos_dir"
		COMPOS_E2E_OAUTH2=1 COMPOS_E2E_OAUTH2_ISSUER="$base_url" COMPOS_E2E_OAUTH2_RESOURCE=https://compos.local.test COMPOS_E2E_OAUTH2_CLIENT_ID="$consumer_client_id" COMPOS_E2E_OAUTH2_EMAIL_DOMAIN=goauthy.e2e COMPOS_E2E_OAUTH2_CLIENT_SECRET_FILE="$temp_dir/consumer-fixture/client-secret" COMPOS_E2E_OAUTH2_TOKEN_FILE="$temp_dir/consumer-fixture/access-token" COMPOS_E2E_OAUTH2_WRONG_AUD_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-aud-token" COMPOS_E2E_OAUTH2_WRONG_SCOPE_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-scope-token" COMPOS_E2E_OAUTH2_REVOKED_TOKEN_FILE="$temp_dir/consumer-fixture/revoked-token" go test -mod=readonly -count=1 -v -timeout=3m ./internal/server -run '^TestOAuth2LiveE2E$'
	)
	echo 'Standalone GoAuthy to generic Compos OAuth2 pilot passed; inspect subtest skips for gaps'
	exit 0
fi
if [ "${GOAUTHY_E2E_COMPOS:-0}" = 1 ]; then
	compos_dir=${GOAUTHY_E2E_COMPOS_PROJECT_DIR:-}
	case "$compos_dir" in /*) ;; *) echo 'GOAUTHY_E2E_COMPOS_PROJECT_DIR must be an absolute checkout path' >&2; exit 1;; esac
	[ -f "$compos_dir/internal/server/goauthy_e2e_test.go" ] || { echo 'Compos live harness is missing' >&2; exit 1; }
	mkdir "$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_CONSUMER_TOKEN_FIXTURE=1 GOAUTHY_E2E_CONSUMER_FIXTURE_DIR="$temp_dir/consumer-fixture"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestConsumerTokenFixture$'
	(
		cd "$compos_dir"
		export COMPOS_E2E_GOAUTHY_WRONG_AUD_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-aud-token" COMPOS_E2E_GOAUTHY_WRONG_SCOPE_TOKEN_FILE="$temp_dir/consumer-fixture/wrong-scope-token" COMPOS_E2E_GOAUTHY_REVOKED_TOKEN_FILE="$temp_dir/consumer-fixture/revoked-token"
		COMPOS_E2E_GOAUTHY=1 COMPOS_E2E_GOAUTHY_ISSUER="$base_url" COMPOS_E2E_GOAUTHY_RESOURCE=https://compos.local.test COMPOS_E2E_GOAUTHY_CLIENT_ID=goauthy-dev COMPOS_E2E_GOAUTHY_EMAIL_DOMAIN=goauthy.e2e COMPOS_E2E_GOAUTHY_CLIENT_SECRET_FILE="$temp_dir/consumer-fixture/client-secret" COMPOS_E2E_GOAUTHY_TOKEN_FILE="$temp_dir/consumer-fixture/access-token" go test -mod=readonly -count=1 -v -timeout=3m ./internal/server -run '^TestGoAuthyLiveE2E$'
	)
	echo 'Standalone GoAuthy to Compos live session pilot passed; see subtest skips for uncovered negative cases'
	exit 0
fi
if [ "${GOAUTHY_E2E_PROVIDER_REGISTRATION:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_OIDC:-0}" = 1 ] || [ "${GOAUTHY_E2E_MANAGED_CLIENTS:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ] || [ "${GOAUTHY_E2E_AUTH_COLLECTIONS:-0}" = 1 ] || [ "${GOAUTHY_E2E_AUTH_COLLECTIONS_UI:-0}" = 1 ] || [ "${GOAUTHY_E2E_MANAGED_CLIENTS_UI:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_SESSIONS:-0}" = 1 ] || [ "${GOAUTHY_E2E_CONNECTION_RESOURCES:-0}" = 1 ] || [ "${GOAUTHY_E2E_DEVICE_SESSIONS_UI:-0}" = 1 ] || [ "${GOAUTHY_E2E_SAAS_PROVIDERS:-0}" = 1 ] || [ "${GOAUTHY_E2E_CONNECTION_API_KEY:-0}" = 1 ]; then
	export GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	pilot_tests='^Test(ManagedClientAudienceProviderBearerLive|ConnectionOAuth2ProviderRegistrationBoundary|ProviderBearerLive|ProviderRegistrationLive|DeviceOIDCLive|ManagedClientsHTTPWorkflow|DeviceAuthorizationBrowserLogin|DeviceAuthorizationPublicBrowserLogin|AuthCollectionsAcrossPods|AuthCollectionsUIAcrossPods|ManagedClientsUIAcrossPods|DeviceSessionsPilot|ConnectionResourcesPilot|DeviceSessionsUI|SaaSProvidersCatalog|ConnectionAPIKeyPilot)$'
	if [ "${GOAUTHY_E2E_DEVICE_RESOURCE:-0}" = 1 ]; then
		pilot_tests='^TestManagedDeviceResourceProviderBearerLive$'
	fi
	if [ "${GOAUTHY_E2E_USE_GRANTS:-0}" = 1 ]; then
		pilot_tests='^TestConnectionUseGrantLive$'
	fi
	if [ "${GOAUTHY_E2E_ACCOUNT_PASSKEY_UI:-0}" = 1 ] && [ "${GOAUTHY_E2E_DEVICE_LOGIN_FLOW:-0}" = 1 ]; then
		pilot_tests="$pilot_tests|^TestAccountPasskeyUIAcrossPods$"
	fi
	go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e ./test/e2e/browser -run "$pilot_tests"
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e ./test/e2e/browser -run "$pilot_tests"
	echo 'Standalone selected client/device/collection pilot and post-restart workflow passed'
	exit 0
fi
if [ "${GOAUTHY_E2E_UPSTREAM_REGISTRY:-0}" = 1 ]; then
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUpstreamRegistryLive$'
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUpstreamRegistryLive$'
	echo 'Standalone upstream registry and post-restart workflow passed'
	exit 0
fi
if [ "${GOAUTHY_E2E_LOGO:-0}" = 1 ]; then
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClient(Logo|Favicon)Live$'
	export GOAUTHY_E2E_LOGO_STATE_FILE="$temp_dir/logo-state.json"
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientLogoPersistPrepare$'
	export GOAUTHY_E2E_FAVICON_STATE_FILE="$temp_dir/favicon-state.json"
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientFaviconPersistPrepare$'
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientLogoPersistVerify$'
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestClientFaviconPersistVerify$'
	echo 'standalone client logo HTTP and retained-data restart E2E passed' 
	exit 0
fi
if [ "${GOAUTHY_E2E_THEME:-0}" = 1 ]; then
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemeLive$'
	if [ "${GOAUTHY_E2E_THEME_UI:-0}" = 1 ]; then
		go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemeLoginUI$'
	fi
	export GOAUTHY_E2E_THEME_STATE_FILE="$temp_dir/theme-state.json"
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemePersistPrepare$'
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestThemePersistVerify$'
	echo 'standalone theme HTTP and restart persistence E2E passed'
	exit 0
fi
if [ "${GOAUTHY_E2E_LOGIN_LOCATION:-0}" = 1 ]; then
	export GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestLoginLocationRevokeLive$'
	echo 'standalone login-location revoke E2E passed'
	exit 0
fi
if [ "${GOAUTHY_E2E_PROFILE_CLAIMS:-0}" = 1 ]; then
	if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then export GOAUTHY_E2E_TOKEN_EVENT_FILE="$temp_dir/token-events.json"; fi
	export GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	GOAUTHY_E2E_ADMIN_UI=1 go test -mod=readonly -count=1 -v -timeout=5m ./test/e2e/browser -run '^Test(TokenIssuedEvents|TokenIssuedUserEvents|TokenIssuedDeviceEvents|ProfileClaimsLive|AdminUIHTTPAcrossPods|AdminUIBrowserAcrossPods|EventNotificationsAcrossPods|AccountDashboardAcrossPods|AdminAPIKeyUIAcrossPods|AdminCatalogSessionsUIAcrossPods|AccountPasskeyUIAcrossPods|AccountLifecycleUIAcrossPods)$'
	if [ "${GOAUTHY_E2E_EVENT_NOTIFICATIONS:-0}" = 1 ]; then
		stop_goauthy
		start_goauthy
		go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestEventNotificationsAcrossPods$'
	fi
	if [ "${GOAUTHY_E2E_TOKEN_EVENTS:-0}" = 1 ]; then
		stop_goauthy
		start_goauthy
		go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestTokenIssuedEventsPersisted$'
	fi
	echo 'standalone feature batch E2E passed'
	exit 0
fi
if [ -n "$policy_mode" ] || [ -n "$preferred_mode" ]; then
	test_prefix=UserValuesPolicy; policy_label="user-values $policy_mode"
	if [ -n "$preferred_mode" ]; then test_prefix=PreferredUsernamePolicy; policy_label="preferred-username $preferred_mode"; fi
	export GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^Test${test_prefix}AcrossPods\$"
	stop_goauthy
	start_goauthy
	go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run "^Test${test_prefix}Persisted\$"
	if [ -n "$preferred_mode" ]; then
		stop_goauthy
		open_reg_enabled=false
		start_goauthy
		GOAUTHY_E2E_USER_VALUES_CONFIG_PRIVATE=1 go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUserValuesConfigPrivateAcrossPods$'
	fi
	echo "standalone $policy_label policy and restart E2E passed"
	exit 0
fi
if [ -n "$backchannel_port" ]; then
	export GOAUTHY_E2E_FORCE_LOGOUT_STATE="$temp_dir/force-logout.json"
	export GOAUTHY_E2E_BACKCHANNEL_SINK_URL="http://127.0.0.1:$backchannel_port" GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port"
	export GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url"
	export GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple
	if [ "${GOAUTHY_E2E_USER_DELETE_BACKCHANNEL:-0}" = 1 ]; then
		export GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_STATE="$temp_dir/user-delete.json"
		GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_PHASE=prepare go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUserDeleteBackchannel$'
		for phase in after-restart after-delete-restart; do
			stop_goauthy
			start_goauthy
			GOAUTHY_E2E_USER_DELETE_BACKCHANNEL_PHASE="$phase" go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestUserDeleteBackchannel$'
		done
		echo 'standalone subject-only user deletion with pre/post deletion restart passed'
		exit 0
	fi
	GOAUTHY_E2E_FORCE_LOGOUT_PHASE=prepare go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestForceLogoutBackchannel$'
	stop_goauthy
	start_goauthy
	GOAUTHY_E2E_FORCE_LOGOUT_PHASE=after-restart go test -mod=readonly -count=1 -v -timeout=3m ./test/e2e/browser -run '^TestForceLogoutBackchannel$'
	echo 'standalone subject-only per-user backchannel logout after restart passed'
	exit 0
fi
GOAUTHY_E2E_ADMIN_USER_CREATE=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port" GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^Test(OpenRegistrationAcrossPods|AdminUserCreateLifecycle|AdminUserUpdateAcrossPods)$'
GOAUTHY_E2E_EVENTS_STREAM=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^TestCreationEventsStream$'
GOAUTHY_E2E_EVENT_TEST=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^TestEventTestEndpoint$'
stop_goauthy
start_goauthy
GOAUTHY_E2E_EVENT_TEST_PERSISTENCE=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^TestEventTestPersisted$'
GOAUTHY_E2E_EVENTS_PERSISTENCE=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^Test(CreationEventsPersisted|AdminUserUpdatePersisted)$'
# Registration above proves per-user ko overrides an en fallback. The legacy
# bootstrap reset fixture has no language and explicitly expects the ko template.
stop_goauthy
template_lang=ko
start_goauthy
GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=correct-horse-browser-staple GOAUTHY_E2E_BROWSER_SUBJECT=bootstrap-admin GOAUTHY_E2E_BROWSER_EMAIL=admin@goauthy.e2e GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_SMTP_SINK_URL="http://localhost:$smtp_http_port" GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^TestPasswordResetAcrossPods$'
stop_goauthy
start_goauthy
GOAUTHY_E2E_RESET_EVENT_PERSISTENCE=1 GOAUTHY_E2E_BROWSER_USERNAME=admin GOAUTHY_E2E_BROWSER_PASSWORD=Reset-Password-1A GOAUTHY_E2E_BROWSER_EMAIL=admin@goauthy.e2e GOAUTHY_E2E_CLIENT_SECRET=correct-horse-battery-staple GOAUTHY_E2E_URL="$base_url" GOAUTHY_E2E_SECONDARY_URL="$base_url" GOAUTHY_E2E_TERTIARY_URL="$base_url" go test -count=1 -v "$root/test/e2e/browser" -run '^TestPasswordResetEventPersisted$'
echo 'standalone open-registration and password-reset E2E passed'
