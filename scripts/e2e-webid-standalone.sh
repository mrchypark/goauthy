#!/bin/sh
# Exercises the public WebID route against one disposable standalone process.
# The process is restarted against the same data/key directories to prove that
# the route and its persisted identity remain stable across a cold restart.
set -eu

for command in cat cmp curl go grep nc sed seq sleep tail tr; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done

port=${GOAUTHY_STANDALONE_WEBID_PORT:-18082}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_WEBID_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'GOAUTHY_STANDALONE_WEBID_PORT must be between 1024 and 65535' >&2; exit 1; }
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone WebID port $port is already in use; choose GOAUTHY_STANDALONE_WEBID_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
temp_dir=$(mktemp -d)
pid=
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
base=http://127.0.0.1:$port
subject=webid-subject
issuer=$base

cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

data_dir=$temp_dir/data
master_key_dir=$temp_dir/master-keys
mkdir -p "$data_dir" "$master_key_dir"
cd "$root"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
browser_password=correct-horse-browser-staple
printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"
binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy

expected_body=$temp_dir/expected-body
printf '<%s/auth/%s/profile> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/PersonalProfileDocument>;\n\t<http://xmlns.com/foaf/0.1/primaryTopic> <%s/auth/%s/profile#me> .\n<%s/auth/%s/profile#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <%s>;\n\t<http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/Person> .\n' "$issuer" "$subject" "$issuer" "$subject" "$issuer" "$subject" "$issuer" >"$expected_body"

start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$issuer" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-webid-e2e \
	GOAUTHY_NODE_ID=standalone-webid-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=webid@example.test \
	GOAUTHY_BOOTSTRAP_USER_SUBJECT="$subject" \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	GOAUTHY_WEB_ID_ENABLED=true \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	for _ in $(seq 1 300); do
		kill -0 "$pid" 2>/dev/null || { cat "$temp_dir/server.log" >&2; return 1; }
		if curl --max-time 1 --fail --silent "$base/livez" >/dev/null 2>&1 && curl --max-time 1 --fail --silent "$base/readyz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	cat "$temp_dir/server.log" >&2
	return 1
}

stop_server() {
	kill "$pid" >/dev/null 2>&1 || true
	for _ in $(seq 1 100); do
		if ! kill -0 "$pid" 2>/dev/null; then
			wait "$pid" 2>/dev/null || true
			pid=
			return 0
		fi
		sleep 0.1
	done
	echo 'standalone WebID process did not exit after bounded SIGTERM wait' >&2
	return 1
}

request() {
	method=$1
	accept=$2
	path=$3
	method_args="-X $method"
	[ "$method" = HEAD ] && method_args=--head
	if [ -n "$accept" ]; then
		# shellcheck disable=SC2086 # exactly either "-X METHOD" or "--head"
		curl --max-time 30 --silent --show-error --output "$temp_dir/body" --dump-header "$temp_dir/headers" --write-out '%{http_code}' $method_args -H "Accept: $accept" "$base$path"
	else
		# shellcheck disable=SC2086 # exactly either "-X METHOD" or "--head"
		curl --max-time 30 --silent --show-error --output "$temp_dir/body" --dump-header "$temp_dir/headers" --write-out '%{http_code}' $method_args "$base$path"
	fi
}

content_type() {
	sed -n 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//p' "$temp_dir/headers" | tr -d '\r' | tail -n 1
}

assert_turtle_get() {
	accept=$1
	status=$(request GET "$accept" "/auth/$subject/profile")
	[ "$status" = 200 ] || { echo "WebID GET Accept=$accept status=$status" >&2; return 1; }
	[ "$(content_type)" = 'text/turtle; charset=utf-8' ] || { echo "unexpected WebID content type: $(content_type)" >&2; return 1; }
	cmp -s "$expected_body" "$temp_dir/body" || { echo 'WebID Turtle body changed from the deterministic subject/issuer document' >&2; return 1; }
	for private in webid@example.test email roles groups; do
		if grep -Fq "$private" "$temp_dir/body"; then
			echo "WebID body leaked private marker $private" >&2
			return 1
		fi
	done
}

assert_status() {
	method=$1
	accept=$2
	path=$3
	want=$4
	status=$(request "$method" "$accept" "$path")
	[ "$status" = "$want" ] || { echo "WebID $method $path Accept=$accept status=$status want=$want" >&2; return 1; }
}

start
wait_ready
assert_turtle_get ''
assert_turtle_get 'text/turtle'

# Exercise RFC-shaped positive ranges and the explicit denial boundary.
assert_turtle_get 'text/turtle; charset=utf-8'
assert_turtle_get 'text/turtle;q=0.9'
assert_turtle_get '*/*'
assert_status GET 'text/turtle;q=0' "/auth/$subject/profile" 406
assert_status GET 'text/turtle' "/auth/$subject%2Fother/profile" 404
assert_status GET 'text/turtle' "/auth/$subject/profile?probe=1" 404
assert_status HEAD 'text/turtle' "/auth/$subject/profile" 405
assert_status POST 'text/turtle' "/auth/$subject/profile" 405

stop_server
start
wait_ready
assert_turtle_get ''
echo 'standalone WebID runtime E2E passed'
