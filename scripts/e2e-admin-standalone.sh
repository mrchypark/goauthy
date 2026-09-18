#!/bin/sh
set -eu

for command in cp curl dirname go grep head nc sed tr; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing required tool: $command" >&2
		exit 1
	}
done

port=${GOAUTHY_STANDALONE_ADMIN_PORT:-18085}
case "$port" in ''|*[!0-9]*) echo 'GOAUTHY_STANDALONE_ADMIN_PORT must be a decimal TCP port' >&2; exit 1;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || {
	echo 'GOAUTHY_STANDALONE_ADMIN_PORT must be between 1024 and 65535' >&2
	exit 1
}
if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
	echo "standalone admin port $port is already in use; choose GOAUTHY_STANDALONE_ADMIN_PORT" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/e2e-port-lock.sh
. "$script_dir/e2e-port-lock.sh"
temp_dir=$(mktemp -d)
pid=
root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$root"
cleanup() {
	status=$?
	trap - 0 1 2 15
	if [ -n "$pid" ]; then
		kill -TERM "$pid" >/dev/null 2>&1 || true
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
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$master_key_dir/dev-1"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$temp_dir/oauth-hmac"
printf '%s\n' correct-horse-battery-staple >"$temp_dir/bootstrap-client"
browser_password=correct-horse-browser-staple
printf '%s\n' "$browser_password" | go run ./cmd/goauthy-password >"$temp_dir/bootstrap-user-password-phc"

binary=$temp_dir/goauthy
go build -trimpath -o "$binary" ./cmd/goauthy

base=http://127.0.0.1:$port
start() {
	GOAUTHY_LISTEN_ADDR="127.0.0.1:$port" \
	GOAUTHY_ISSUER="$base" \
	GOAUTHY_RHIZA_PROFILE=standalone \
	GOAUTHY_CLUSTER_ID=standalone-admin-e2e \
	GOAUTHY_NODE_ID=standalone-admin-0 \
	GOAUTHY_DATA_DIR="$data_dir" \
	GOAUTHY_MASTER_KEY_DIR="$master_key_dir" \
	GOAUTHY_ACTIVE_MASTER_KEY_ID=dev-1 \
	GOAUTHY_OAUTH_HMAC_SECRET_FILE="$temp_dir/oauth-hmac" \
	GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE="$temp_dir/bootstrap-client" \
	GOAUTHY_BOOTSTRAP_USER=admin \
	GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE="$temp_dir/bootstrap-user-password-phc" \
	GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES='["https://api.example.test/v1"]' \
	"$binary" >"$temp_dir/server.log" 2>&1 &
	pid=$!
}

wait_ready() {
	# curl retries are bounded by both attempts and wall time; no arbitrary sleep.
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 \
		"$base/livez" >/dev/null 2>&1 || {
		cat "$temp_dir/server.log" >&2
		return 1
	}
	curl --fail --silent --show-error --retry 300 --retry-connrefused --retry-delay 0 --retry-max-time 30 \
		"$base/readyz" >/dev/null 2>&1 || {
		cat "$temp_dir/server.log" >&2
		return 1
	}
}

expect_admin_status() {
	want=$1
	label=$2
	shift 2
	url=$base/auth/v1/admin
	if [ "${1:-}" = --url ]; then
		url=$2
		shift 2
	fi
	body=$temp_dir/$label.body
	got=$(curl --max-time 5 --silent --show-error --output "$body" --write-out '%{http_code}' "$@" "$url")
	[ "$got" = "$want" ] || {
		echo "$label admin status=$got want $want" >&2
		return 1
	}
}

header_value() {
	name=$1
	file=$2
	grep -i "^$name:" "$file" | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'
}

hidden_input() {
	name=$1
	file=$2
	sed -n "s/.*name=\"$name\" value=\"\([^\"]*\)\".*/\1/p" "$file" | head -n 1
}

start
wait_ready

cookie_jar=$temp_dir/cookies.txt
init_cookie_jar=$temp_dir/init-cookies.txt
auth_cookie_jar=$temp_dir/auth-cookies.txt

# An anonymous request cannot reach the browser-admin index.
expect_admin_status 401 anonymous

challenge=O9M0cMevVEgqfN7qJR8DkkvCZabiBMYfF70EU0Q9Tjc
state=standalone-admin-state
nonce=standalone-admin-nonce
authorize_url="$base/oidc/authorize?response_type=code&client_id=goauthy-dev&redirect_uri=http%3A%2F%2Flocalhost%3A5555%2Fcallback&scope=openid%20goauthy.read%20offline_access&state=$state&nonce=$nonce&code_challenge=$challenge&code_challenge_method=S256"
authorize_body=$temp_dir/authorize.html
authorize_status=$(curl --max-time 5 --silent --show-error --output "$authorize_body" --write-out '%{http_code}' --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$authorize_url")
[ "$authorize_status" = 200 ] || {
	echo "authorize status=$authorize_status want 200" >&2
	exit 1
}
cp "$cookie_jar" "$init_cookie_jar"
interaction=$(hidden_input interaction "$authorize_body")
[ -n "$interaction" ] || { echo 'authorize response has no interaction' >&2; exit 1; }

login_headers=$temp_dir/login.headers
login_status=$(curl --max-time 5 --silent --show-error --output /dev/null --dump-header "$login_headers" --write-out '%{http_code}' \
	--cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	-H 'Content-Type: application/x-www-form-urlencoded' -H 'Sec-Fetch-Site: same-origin' \
	--data-urlencode "interaction=$interaction" --data-urlencode 'username=admin' --data-urlencode "password=$browser_password" \
	"$base/auth/login")
if [ "$login_status" != 302 ] && [ "$login_status" != 303 ]; then
	echo "login status=$login_status want 302/303" >&2
	exit 1
fi
location=$(sed -n 's/^[Ll]ocation:[[:space:]]*//p' "$login_headers" | head -n 1 | tr -d '\r')
case "$location" in *"state=$state"*) ;; *) echo "login redirect missing state: $location" >&2; exit 1;; esac
code=$(printf '%s\n' "$location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$code" ] || { echo 'login redirect has no authorization code' >&2; exit 1; }
cp "$cookie_jar" "$auth_cookie_jar"

admin_headers=$temp_dir/admin.headers
admin_body=$temp_dir/admin.html
admin_status=$(curl --max-time 5 --fail --silent --show-error --output "$admin_body" --dump-header "$admin_headers" --write-out '%{http_code}' --cookie "$cookie_jar" "$base/auth/v1/admin")
[ "$admin_status" = 200 ] || { echo "admin status=$admin_status want 200" >&2; exit 1; }
expected_links=$(printf '%s\n' \
	/auth/v1/roles \
	/auth/v1/groups \
	/auth/v1/scopes \
	/auth/v1/users/attr \
	/auth/v1/api_keys)
actual_links=$(tr '<' '\n' <"$admin_body" | sed -n 's/^[^>]*href="\([^"]*\)".*/\1/p')
[ "$actual_links" = "$expected_links" ] || {
	echo "admin links changed: $(printf '%s' "$actual_links" | tr '\n' ' ')" >&2
	exit 1
}
[ "$(header_value Cache-Control "$admin_headers")" = no-store ] || exit 1
[ "$(header_value Content-Security-Policy "$admin_headers")" = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" ] || exit 1
[ "$(header_value X-Frame-Options "$admin_headers")" = DENY ] || exit 1
[ "$(header_value X-Content-Type-Options "$admin_headers")" = nosniff ] || exit 1
[ "$(header_value Content-Type "$admin_headers")" = 'text/html; charset=utf-8' ] || exit 1

# The pre-login Init session is not an administrator session.
expect_admin_status 401 init-session --cookie "$init_cookie_jar"
expect_admin_status 401 bearer --cookie "$auth_cookie_jar" -H 'Authorization: Bearer invalid'
expect_admin_status 401 api-key --cookie "$auth_cookie_jar" -H 'Authorization: API-Key invalid'
expect_admin_status 401 cross-site --cookie "$auth_cookie_jar" -H 'Sec-Fetch-Site: cross-site'
expect_admin_status 401 query --url "$base/auth/v1/admin?probe=1" --cookie "$auth_cookie_jar"

# A revoked browser session remains unusable even when its stale cookie is
# replayed after the logout confirmation flow.
stale_cookie_jar=$temp_dir/stale-cookies.txt
cp "$auth_cookie_jar" "$stale_cookie_jar"
logout_body=$temp_dir/logout.html
logout_status=$(curl --max-time 5 --silent --show-error --output "$logout_body" --write-out '%{http_code}' --cookie "$cookie_jar" "$base/oidc/logout")
[ "$logout_status" = 200 ] || { echo "logout confirmation status=$logout_status want 200" >&2; exit 1; }
confirmation=$(hidden_input confirmation "$logout_body")
[ -n "$confirmation" ] || { echo 'logout confirmation has no token' >&2; exit 1; }
logout_status=$(curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	-H 'Content-Type: application/x-www-form-urlencoded' -H 'Sec-Fetch-Site: same-origin' \
	--data-urlencode "confirmation=$confirmation" "$base/oidc/logout")
[ "$logout_status" = 303 ] || { echo "logout status=$logout_status want 303" >&2; exit 1; }
expect_admin_status 401 logged-out --cookie "$stale_cookie_jar"

echo 'standalone browser-admin index E2E passed'
