#!/bin/sh
# Shell-only controls. All Docker calls below are fakes; no daemon is used.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
script=$root/scripts/e2e-v038-readiness.sh
workflow=$root/.github/workflows/v038-readiness.yml
scratch=$(mktemp -d "${TMPDIR:-/tmp}/goauthy-v038-guards.XXXXXX")
trap 'rm -rf "$scratch"' 0
trap 'exit 130' 2
trap 'exit 143' 1 15
mkdir -p "$scratch/bin" "$scratch/logs" "$scratch/inputs"
chmod 700 "$scratch"
cat >"$scratch/bin/docker" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>'$scratch/docker.calls'
case "\$*" in
  'info --format '*) cat '$scratch/platform';;
  'pull '*) echo 'preflight completed: synthetic pull stop' >&2; exit 99;;
  *) echo 'unexpected Docker call in preflight guard' >&2; exit 99;;
esac
EOF
cat >"$scratch/bin/uname" <<EOF
#!/bin/sh
case "\$1" in -s) cat '$scratch/os';; -m) cat '$scratch/arch';; esac
EOF
cat >"$scratch/bin/nc" <<EOF
#!/bin/sh
echo 'synthetic issuer-port listener queried' >>'$scratch/nc.calls'
exit 0
EOF
chmod +x "$scratch/bin/"*
guard_path=$scratch/bin:$PATH
run_script() { PATH="$guard_path" TMPDIR="$scratch" /bin/sh "$script" "$@"; }
expect_failure() {
	if run_script --run >"$scratch/result" 2>&1; then echo 'unsafe preflight unexpectedly succeeded' >&2; exit 1; fi
	grep -F "$1" "$scratch/result" >/dev/null
}

GOAUTHY_ISSUER=https://forbidden.example GOOGLE_APPLICATION_CREDENTIALS=/forbidden run_script --check >"$scratch/check"
[ ! -e "$scratch/docker.calls" ]
grep -F 'Offline check only' "$scratch/check" >/dev/null
grep -F 'FS cap=120s; GCS cold cap=900s checkpoint=120s; warm cap=120s.' "$scratch/check" >/dev/null
grep -F 'ghcr.io/mrchypark/goauthy@sha256:0e143036a9cdbbf458f8ebf16739fb59a4d43bb6efff86b8f4a003eb61e51903' "$scratch/check" >/dev/null
grep -F 'revision=908cc698b1f238fb12ce83a47e2656d8333e2523' "$scratch/check" >/dev/null
grep -F 'GCS=docker.io/floci/floci-gcp@sha256:042c0c6d29b992691ea640bfce91554329d29004cfe4b68aa2093da23e06784f port=4588' "$scratch/check" >/dev/null

printf 'Darwin\n' >"$scratch/os"; printf 'arm64\n' >"$scratch/arch"
expect_failure 'native Linux/amd64 host required'
[ ! -e "$scratch/docker.calls" ]
printf 'Linux\n' >"$scratch/os"; printf 'x86_64\n' >"$scratch/arch"
printf 'linux/aarch64\n' >"$scratch/platform"
expect_failure 'native Docker Linux/amd64 server required'
# nc would report an unrelated listener on the issuer port. With no published
# port, preflight must ignore it and reach the deliberate fake pull failure.
printf 'linux/amd64\n' >"$scratch/platform"
expect_failure 'preflight completed: synthetic pull stop'
[ ! -e "$scratch/nc.calls" ]
[ "$(wc -l <"$scratch/docker.calls" | tr -d ' ')" -eq 3 ]
if grep -E '(^|[[:space:]])nc([[:space:]]|$)' "$script"; then exit 1; fi

# Exercise the real cleanup functions with an owned-ID fake, a foreign label,
# and an unavailable daemon. Only the verified owned ID may be stopped/removed.
for function in build_redaction_patterns sanitize_logs owned_id container_identity verified_identity verify_absent remove_container fingerprint_jwks diagnostic_http_probe owned_container_ip diagnose_fs_timeout observe cleanup; do
	awk -v name="$function" '$0 == name "() {" {copy=1} copy {print} copy && /^}/ {exit}' "$script" >>"$scratch/functions.sh"
done
# shellcheck source=/dev/null
. "$scratch/functions.sh"
nonce=owned-run
# shellcheck disable=SC2034 # The extracted production functions use logs.
logs=$scratch/logs
# shellcheck disable=SC2034 # The extracted production functions use inputs.
inputs=$scratch/inputs
printf 'synthetic-first\n' >"$inputs/trailing-newline"
printf 'synthetic-second\n\n\n' >"$inputs/extra-newlines"
build_redaction_patterns "$inputs/trailing-newline" "$inputs/extra-newlines"
if grep '^$' "$inputs/patterns" >/dev/null; then echo 'redaction regression: empty pattern would withhold every log' >&2; exit 1; fi
[ "$(wc -l <"$inputs/patterns" | tr -d ' ')" -eq 2 ]
printf 'public startup diagnostic\n' >"$logs/benign.log"
printf 'synthetic-first\n' >"$logs/sensitive.log"
sanitize_logs
grep -Fx 'public startup diagnostic' "$logs/benign.log" >/dev/null
grep -Fx 'Log withheld: synthetic key material detected.' "$logs/sensitive.log" >/dev/null
owned_test_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
test_label=$nonce
test_daemon=up
dkr() {
	case "$1/$2" in
		container/inspect|network/inspect)
			[ "$test_daemon" = up ] || return 125
			if [ "$3" = --format ]; then printf '%s %s\n' "$owned_test_id" "$test_label"; else echo "Error: No such container: $owned_test_id" >&2; return 1; fi;;
		logs/*) echo 'bounded synthetic log';;
		stop/*|rm/*|network/rm) printf '%s\n' "$*" >>"$scratch/actions";;
		*) return 99;;
	esac
}
remove_container owned-name
grep -Fx "stop --time 10 $owned_test_id" "$scratch/actions" >/dev/null
grep -Fx "rm $owned_test_id" "$scratch/actions" >/dev/null
cp "$scratch/actions" "$scratch/before"
test_label=foreign-run
if remove_container owned-name 2>"$scratch/rejected"; then echo 'foreign label accepted' >&2; exit 1; fi
cmp "$scratch/actions" "$scratch/before"
test_daemon=down
if remove_container owned-name 2>"$scratch/rejected"; then echo 'daemon failure treated as verified absence' >&2; exit 1; fi
cmp "$scratch/actions" "$scratch/before"

# Run the actual EXIT cleanup in a subshell. Only verified resource absence
# may print true; an unavailable daemon must print false and fail cleanup.
for cleanup_case in up down; do
	# shellcheck disable=SC2034 # The extracted cleanup uses these variables.
	if (
		test_daemon=$cleanup_case; test_label=$nonce
		run_dir=$scratch/cleanup-$cleanup_case
		inputs=$run_dir/inputs
		# shellcheck disable=SC2030 # Each cleanup case deliberately isolates paths.
		logs=$run_dir/logs
		sut_name=owned-name; gcs_name=not-started; network_name=owned-network
		mkdir -p "$inputs" "$logs"
		: >"$run_dir/$sut_name.created"; : >"$run_dir/network.created"
		cleanup
	) >"$scratch/cleanup-$cleanup_case.output" 2>&1; then cleanup_rc=0; else cleanup_rc=$?; fi
	if [ "$cleanup_case" = up ]; then
		[ "$cleanup_rc" -eq 0 ]
		grep -Fx 'cleanup_verified=true' "$scratch/cleanup-$cleanup_case.output" >/dev/null
	else
		[ "$cleanup_rc" -eq 1 ]
		grep -Fx 'cleanup_verified=false' "$scratch/cleanup-$cleanup_case.output" >/dev/null
		if grep -Fx 'cleanup_verified=true' "$scratch/cleanup-$cleanup_case.output"; then exit 1; fi
	fi
	[ ! -e "$scratch/cleanup-$cleanup_case/inputs" ]
done

http_probe() { cp "$scratch/jwks" "$2"; printf 200; }
printf '%s\n' '{"keys":[{"kty":"OKP","kid":"fixture","crv":"Ed25519","x":"public"}]}' >"$scratch/jwks"
fingerprint_jwks valid >"$scratch/fingerprint"
[ "$(wc -c <"$scratch/fingerprint" | tr -d ' ')" -eq 65 ]
printf '%s\n' '{"keys":[{"kty":"OKP","kid":"fixture","x":"public","d":"private"}]}' >"$scratch/jwks"
if fingerprint_jwks private >"$scratch/private-fingerprint" 2>&1; then echo 'private JWKS accepted' >&2; exit 1; fi
# shellcheck disable=SC2031 # This is the outer fixture's log path.
[ ! -e "$logs/private-jwks.body" ] || { echo 'private JWKS response retained' >&2; exit 1; }

# A running service exceeding the observation cap is incomplete, not a product
# failure. A stopped service still fails. Both must retain a nonzero result.
for running_state in true false; do
	# shellcheck disable=SC2329,SC2034 # observe is extracted at runtime and uses these fakes/variables.
	if (
		http_probe() { : >"$2"; printf 503; }
		dkr() { printf '%s\n' "$running_state"; }
		stage_started=$(date +%s)
		sut_id=$owned_test_id
		observe capped 0
	) >"$scratch/observation-$running_state" 2>&1; then
		echo 'unready observation unexpectedly succeeded' >&2; exit 1
	else
		observation_rc=$?
	fi
	expected_rc=1
	[ "$running_state" != true ] || expected_rc=75
	[ "$observation_rc" -eq "$expected_rc" ]
done
grep -F 'INCOMPLETE observation_window_exceeded stage=capped ' "$scratch/observation-true" >/dev/null
if grep -F 'FAIL ' "$scratch/observation-true"; then exit 1; fi
grep -F 'FAIL stage=capped ' "$scratch/observation-false" >/dev/null
if grep -F 'INCOMPLETE ' "$scratch/observation-false"; then exit 1; fi

# Only an FS observation cap invokes the diagnostic; the capped non-FS cases
# above run with the real diagnostic function and must not make network probes.
# shellcheck disable=SC2034,SC2329 # The extracted observe uses these fakes.
if (
	http_probe() { : >"$2"; printf 000; }
	dkr() { printf true; }
	diagnose_fs_timeout() { echo timeout_diagnostic_called; }
	stage_started=$(date +%s)
	sut_id=$owned_test_id
	observe fs 0
) >"$scratch/fs-timeout" 2>&1; then exit 1; else [ "$?" -eq 75 ]; fi
[ "$(grep -c '^timeout_diagnostic_called$' "$scratch/fs-timeout")" -eq 1 ]

# All direct routes require the exact owned container attachment. Foreign
# labels/IDs must prevent IP inspection and every HTTP request.
for diagnostic_case in owned foreign_container foreign_network wrong_container wrong_network wrong_attachment invalid_ip; do
	# shellcheck disable=SC2034,SC2329 # Extracted diagnostic functions use these fakes and variables.
	(
		sut_id=$owned_test_id
		network_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
		network_name=owned-network
		dkr() {
			case "$1/$2/$4" in
				container/inspect/*NetworkSettings*)
					[ "$5" = "$sut_id" ]
					echo attachment >>"$scratch/probe-$diagnostic_case.calls"
					case "$diagnostic_case" in
						wrong_attachment) printf '%s 172.30.0.2\n' "$sut_id";;
						invalid_ip) printf '%s forbidden.example\n' "$network_id";;
						*) printf '%s 172.30.0.2\n' "$network_id";;
					esac;;
				container/inspect/*)
					[ "$5" = "$sut_id" ]
					echo container_identity >>"$scratch/probe-$diagnostic_case.calls"
					case "$diagnostic_case" in
						foreign_container) printf '%s foreign\n' "$sut_id";;
						wrong_container) printf '%s %s\n' "$network_id" "$nonce";;
						*) printf '%s %s\n' "$sut_id" "$nonce";;
					esac;;
				network/inspect/*)
					[ "$5" = "$network_id" ]
					echo network_identity >>"$scratch/probe-$diagnostic_case.calls"
					case "$diagnostic_case" in
						foreign_network) printf '%s foreign\n' "$network_id";;
						wrong_network) printf '%s %s\n' "$sut_id" "$nonce";;
						*) printf '%s %s\n' "$network_id" "$nonce";;
					esac;;
				*) return 99;;
			esac
		}
		curl() {
			printf '%s\n' "$*" >>"$scratch/probe-$diagnostic_case.curl"
			echo 'sensitive raw curl error' >&2
			case "$*" in
				*http://172.30.0.2:8080/*) printf 204;;
				*) return 99;;
			esac
		}
		if direct_ip=$(owned_container_ip "$sut_id"); then
			[ "$diagnostic_case" = owned ]
			probe_base=http://$direct_ip:8080
			diagnose_fs_timeout
			# Exercise the real production probe for every SUT endpoint.
			awk '$0 == "http_probe() {" {copy=1} copy {print} copy && /^}/ {exit}' "$script" >"$scratch/http-probe.sh"
			# shellcheck source=/dev/null
			. "$scratch/http-probe.sh"
			for probe_path in /livez /readyz /.well-known/openid-configuration /oidc/jwks.json; do
				[ "$(http_probe "$probe_path" "$scratch/probe.body")" = 204 ]
			done
		else
			[ "$diagnostic_case" != owned ]
		fi
	) >"$scratch/probe-$diagnostic_case.output" 2>&1
	if grep -E '172\.30|127\.0|sensitive raw|forbidden' "$scratch/probe-$diagnostic_case.output"; then exit 1; fi
	if [ "$diagnostic_case" = owned ]; then
		if grep -v -e '--connect-timeout 1 --max-time 2' "$scratch/probe-$diagnostic_case.curl"; then exit 1; fi
		grep -Fx 'diagnostic stage=fs_direct http=204 curl_exit=0 category=other' "$scratch/probe-$diagnostic_case.output" >/dev/null
		printf 'container_identity\nnetwork_identity\nattachment\n' >"$scratch/expected-probe-order"
		cmp "$scratch/expected-probe-order" "$scratch/probe-$diagnostic_case.calls"
		[ "$(wc -l <"$scratch/probe-$diagnostic_case.curl" | tr -d ' ')" -eq 5 ]
	else
		[ ! -e "$scratch/probe-$diagnostic_case.curl" ]
		case "$diagnostic_case" in foreign_*|wrong_container|wrong_network) if grep -Fx attachment "$scratch/probe-$diagnostic_case.calls"; then exit 1; fi;; esac
	fi
done

# Transport addresses are independent of the configured public issuer. Both
# SUT start paths and emulator initialization use the verified attachment.
# shellcheck disable=SC2016 # These assertions match literal source expressions.
{
grep -Fx 'issuer=http://127.0.0.1:19580' "$script" >/dev/null
grep -F -- '--env "GOAUTHY_ISSUER=$issuer"' "$script" >/dev/null
grep -F -- '"$probe_base$path"' "$script" >/dev/null
[ "$(grep -Fc 'probe_base=http://$(owned_container_ip "$sut_id"):8080' "$script")" -eq 2 ]
grep -Fx 'gcs_probe_base=http://$(owned_container_ip "$gcs_id"):$gcs_port' "$script" >/dev/null
grep -F '"$gcs_probe_base/storage/v1/b?project=readiness-fixture"' "$script" >/dev/null
grep -F '"$gcs_probe_base/storage/v1/b/$bucket/o"' "$script" >/dev/null
grep -F -- '--env "STORAGE_EMULATOR_HOST=$gcs_probe_base"' "$script" >/dev/null
if grep -E -- '--publish|gcs_host_port|\$issuer\$path|STORAGE_EMULATOR_HOST=http://gcs:' "$script"; then exit 1; fi
}

# Fixed curl categories must not expose stderr even for unexpected failures.
for probe_rc in 7 28 52 56 99; do
	# shellcheck disable=SC2329 # diagnostic_http_probe calls this fake.
	(
		curl() { echo 'sensitive raw curl error' >&2; printf 000; return "$probe_rc"; }
		diagnostic_http_probe fs_published http://127.0.0.1:19580/livez
	) >"$scratch/category-$probe_rc" 2>&1
	case "$probe_rc" in 7) category=connect_failed;; 28) category=timeout;; 52) category=empty_reply;; 56) category=receive_failed;; *) category=other;; esac
	grep -Fx "diagnostic stage=fs_published http=000 curl_exit=$probe_rc category=$category" "$scratch/category-$probe_rc" >/dev/null
	[ "$(wc -l <"$scratch/category-$probe_rc" | tr -d ' ')" -eq 1 ]
done

grep -F 'pull_request:' "$workflow" >/dev/null
grep -F 'paths:' "$workflow" >/dev/null
grep -F 'runs-on: ubuntu-latest' "$workflow" >/dev/null
grep -F 'timeout-minutes: 25' "$workflow" >/dev/null
if grep -E 'workflow_dispatch:|branches:|pull_request_target:|ci.yml|docker (push|build)' "$workflow"; then exit 1; fi
for path in scripts/e2e-v038-readiness.sh scripts/test-e2e-v038-readiness.sh .github/workflows/v038-readiness.yml; do grep -F -e "- '$path'" "$workflow" >/dev/null; done
echo 'PASS v0.3.8 shell guards: offline check, native host/server, unrelated issuer-port listener, owned cleanup/status, newline redaction, JWKS, timeout network diagnostics, workflow scope.'
