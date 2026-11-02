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
  *) echo 'unexpected Docker call in preflight guard' >&2; exit 99;;
esac
EOF
cat >"$scratch/bin/uname" <<EOF
#!/bin/sh
case "\$1" in -s) cat '$scratch/os';; -m) cat '$scratch/arch';; esac
EOF
cat >"$scratch/bin/nc" <<EOF
#!/bin/sh
[ -f '$scratch/occupied' ]
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
printf 'linux/amd64\n' >"$scratch/platform"; : >"$scratch/occupied"
expect_failure 'loopback port 19580 is occupied'
[ "$(wc -l <"$scratch/docker.calls" | tr -d ' ')" -eq 2 ]

# Exercise the real cleanup functions with an owned-ID fake, a foreign label,
# and an unavailable daemon. Only the verified owned ID may be stopped/removed.
for function in container_identity verified_identity verify_absent remove_container fingerprint_jwks observe; do
	awk -v name="$function" '$0 == name "() {" {copy=1} copy {print} copy && /^}/ {exit}' "$script" >>"$scratch/functions.sh"
done
# shellcheck source=/dev/null
. "$scratch/functions.sh"
nonce=owned-run
# shellcheck disable=SC2034 # The extracted production functions use logs.
logs=$scratch/logs
owned_test_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
test_label=$nonce
test_daemon=up
dkr() {
	case "$1/$2" in
		container/inspect)
			[ "$test_daemon" = up ] || return 125
			if [ "$3" = --format ]; then printf '%s %s\n' "$owned_test_id" "$test_label"; else echo "Error: No such container: $owned_test_id" >&2; return 1; fi;;
		logs/*) echo 'bounded synthetic log';;
		stop/*|rm/*) printf '%s\n' "$*" >>"$scratch/actions";;
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

http_probe() { cp "$scratch/jwks" "$2"; printf 200; }
printf '%s\n' '{"keys":[{"kty":"OKP","kid":"fixture","crv":"Ed25519","x":"public"}]}' >"$scratch/jwks"
fingerprint_jwks valid >"$scratch/fingerprint"
[ "$(wc -c <"$scratch/fingerprint" | tr -d ' ')" -eq 65 ]
printf '%s\n' '{"keys":[{"kty":"OKP","kid":"fixture","x":"public","d":"private"}]}' >"$scratch/jwks"
if fingerprint_jwks private >"$scratch/private-fingerprint" 2>&1; then echo 'private JWKS accepted' >&2; exit 1; fi
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

grep -F 'pull_request:' "$workflow" >/dev/null
grep -F 'paths:' "$workflow" >/dev/null
grep -F 'runs-on: ubuntu-latest' "$workflow" >/dev/null
grep -F 'timeout-minutes: 25' "$workflow" >/dev/null
if grep -E 'workflow_dispatch:|branches:|pull_request_target:|ci.yml|docker (push|build)' "$workflow"; then exit 1; fi
for path in scripts/e2e-v038-readiness.sh scripts/test-e2e-v038-readiness.sh .github/workflows/v038-readiness.yml; do grep -F -e "- '$path'" "$workflow" >/dev/null; done
echo 'PASS v0.3.8 shell guards: offline check, native host/server, port collision, owned cleanup, JWKS, workflow scope.'
