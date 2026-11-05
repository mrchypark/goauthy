#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
runner=$root/scripts/e2e-ely-standalone.sh
sh -n "$runner"
sh "$runner" --check >/dev/null
grep -Fq '{ rg --files cmd internal test/e2e/browser;' "$runner" || { echo 'runner source digest must cover all built browser-package sources' >&2; exit 1; }
base_tests=$(sed -n "s/^base_tests='\(.*\)'$/\1/p" "$runner")
extra_tests=$(sed -n "s/^extra_tests='\(.*\)'$/\1/p" "$runner")
[ "$(printf '%s\n' "$base_tests" | wc -w | tr -d ' ')" -eq 15 ] || { echo 'runner first-pass base selection must contain 15 tests' >&2; exit 1; }
[ "$(printf '%s\n' "$extra_tests" | wc -w | tr -d ' ')" -eq 4 ] || { echo 'runner extra selection must contain four tests' >&2; exit 1; }
[ "$(grep -c '^for test_name in TestThemePersistVerify TestClientLogoPersistVerify' "$runner")" -eq 1 ] || { echo 'runner restart selection must contain the two persistence verifiers' >&2; exit 1; }
[ "$(grep -c 'run_test TestPasswordResetAcrossPods' "$runner")" -eq 1 ] || { echo 'runner restart selection must contain password reset' >&2; exit 1; }
printf '%s\n' "$base_tests" | grep -qw TestThemeLoginUI || { echo 'runner base selection omitted theme login' >&2; exit 1; }
for additional in TestAccountPasskeyUIAcrossPods TestSaaSProvidersCatalog TestProviderRegistrationLive; do
	if printf '%s\n' "$base_tests" | grep -qw "$additional"; then
		echo "runner base selection duplicated $additional" >&2
		exit 1
	fi
done
if GOAUTHY_ELY_E2E_SLOT= sh "$runner" --run >/dev/null 2>&1; then
	echo 'runner accepted a run without a reserved parent slot' >&2
	exit 1
fi
if GOAUTHY_ELY_E2E_SLOT= sh "$runner" --run-extra >/dev/null 2>&1; then
	echo 'runner accepted an add-on run without a reserved parent slot' >&2
	exit 1
fi
if GOAUTHY_ELY_E2E_SLOT= sh "$runner" --run-boundary >/dev/null 2>&1; then
	echo 'runner accepted a boundary run without a reserved parent slot' >&2
	exit 1
fi
for port in 0 08080 1023 65532 bad '18480;exit 0'; do
	if GOAUTHY_ELY_E2E_PORT="$port" sh "$runner" --check >/dev/null 2>&1; then
		echo 'runner accepted an invalid port' >&2
		exit 1
	fi
done
if sh "$runner" --unknown >/dev/null 2>&1; then
	echo 'runner accepted an unknown mode' >&2
	exit 1
fi
echo 'Ely runner syntax and pre-execution guards passed; no server/build/browser started.'
