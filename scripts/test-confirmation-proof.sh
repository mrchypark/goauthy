#!/bin/sh
# Test-only overlays: intercept the real creator request without production hooks.
# Requires Go, awk and jq. Does not edit dependency sources or another checkout.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
if [ "${CONFIRMATION_BASELINE:-0}" = 1 ]; then
 git show a4515ac517affedf55f073d625d91c9a3d4b17cc:internal/browser/store.go > "$tmp/store-source.go"
else
 cp internal/browser/store.go "$tmp/store-source.go"
fi
awk '{gsub(/storage.Execute\(ctx, s.db,/, "confirmationExecute(ctx, s.db,"); gsub(/s.db.Query\(ctx,/, "confirmationQuery(ctx, s.db,"); print}' "$tmp/store-source.go" > "$tmp/store.go"
# Leave the import used even if future source changes remove unrelated calls.
printf '\nvar _ = storage.Execute\n' >> "$tmp/store.go"
# Coverage also builds the non-test package. Put the test-only wrappers in the
# virtual production file and remove their duplicate declarations from the test.
awk '/^type confirmationKey / {copy=1} /^func confirmationFixture/ {copy=0} copy {print}' internal/browser/confirmation_overlay_test.go >> "$tmp/store.go"
awk '/^type confirmationKey / {skip=1} /^func confirmationFixture/ {skip=0} !skip {print}' internal/browser/confirmation_overlay_test.go > "$tmp/confirmation_overlay_test.go"
awk '{gsub(/db.Execute\(ctx, request\)/, "confirmationRecoveryExecute(ctx, db, request)"); print}' internal/storage/migrate.go > "$tmp/migrate.go"
jq -n --arg recovery "${CONFIRMATION_RECOVERY_OVERLAY:-0}" --arg store "$root/internal/browser/store.go" --arg newstore "$tmp/store.go" --arg test "$root/internal/browser/confirmation_overlay_test.go" --arg newtest "$tmp/confirmation_overlay_test.go" --arg migrate "$root/internal/storage/migrate.go" --arg newmigrate "$tmp/migrate.go" '{Replace: (if $recovery == "1" then {($migrate):$newmigrate} else {($store):$newstore,($test):$newtest} end)}' > "$tmp/overlay.json"
go test -overlay="$tmp/overlay.json" -tags=confirmationproof "$@"
