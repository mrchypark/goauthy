#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
sed 's/s\.db\.Query(ctx, /accountDataProofQuery(ctx, s.db, /g' internal/identity/store.go > "$tmp/store.go"
cat >> "$tmp/store.go" <<'GO'

func accountDataProofQuery(ctx context.Context, db *rhiza.DB, req rhiza.QueryRequest) (rhiza.QueryResponse, error) {
 if n, ok := ctx.Value("account-data-proof-query-count").(*int); ok { *n++ }
 return db.Query(ctx, req)
}
GO
jq -n --arg old "$root/internal/identity/store.go" --arg new "$tmp/store.go" '{Replace:{($old):$new}}' > "$tmp/overlay.json"
if [ -f internal/identity/account_data.go ]; then
 sed 's/s\.db\.Query(ctx, /accountDataProofQuery(ctx, s.db, /g' internal/identity/account_data.go > "$tmp/account_data.go"
 jq --arg old "$root/internal/identity/account_data.go" --arg new "$tmp/account_data.go" '.Replace[$old]=$new' "$tmp/overlay.json" > "$tmp/next.json"
 mv "$tmp/next.json" "$tmp/overlay.json"
fi
GOMAXPROCS=2 go test -p 1 -overlay="$tmp/overlay.json" -tags=accountdataproof ./internal/account -run '^TestDashboardIdentitySingleSnapshot$' -count=1 -v
