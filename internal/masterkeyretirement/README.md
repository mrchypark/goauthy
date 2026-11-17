# masterkeyretirement

## Overview
`masterkeyretirement` exposes the authenticated HTTP operator API (`/auth/v1/master_key_retirement`) for inspecting and advancing the replicated master-key retirement barrier (`prepare`, `fence`, `ready`, `abort`).

## Interface
- `Handler`, `NewHandler`, and `Handler.ServeHTTP` in [http.go](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L30-L93).

## Invariants
- Accepts API-key authentication only (`"Secrets"` resource with `Read` for `GET`, `Create` for `prepare`, `Update` for `fence`/`ready`, `Delete` for `abort`) and rejects cross-site `Sec-Fetch-Site` headers and non-empty query strings ([http.go:ServeHTTP](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L47-L108), [http.go:mutate](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L157-L233)).
- `members` is copied at construction (`NewHandler`), and `ready` requires either 1 standalone member or 3 cluster members ([http.go:NewHandler](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L39-L42), [http.go:ready](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L262-L268)).
- JSON decoding enforces `Content-Type: application/json`, an 8 KiB body limit, no unknown fields, no duplicate keys, and no case-insensitive key collisions at depth 0 ([http.go:decodeJSON](file:///Users/cypark/Documents/project/goauthy/internal/masterkeyretirement/http.go#L270-L372)).

## Side Effects
- Delegates guarded reads and state transitions to `storage.LoadMasterKeyRetirementGuarded`, `storage.PrepareMasterKeyRetirementGuarded`, `storage.FenceMasterKeyRetirementGuarded`, `storage.ReadyMasterKeyRetirementGuarded`, and `storage.AbortMasterKeyRetirementGuarded`.
- Writes JSON responses with `Cache-Control: no-store`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff`.

## Verification
- Run: `go test ./internal/masterkeyretirement`
