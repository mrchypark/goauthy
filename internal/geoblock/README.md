# geoblock

## Overview
`geoblock` implements country-based HTTP request admission (`Whitelist` / `Blacklist`) and IP-to-location resolution using trusted proxy headers and MaxMind MMDB databases.

## Interface
- Errors, types, and policy: `ErrInvalidCountry`, `ErrSpoofedHeader`, `ErrAmbiguousHeader`, `ListType` (`Whitelist`, `Blacklist`), `Decision` (`Unknown`, `Allow`, `Deny`), `NormalizeCountry`, `Policy`, `NewPolicy`, `Policy.Decide`, and `CountryLookup` in [geoblock.go](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L16-L98).
- MaxMind reader: `MaxMindReader`, `OpenMaxMind`, `MaxMindReader.Country`, and `MaxMindReader.Close` in [geoblock.go](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L100-L148); `MaxMindReader.Location` in [location.go](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/location.go#L20-L34).
- HTTP helpers and middleware: `HeaderCountry` and `Middleware` in [geoblock.go](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L152-L218); `RequestLocation` in [location_header.go](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/location_header.go#L15-L37).
- `testdata/` contains test MMDB fixtures (`GeoIP2-Country-Test.mmdb`, `LICENSE-MIT`).

## Invariants
- `NormalizeCountry` accepts only 2-letter uppercase ASCII ISO 3166-1 alpha-2 codes; `normalizeDatabaseCountry` validates ASCII letters before uppercasing to avoid Unicode case-folding expansion ([geoblock.go:NormalizeCountry](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L38-L43), [geoblock.go:normalizeDatabaseCountry](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L130-L137)).
- `HeaderCountry` and `RequestLocation` trust a configured country/location header only when the direct TCP peer (`loginpolicy.PeerIP`) is within `trusted`; `HeaderCountry` rejects untrusted or ambiguous headers fail-closed ([geoblock.go:HeaderCountry](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L152-L185), [location_header.go:RequestLocation](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/location_header.go#L15-L37)).
- `Middleware` denies with a generic `403 Forbidden` (`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`) without exposing lookup results or distinguishing failure reasons ([geoblock.go:Middleware](file:///Users/cypark/Documents/project/goauthy/internal/geoblock/geoblock.go#L188-L224)).

## Side Effects
- `OpenMaxMind` opens and memory-maps an `.mmdb` file on disk (`MaxMindReader.Close` releases it).
- `Middleware` intercepts HTTP requests and short-circuits denied requests with `403 Forbidden`.

## Verification
- Run: `go test ./internal/geoblock`
