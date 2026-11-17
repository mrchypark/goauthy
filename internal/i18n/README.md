# i18n

## Overview
`i18n` provides embedded UI message catalogs (`en`, `ko`) for browser authentication pages and deterministic `Accept-Language` / cookie language resolution for both UI pages and account/email locales.

## Interface
- `Messages`, `Resolve`, `UILanguageFromRequest`, `UserLanguageFromRequest`, `ValidUserLanguage`, and `MessagesFor` in [catalog.go](file:///Users/cypark/Documents/project/goauthy/internal/i18n/catalog.go#L28-L288).
- `catalog/` embeds `en.json` and `ko.json` via `go:embed`.

## Invariants
- Embedded catalogs are validated at package initialization (`mustCatalog` panics on missing, duplicate, empty, or unknown keys) and exposed as immutable `Messages` structs ([catalog.go:mustCatalog](file:///Users/cypark/Documents/project/goauthy/internal/i18n/catalog.go#L45-L74)).
- `Resolve` and `UILanguageFromRequest` only select shipped UI catalogs (`en`, `ko`), whereas `UserLanguageFromRequest` and `ValidUserLanguage` support the 9 account/email languages (`de`, `en`, `fr`, `ko`, `nb`, `nl`, `ru`, `uk`, `zhhans`) ([catalog.go:UILanguageFromRequest](file:///Users/cypark/Documents/project/goauthy/internal/i18n/catalog.go#L94-L145)).
- Header parsing enforces bounded length (`maxAcceptLanguageLength = 1024`, `maxLanguageRanges = 16`) and strict RFC 9110 q-values, failing safe to `"en"` ([catalog.go:resolve](file:///Users/cypark/Documents/project/goauthy/internal/i18n/catalog.go#L147-L265)).

## Side Effects
- None (pure in-memory resolution over embedded JSON catalogs).

## Verification
- Run: `go test ./internal/i18n`
