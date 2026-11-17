# Global / Common ID Branding (`docs/global-id-branding.md`)

## Problem Statement & Goals

Previously, GoAuthy stored central/global branding (used on central account, admin, and error pages) inside the OAuth client branding namespace under `client_id: "goauthy"` (or `"rauthy"` on deployments migrated from Rauthy, the upstream Rust OIDC reference). Sharing the OAuth client namespace caused ownership collisions, accidental deletion/overwrites, and coupling between OAuth client lifecycle and central UI branding.

- **Goals**:
  - Separate common branding into dedicated Schema 114 tables (`global_brand_themes`, `global_brand_logos`) and dedicated `/auth/v1/branding/*` endpoints (`internal/branding`).
  - Keep central account, admin, and error pages bound to the common brand while allowing OAuth client login pages to inherit common themes and fall back to common logos independently.
  - Provide an explicit, operator-confirmed one-time legacy resolution workflow so existing `goauthy` branding rows are neither silently overwritten nor auto-attributed.
- **Non-Goals**:
  - Automatic migration of `"rauthy"` or arbitrary client IDs into common branding (operators recreate those in the UI).
  - Mixed-version rolling upgrades or downgrades to binaries that still share the client namespace.

---

## Alternatives Considered

| Option | Decision | Trade-off / Rejection Rationale |
| --- | --- | --- |
| **Auto-migrate `"goauthy"` rows during Schema 114** | Rejected | Cannot distinguish whether an existing `"goauthy"` row belongs to central branding or an OAuth client named `"goauthy"`; risks exposing or overwriting client branding. |
| **Remove `client_id` from theme JSON completely** | Deferred | Retaining `client_id: "goauthy"` in the common theme document preserves JSON compatibility with existing theme parsers; `PUT /auth/v1/branding/theme` enforces `client_id == "goauthy"`. |
| **Reserve `"goauthy"` across all client creation APIs** | Partial | Anonymous Dynamic Client Registration (DCR) reserves `"goauthy"` alongside the configured bootstrap client ID (`internal/dcr`), while legacy resolution gates `goauthy` client branding reads/writes until resolved. |

---

## Proposed Architecture

Related package contracts: [`internal/branding/README.md`](../internal/branding/README.md), [`internal/clients/README.md`](../internal/clients/README.md), [`internal/dcr/README.md`](../internal/dcr/README.md), [`internal/storage/README.md`](../internal/storage/README.md), and [`docs/openapi.md`](openapi.md).

### 1. Admin UI & Inheritance Semantics

Administrators manage common branding at `<issuer-path>/auth/v1/admin/branding` (configured via `GOAUTHY_ISSUER`) under the **Common brand** editor:

- **Common name vs. login title**: The **common name** (for example, `GoAuthy ID`) sets the central display name for account/admin shells and is independent of the per-locale **login title** (`LoginCopy` title shown on sign-in pages).
- **Central pages**: Account dashboard, admin pages, and central error pages always use the common name, common theme, and common logo.
- **Application login pages**: Use the client's saved theme if present, or inherit the entire common theme when absent. Application-specific logos override the common logo independently of theme inheritance.
- **Resetting defaults**: **Reset common theme to defaults** and **Remove common logo** clear the stored common theme/logo so central pages fall back to built-in defaults and inheriting apps fall back accordingly.

### 2. Schema 114 & Namespace Isolation

- **Schema 114** (`internal/storage/migrate.go`) runs automatically on `cmd/goauthy` startup after **bootstrap policy schema 113** (which isolates configured bootstrap client policy from managed clients).
- Schema 114 creates `global_brand_themes`, `global_brand_logos`, and `branding_legacy_resolution` without copying existing `client_themes` or `client_logos` rows.
- Anonymous DCR reserves `"goauthy"` alongside the configured bootstrap client ID so unauthenticated dynamic registration cannot claim `"goauthy"`.

### 3. Common & Legacy HTTP Endpoints

All mutating endpoints enforce administrator/CSRF guards (for browser sessions) or `Clients`-scoped API-key rights with atomic revocation checks, SVG upload sanitization, and page CSP.

| Endpoint | Auth / Right | Behavior & Notes |
| --- | --- | --- |
| `GET /auth/v1/branding/theme` | Public | Returns the active common theme JSON (built-in default if unset). |
| `GET /auth/v1/branding/theme/{version}` | Public | Versioned CSS/theme asset (`version` is an `int64` token; cached with `max-age=31104000, public`). |
| `PUT /auth/v1/branding/theme` | Admin or `Clients.Update` | Saves the common theme; rejects any `client_id != "goauthy"` with `400 Bad Request`. |
| `DELETE /auth/v1/branding/theme` | Admin or `Clients.Delete` | Resets common theme to built-in defaults (`Clear-Site-Data: "cache"`). |
| `GET /auth/v1/branding/logo` | Public | Returns the active common logo (supports `?size=small\|medium\|large\|svg` or default SVG/raster). |
| `PUT /auth/v1/branding/logo` | Admin or `Clients.Update` | Uploads sanitized SVG or raster logo (`Clear-Site-Data: "cache"`). |
| `DELETE /auth/v1/branding/logo` | Admin or `Clients.Update` | Removes common logo (falls back to built-in default). |
| `GET /auth/v1/branding/legacy` | Admin or `Clients.Read` | Returns whether `branding_legacy_resolution` is resolved and whether legacy `goauthy` theme/logo rows exist. |
| `GET /auth/v1/branding/legacy/theme` | Admin or `Clients.Read` | Inspects legacy `goauthy` theme (returns defaults if absent; check `/legacy` first). |
| `GET /auth/v1/branding/legacy/logo` | Admin (mutating check) or `Clients.Update` | Inspects legacy `goauthy` non-favicon logo (`404` if absent). |
| `POST /auth/v1/branding/legacy/resolve` | Admin or `Clients.Update` | One-time resolution; returns `204 No Content` on success, `400` on invalid body, `403` if unauthorized, `503` on conflict/already resolved. |

### 4. Upgrade & One-Time Legacy Resolution Workflow

1. **Expect built-in defaults after upgrade**: Immediately after Schema 114 migration, central pages use built-in defaults until common branding is saved or legacy resolution runs.
2. **Inspect legacy state and OAuth clients**: Query `GET /auth/v1/branding/legacy`, `/legacy/theme`, `/legacy/logo`, and inspect existing OAuth clients (`GET /auth/v1/clients` or the Admin UI Clients tab) to verify whether `"goauthy"` (or `"rauthy"`) is an actual OAuth client or legacy common branding. Neither client existence nor an ID alone proves ownership.
3. **Resolve `"goauthy"` once**: Submit `POST /auth/v1/branding/legacy/resolve` with explicit boolean choices (`confirm_client_ownership` must be `true`, otherwise `400 Bad Request`):
   ```json
   {
     "confirm_client_ownership": true,
     "copy_theme": true,
     "copy_logo": true
   }
   ```
   - If common branding already exists at the destination and `copy_theme` or `copy_logo` is `true`, clear the destination first (`DELETE /auth/v1/branding/theme` or `DELETE /auth/v1/branding/logo`) before retrying.
   - If there is no legacy `goauthy` theme or non-favicon logo, the first authorized client-branding mutation on `goauthy` automatically records an empty resolution so later edits do not require manual resolution.
   - For `"rauthy"` or other legacy IDs, recreate common branding manually in `/auth/v1/admin/branding`.

---

## Risks & Mitigations

1. **No Schema-114 DB-level rolling-upgrade fence**:
   - *Risk*: Unlike Schema 109 triggers, Schema 114 does not install SQLite triggers blocking pre-114 binaries from writing `client_themes`/`client_logos` for `goauthy`. Running mixed versions or rolling back can corrupt branding ownership.
   - *Mitigation*: Perform a full-stop upgrade without mixed-version peers or rollbacks to pre-114 binaries.
2. **Non-idempotent `POST /auth/v1/branding/legacy/resolve` & `503` ambiguity**:
   - *Risk*: `legacy/resolve` has no idempotency key and returns `503 Service Unavailable` (`"Resolution unavailable; inspect state before retrying"`) both when already resolved and when destination data conflicts (`internal/branding/legacy_http.go`).
   - *Mitigation*: On timeout or `503`, always inspect `GET /auth/v1/branding/legacy` and `/auth/v1/branding/theme` / `/logo` before retrying.
3. **Unresolved `goauthy` client read/write gating & API asymmetries**:
   - *Risk*: Until resolution completes, client-scoped `goauthy` theme/logo mutations fail with `404` (`clients.ErrNotFound`), `DELETE` client fails with `409`, `DELETE /auth/v1/branding/theme` requires `Clients.Delete` while `DELETE /auth/v1/branding/logo` requires `Clients.Update`, `GET /auth/v1/branding/legacy/logo` enforces `Clients.Update` + mutating browser check, and `legacy_http.go` `GET` handlers do not reject non-`GET` methods with `405`.
   - *Mitigation*: Complete `legacy/resolve` immediately post-upgrade and use the documented API-key scopes when automating cleanup/inspection.
4. **Logo deletion cache invalidation**:
   - *Risk*: `DELETE /auth/v1/branding/logo` omits `Clear-Site-Data: "cache"` (unlike `PUT` logo and `PUT`/`DELETE` theme).

---

## Verification

`cmd/goauthy` embeds admin JS and HTML templates directly into the binary; rebuild and restart `cmd/goauthy` after UI asset edits.

```sh
go build ./cmd/goauthy
go test ./internal/branding ./internal/clients ./internal/dcr ./internal/storage
```
