# Outbound SCIM Provisioning (`internal/scim`)

## Overview
Provides a stateless, bounded outbound SCIM 2.0 HTTP client for Users and Groups, a Rhiza-backed durable outbox for coalesced retries, an encrypted SCIM client configuration store, and an immutable local-to-remote user mapping store.

## Interface
- `[scim.go:Client]`, `[scim.go:New]`, `[scim.go:NewClient]` — Outbound HTTPS SCIM 2.0 client enforcing no-redirect and bounded response sizes (`64 KiB` default).
- `[scim.go:User]`, `[scim.go:Request]`, `[scim.go:Result]`, `[scim.go:Action]`, `[scim.go:DeletePolicy]`, `[scim.go:Config]` — User reconciliation types (`SyncUser`, `DeleteUser`, `Reconcile`) and action/delete policy constants (`ActionCreated`, `ActionUpdated`, `ActionUnchanged`, `ActionDeleted`, `ActionUnlinked`, `ActionNoop`, `DeleteRemote`, `UnlinkRemote`).
- `[groups.go:Group]`, `[groups.go:GroupMember]`, `[groups.go:GroupRequest]`, `[groups.go:Client.SyncGroup]`, `[groups.go:Client.DeleteGroup]`, `[groups.go:Client.ReconcileGroup]`, `[groups.go:ErrGroupTooLarge]`, `[groups.go:ErrInvalidGroup]` — Outbound SCIM Group reconciliation (max `4096` members).
- `[outbox.go:Outbox]`, `[outbox.go:NewOutbox]`, `[outbox.go:OutboxConfig]`, `[outbox.go:Job]`, `[outbox.go:Reconciler]`, `[outbox.go:ClientResolver]` — Durable outbox with `Enqueue`, `EnqueueUser`, `EnqueueGroup`, `EnqueueTombstoneDelete`, `Step`, `Lookup`, `LookupGroup`, `Cleanup`, and `[outbox.go:SupersedeGroupProjection]`.
- `[config_store.go:ConfigStore]`, `[config_store.go:NewConfigStore]`, `[config_store.go:ClientConfig]`, `[config_store.go:EnvelopeKeyring]` — Encrypted per-client SCIM endpoint, bearer token (`scim/client-config` envelope), and CA PEM store (`scim_client_config`).
- `[mapping.go:UserMappingStore]`, `[mapping.go:NewUserMappingStore]` — Provider-scoped durable mapping (`scim_user_mappings`) between `local_external_id` and `remote_user_id`.
- Sentinels: `[scim.go:ErrInvalidConfig]`, `[scim.go:ErrInvalidUser]`, `[scim.go:ErrProtocol]`, `[scim.go:ErrRetryable]`, `[scim.go:ErrAmbiguous]`, `[scim.go:ErrIdentifierChanged]`, `[outbox.go:ErrOutboxInvalid]`, `[outbox.go:ErrOutboxLease]`, `[outbox.go:ErrOutboxStale]`.

## Invariants
- `[outbox.go:Outbox]` never persists SCIM Bearer credentials in outbox job rows; `[outbox.go:ClientResolver]` resolves credentials dynamically at `Step` time.
- `[mapping.go:UserMappingStore]` links are immutable once written; a changed `remote_user_id` for an existing `(client_id, local_external_id)` fails closed with `ErrIdentifierChanged`.
- `[groups.go:Client.SyncGroup]` falls back to `displayName` lookup only when `externalId` has no match and the remote group is unmanaged (empty `externalId`).
- `[scim.go:New]` disables HTTP redirects and enforces HTTPS (unless explicitly overridden for trusted test transports).

## Side Effects
- Sends outbound HTTPS `GET`/`POST`/`PUT`/`DELETE` requests to external SCIM `/Users` and `/Groups` endpoints.
- Persists and leases outbox jobs, client configs, and user mappings in `*rhiza.DB`.

## Verification
- Run: `go test ./internal/scim`
