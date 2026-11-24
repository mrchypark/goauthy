# Encrypted Dated Backups Design

## Problem Statement & Goals

Rauthy `v0.36.2` writes backups to a local filesystem `backup_dir` via `AUTO_BACKUP_TASK` and `BACKUP_RESTORE_FROM` on top of Hiqlite. Because GoAuthy's default Kubernetes topology uses **no GoAuthy PVC** (`emptyDir` `DataDir` with Rhiza `Local: false` object-store DR), local-disk backup directories are not durable across Pod loss. Meanwhile, Rhiza's internal checkpoint garbage collection (GC) is a live-cluster retention mechanism, not a dated-backup archive or cross-bucket DR policy.

- **Goals**:
  - Export certified Rhiza `Local: false` (`standalone`, `cluster`) state into self-contained, `age`-encrypted USTAR bundles containing a verified `manifest.json`.
  - Restore encrypted bundles offline into a fresh target object-store prefix using Rhiza's verification and `PromoteCertifiedCurrent`.
  - Publish immutable Ed25519-signed catalog records (`Publish`, `ListCompleted`, `FetchCompleted`) and prune expired completed artifacts (`Prune`) on demand or via KV-lease scheduling (`internal/backupschedule`, [docs/backup-scheduling.md](backup-scheduling.md)).
- **Non-Goals & Scope Exclusions**:
  - **`standalone-local` (`Local: true`, `local/v1`)**: `goauthy-backup` supports **`Local: false` profiles only** and rejects `standalone-local` (`docs/no-pvc-dr.md`).
  - **Application master keys**: `age` recipient/identity keys encrypt the backup bundle only; GoAuthy's `OIDC` / `GAOP` master keys and cluster identity material are separate recovery inputs that must be backed up independently.
  - **In-place overwrite**: `Restore` never overwrites an active or dirty target prefix.

---

## Alternatives Considered

| Option | Decision | Rejection / Trade-off Rationale |
| --- | --- | --- |
| **Custom stdlib AES-GCM envelope format** | Rejected | Reimplements recipient key wrapping, streaming chunk authentication, and header parsing; `filippo.io/age` provides audited X25519/hybrid streaming encryption and standard CLI interoperability. |
| **Logical SQLite/SQL dump (`rhiza.DB` export)** | Deferred | `rhiza.DB` does not expose a backup/export handle or on-demand checkpoint trigger; physical object capture via Rhiza's public `checkpoint` and `recovery` managers preserves certified block hashes and avoids SQLite-level snapshot locking, at the cost of coupling backups to compatible Rhiza `Local: false` layouts. |
| **Object-store bucket replication alone** | Rejected as primary | Protects against bucket outage but not logical corruption, accidental deletion, or unencrypted-at-rest blast radius when credentials are shared with the live cluster. |
| **Kubernetes `CronJob` vs. KV-lease worker** | KV-lease worker (`internal/backupschedule`) | Replicated KV leases coordinate one active backup slot across 3-voter HA pods without requiring Kubernetes-specific scheduling; see [docs/backup-scheduling.md](backup-scheduling.md). |

---

## Proposed Architecture

Detailed package symbols live in [`internal/backup/README.md`](../internal/backup/README.md), [`internal/backupconfig/README.md`](../internal/backupconfig/README.md), and [`cmd/goauthy-backup/README.md`](../cmd/goauthy-backup/README.md); operator CLI flags and runbooks live in [docs/backup-operator.md](backup-operator.md).

### 1. Snapshot Export (`v1` Checkpoint-Backed & `v2` Archive-Only)

`backup.Export` constructs Rhiza's public `checkpoint.Manager` and `recovery.Manager` against `path.Join(ObjStorePrefix, ClusterID)` (configuration ID `1`) using `objstore.Bucket`:

- **Mode `v1` (checkpoint-backed, `format_version: 1`)**: Calls `BeginRecoverySnapshot` to acquire renewable paired **checkpoint pin** and **recovery pin** leases, reads the certified checkpoint (`CURRENT` pointer, immutable root, and data blocks) plus trailing archive `decisions` up to a fixed tip, and streams objects to private staging files under `-work-dir` with incremental SHA-256 verification.
- **Mode `v2` (archive-only, `format_version: 2`)**: When no checkpoint exists yet, `Manager.Load` + `DecisionsFrom(1)` captures the genesis-to-tip archive head (`recovery_mode: "archive-only"`, `archive_tip`) without a checkpoint base.

### 2. Encrypted Bundle & `manifest.json` Schema

Objects are packed under `objects/<source-relative-key>` alongside `manifest.json` (`internal/backup/manifest.go`) inside a USTAR tar stream encrypted with `filippo.io/age` (X25519 or hybrid recipients):

| Field (`SnapshotManifest`) | Type | Meaning |
| --- | --- | --- |
| `format_version` | `int` | `1` (checkpoint-backed) or `2` (archive-only) |
| `rhiza_version` | `string` | Pinned `github.com/mrchypark/rhiza` module version (`v0.27.4` in `go.mod`) |
| `source_prefix`, `cluster_id`, `config_id` | `string`, `string`, `uint64` | Source cluster namespace and configuration ID (`1`) |
| `checkpoint_index`, `checkpoint_root_hash`, `checkpoint_state_hash` | `uint64`, `string`, `string` | Certified checkpoint coordinates (zero/empty in `v2`) |
| `recovery_mode`, `archive_tip` | `string`, `uint64` | Set to `"archive-only"` and tip index in `v2` |
| `objects` | `[]ManifestObject` | Exact relative path, byte size, and lowercase SHA-256 digest per object |

### 3. Offline Restore & Target Arbitration

`backup.Restore` decrypts and extracts the bundle into a private `-work-dir` directory (enforcing `Limits`: max files, per-file bytes, and total bytes up to `8 GiB`), verifies every `objects/*` digest against `manifest.json`, and writes to a fresh target prefix:

- **Target ownership (`goauthy-restore.json`)**: Uses conditional `objstore.IfNotExists` on a restore marker (`goauthy-restore.json`) so concurrent restores cannot overwrite the same target prefix.
- **Certification**: Runs Rhiza verification (`DownloadAndVerifyRootFiles` / archive validation) and promotes `CURRENT` via `PromoteCertifiedCurrent` (or writes certified archive-only objects in `v2`).

### 4. Signed Catalog & Retention (`Publish`, `ListCompleted`, `FetchCompleted`, `Prune`)

`internal/backup/catalog.go` publishes immutable completion records under an isolated `catalog_prefix` (validated by `ValidateCatalogLocation` so `catalog_prefix` and `source_prefix` never overlap):

- **`CatalogEntry` (`signedEntry`)**: Contains `version`, `id`, `created_at` (publisher-supplied Unix timestamp), `source_prefix`, `catalog_prefix`, `size`, and `sha256`, wrapped with an Ed25519 `signature`.
- **Trust bundle rotation**: `ListCompleted` and `Prune` verify signatures against `1..32` (`MaxCatalogTrustKeys`) externally pinned PKIX public keys (`GOAUTHY_BACKUP_TRUST_KEY_FILE`), supporting overlap key rotation.
- **Retention (`Prune`)**: Deletes expired completed artifacts (default `30` UTC days, configurable `0..65535` days including `expire-all`) while retaining the newest verified keeper per `source_prefix`.

---

## Risks & Mitigations

1. **Multi-copy ephemeral disk amplification (`emptyDir`)**:
   - *Risk*: Export and restore materialize captured objects, verification copies, and the `age` ciphertext simultaneously under `-work-dir` (`*os.File` is used for `objstore` size/retry compatibility). On no-PVC pods with a `1Gi` `emptyDir`, larger snapshots risk `ENOSPC` or kubelet eviction.
   - *Mitigation*: Size `-work-dir` to at least `3×` expected snapshot size or run `goauthy-backup` on a dedicated operator volume.
2. **Catalog key-revocation deadlock**:
   - *Risk*: Removing a compromised Ed25519 public key from the trust bundle causes `ListCompleted` and `Prune` to fail closed on any retained record signed by that key ([docs/backup-operator.md](backup-operator.md)).
   - *Mitigation*: Rotate keys via overlap windows while old records age out, or manually purge records signed by a compromised key before removing it from the trust bundle.
3. **Anti-rollback & `CatalogEntry` / `SnapshotManifest` `SourcePrefix` gap**:
   - *Risk*: `CatalogEntry.CreatedAt` is self-reported (no independent freshness/anti-rollback proof), and `Restore` (`internal/backup/restore.go`) does not cross-check `SnapshotManifest.SourcePrefix` against `CatalogEntry.SourcePrefix`.
   - *Mitigation*: Restrict catalog write credentials to trusted backup publishers and verify target prefix/contents during DR drills.
4. **No GoAuthy startup fencing against `goauthy-restore.json`**:
   - *Risk*: `goauthy-restore.json` arbitrates concurrent `backup.Restore` calls, not live `goauthy` server startups. Starting `goauthy` against an in-progress or failed restore prefix can observe partial state.
   - *Mitigation*: Keep `goauthy` replicas scaled to `0` on the target prefix until `goauthy-backup restore` exits `0`, and never reuse a failed restore prefix.
5. **`v2` archive-only live-writer race & orphan accumulation**:
   - *Risk*: `v2` capture holds no retention pin and aborts if a checkpoint or GC sweep intervenes mid-export; failed `Publish` or `Restore` calls leave unlisted orphan objects (`Prune` never deletes unverified objects); `Prune` streams full keeper ciphertexts (`O(N × size)` readback).
   - *Mitigation*: Retry transient `v2` export failures (bounded 6-attempt backoff in `create`) and apply bucket lifecycle rules or manual sweeps to clean abandoned prefixes/orphans.
6. **Untested GCS transport & unqualified `v2` Kind gate**:
   - *Risk*: `goauthy-backup` live transport qualification covers S3-compatible stores (MinIO/VersityGW); GCS transport and `v2` Kind DR remain unqualified ([docs/backup-operator.md](backup-operator.md)).

---

## Historical Verification Reference

Historical `Rhiza v0.12.3` Kind/MinIO qualification runs (including `scripts/e2e-kind-backup-restore.sh` and `2026-09-09` scheduled/rotation gates) are recorded in [docs/status.md](status.md) and [docs/features.md](features.md).
