# No-PVC and Object-Store DR Contract

## Problem Statement & Goals

GoAuthy is an OAuth 2.0 / OIDC identity provider built on **Rhiza** (an embedded replicated/consensus storage engine wrapping SQLite and **LatticeDB**) and a minimally patched **Fosite** fork. The default Kubernetes deployment uses **no GoAuthy PVC** (`DataDir` is a disposable `emptyDir`), relying on external S3 or GCS object storage for durable disaster recovery (DR).

For durable single-node operation, GoAuthy provides two distinct profiles configured via `GOAUTHY_RHIZA_PROFILE`:

| Profile | Rhiza Mode | Local `DataDir` | Object Store | Backup/Restore (`goauthy-backup`) | Periodic GC |
| --- | --- | --- | --- | --- | --- |
| `standalone` | `Local: false` | `emptyDir` | Required (S3/GCS) | Supported (`age` + Ed25519) | Disabled (`0`) |
| `standalone-local` (opt-in) | `Local: true` (`local/v1`) | `emptyDir` | Required (S3/GCS) | Rejected (incompatible format) | Enabled (`1h` / `24h` / `3` snapshots) |

- **Non-goals**: Automatic migration between `Local: false` (`standalone` / `cluster`) and `Local: true` (`standalone-local`), mixed-version peers, and in-place downgrade are unsupported. A local-directory copy is not a default DR mechanism.

---

## Alternatives Considered

| Option | Decision | Trade-off / Rejection Rationale |
| --- | --- | --- |
| **PVC-backed SQLite + volume snapshots** | Rejected as default | Couples pod scheduling and DR to node/AZ-local storage classes and CSI snapshot availability. |
| **External managed DB (Postgres/MySQL)** | Rejected | Introduces a separate database service, network hop, and external HA/backup operational surface. |
| **Rhiza `Local: true` (`standalone-local`) + `/goauthy-rhiza-init`** | Opt-in (`v0.24.0`) | Separates crash recovery (`Open`/`Close`) from service startup without a Rhiza operator, at the cost of `goauthy-backup` incompatibility and single-writer fencing reliance. |
| **Adapting `goauthy-backup` for `local/v1`** | Deferred | Requires a logical `*rhiza.DB` export/import boundary or `local/v1` codec adapter; currently rejected to avoid silent format corruption. |

---

## Opt-in `standalone-local` Profile

`GOAUTHY_RHIZA_PROFILE=standalone-local` runs a single GoAuthy process using Rhiza `Local: true` (`local/v1` archive format), required S3 or GCS object storage, and `before-ack` durability (`EnsureDurable` + archive `SyncThrough` before acknowledging writes; `Async` is unsupported because it introduces a data-loss window).

- **Configuration constraints (`internal/storage/config.go`)**:
  - Rejects `GOAUTHY_RHIZA_CHECKPOINT_INTERVAL` overrides and uses Rhiza's 15-minute default (a `1s` override caused `node is not ready` during schema migration).
  - Rejects `GOAUTHY_BACKUP_ENABLED=true` and all `goauthy-backup` commands (`export`, `restore`, `create`, `publish`, `list`, `fetch`, `prune`).
  - Rejects `GOAUTHY_RHIZA_OBJECT_STORE_GC_*` overrides: `RhizaProfileStandaloneLocal` unconditionally sets `ObjStoreGCInterval=1h`, `ObjStoreGCGracePeriod=24h`, and `CheckpointRetainCount=3` (zero does not disable GC in Rhiza Local mode).
  - Rejects `cluster`-only peer/member/admin-token variables and `Azure` object storage.

### Init and Main Process (`/goauthy-rhiza-init`)

Rhiza `v0.24.0` uses an application-owned `Open`/`Close` init-container flow ([tagged Rhiza guide](https://github.com/mrchypark/rhiza/blob/v0.24.0/docs/local-init-container-recovery.md)):

1. **Init container (`/goauthy-rhiza-init`)**: Built into the GoAuthy image (`deploy/standalone-local/statefulset-patch.yaml`). It opens the Local database with the same `ClusterID`, `NodeID`, `DataDir`, and object-store configuration as `main`, waits for `Open` (bounded by a hardcoded 2-minute timeout in `cmd/goauthy-rhiza-init/main.go`), and calls `Close` without running application SQL, migrations, or HTTP listeners. Any nonzero error blocks `main` from starting.
2. **Main container (`goauthy`)**: Mounts the same `DataDir` (`emptyDir`) read/write with identical object-store credentials. Rhiza validates the **local binding** (the local identity/history marker persisted inside `DataDir`, which survives container restarts in the same Pod but is lost when the Pod is deleted) and **archive binding** (remote `local/v1` archive identity), reconciling any uncheckpointed tail without a blind checkpoint redownload when histories match.
3. **Fail-closed greenfield rule**:
   - When a **local binding exists** in `DataDir`, missing, corrupt, partial, inaccessible, or maintenance-held remote history fails closed; preserve remote objects and investigate rather than clearing the prefix.
   - When **both the Local archive and local binding are absent** (true on every Pod replacement or prefix typo), Rhiza cannot distinguish a first install from total loss of remote history. Operators must verify via external inventory before authorizing a greenfield namespace.

---

## Current v0.24.0 Integration

GoAuthy pins Rhiza `v0.24.0` at [`e9cefbbb260d2f62b2a47971de3f091720b42a68`](https://github.com/mrchypark/rhiza/commit/e9cefbbb260d2f62b2a47971de3f091720b42a68) (Go `1.27.4+`).

### Verification Commands

```sh
go test -mod=readonly -p 1 ./internal/storage ./cmd/goauthy-rhiza-init -run 'TestStandaloneLocal|TestRestoreInit' -count=1 -timeout=5m
go test -mod=readonly -race -p 1 ./internal/storage ./cmd/goauthy-rhiza-init ./cmd/goauthy -run 'TestStandaloneLocal|TestRestoreInit' -count=1 -timeout=5m
scripts/test-rhiza-local-upgrade.sh
scripts/test-rhiza-local-upgrade.sh --race
```

`scripts/test-rhiza-local-upgrade.sh` verifies cross-version `v0.21.2 -> v0.24.0` retained-directory upgrade, abrupt no-`Close` recovery, total `DataDir` loss recovery, keyring-sealed synthetic blob continuity, and negative node/prefix rejection, while [PR176 final CI](https://github.com/mrchypark/goauthy/actions/runs/42146836993) verified S3/GCS/Azure SDK contracts and the Linux cross-version oracle.

### Qualification Boundary

- **Qualified**: Single-node filesystem `Open`/`Close` recovery, `v0.21.2 -> v0.24.0` Local upgrade, and SDK object-version/metadata copy checks.
- **Not qualified on `v0.24.0`**: Packaged S3/GCS application recovery, Kubernetes deployment (`deploy/standalone-local`), managed HA, writer fencing, real account/token continuity, arbitrary production-data migration, and production-cloud parity.

---

## Risks & Mitigations

1. **Split-brain / concurrent archive-head overwrite**:
   - *Risk*: `One replica` or `Recreate` rollout is not fencing. Force-deleting a `Terminating` Pod on an unreachable node lets a replacement `goauthy-0` Pod start with an empty `DataDir` and write concurrently to the same `local/v1` prefix.
   - *Mitigation*: Do not force-delete Pods without node-level fencing until object-store writer-epoch fencing is implemented.
2. **Periodic GC vs. Issue #105**:
   - *Risk*: `standalone` (`Local: false`) keeps periodic GC disabled (`0`) because Issue #105 remains open, accepting unbounded object-store growth. Conversely, `standalone-local` (`Local: true`) unconditionally enables Rhiza's default `1h` / `24h` / `3`-snapshot GC in `internal/storage/config.go`, even though periodic Local GC has not been independently qualified under concurrent init/recovery.
   - *Mitigation*: Track Issue #105 and avoid concurrent maintenance writers during recovery until Local-mode periodic GC is qualified.
3. **`standalone-local` DR single point of failure**:
   - *Risk*: Because `goauthy-backup` is rejected and byte-only object copies that strip SDK object version metadata fail recovery, the live `local/v1` object-store prefix is a single point of failure.
   - *Mitigation*: Use version-preserving object-store replication/snapshots or retain `standalone` (`Local: false`) if `goauthy-backup` (`age` + Ed25519) is required ([docs/backup-operator.md](backup-operator.md)).
4. **Silent greenfield initialization on prefix typo**:
   - *Risk*: On Pod replacement (`emptyDir` absent), a typo in `GOAUTHY_RHIZA_OBJECT_STORE_PREFIX` / `BUCKET` or an empty prefix silently initializes a blank IdP.
   - *Mitigation*: Validate prefix/bucket configuration via external inventory and `goauthy config check` before rollout.
5. **Init 2-minute timeout & `db.Close()` retry hazard**:
   - *Risk*: `/goauthy-rhiza-init` hardcodes a `2m` timeout (`cmd/goauthy-rhiza-init/main.go`); large checkpoints exceeding `2m` trigger `Init:CrashLoopBackOff`. Additionally, `main` still carries a `v0.10.0` `db.Close()`-skip guard whose `v0.24.0` behavior on interrupted startup is unverified.
   - *Mitigation*: Keep `DataDir` within bounded checkpoint sizes and verify partial-`DataDir` retry idempotency on `v0.24.0`.
6. **`1Gi` `emptyDir` eviction & `before-ack` tail latency**:
   - *Risk*: `deploy/standalone-local` bounds `emptyDir` to `1Gi` (covering SQLite DB, WAL, downloaded checkpoint, and journal install copies); exceeding `1Gi` triggers kubelet eviction into a fresh `emptyDir`. Synchronous `before-ack` writes also tie auth write latency/availability directly to object-store health.
   - *Mitigation*: Monitor `emptyDir` usage and object-store latency; ensure `SQLITE_TMPDIR` and checkpoint sizes stay well below `1Gi`.

---

## Historical Baselines & Evidence References

- **Kubernetes deployment & fixtures**: Current Kustomize overlays live in [`deploy/standalone`](../deploy/standalone/README.md) (`Local: false`) and [`deploy/standalone-local`](../deploy/standalone-local/README.md) (`Local: true`), both using **VersityGW** as the local Kubernetes S3 fixture (historical 2026-09 `v0.12.3` E2E runs used MinIO).
- **Backup & scheduling contracts**: Offline `age`/Ed25519 backup/restore is specified in [docs/backup-operator.md](backup-operator.md) and scheduled KV-lease backups in [docs/backup-scheduling.md](backup-scheduling.md).
- **Historical qualification ledger**: Earlier Rhiza `v0.21.2` (`8acb6da35a4c6fc83fa14ecec2fe2b64370fa4bd`), `v0.21.1`, `v0.19.0`, and `v0.12.3` (schema 86/87 Kind/MinIO crash, corruption, and `tc` partition) runs are recorded in [docs/status.md](status.md) and do not qualify `v0.24.0`.
