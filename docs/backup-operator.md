# Encrypted backup operator

`go build -o goauthy-backup ./cmd/goauthy-backup` builds the offline operator.
The main container image also includes `/goauthy-backup`.
It uses Rhiza v0.12.3 public recovery/checkpoint APIs and never opens a DB.
The source may remain live during export. The restore target must remain offline
and exclusively owned until the command exits successfully.

Use the application's validated `GOAUTHY_RHIZA_*` environment, including cluster
identity and object-store settings. For an operator process, use the standalone
profile, a distinct node ID and a dedicated unused DataDir. Peer configuration
must be absent for that profile. DataDir is not opened; `-work-dir` is the private
scratch parent. S3 and GCS constructors mirror the pinned Rhiza implementation;
S3 has real-MinIO qualification, while this operator's GCS transport is untested.
Supply object-store credentials through the environment or native workload
identity, never command arguments. Restore master keys separately for GoAuthy.

Create age recipient/identity files using age's native key tooling. Export accepts
native recipient lines (including Hybrid recipients); restore accepts native
unencrypted identity lines. Identity files must be regular files with no group
or other permission bits, e.g. mode 0600. Keys are never printed by this command.

```sh
umask 077
mkdir -p ./backup-work
./goauthy-backup export -file ./snapshot.age \
  -key-file ./recipients.txt -work-dir ./backup-work > ./snapshot.sha256
```

Only an exit status of zero declares success. Export stages a private encrypted
file beside the requested path, syncs it, and publishes with an exclusive hard
link: existing files are never replaced. The output directory must be trusted,
exclusively controlled and support hard links. On failure, do not treat any
output/digest as a completed backup. The signed remote catalog commands below publish the encrypted artifact to
independent object storage. Opt-in automatic scheduling is implemented; see
[backup scheduling](backup-scheduling.md) for configuration and live qualification.

Export prints only the artifact's lowercase SHA-256. Retain that digest through
an independently trusted channel: a digest obtained from the same untrusted
artifact location does not authenticate its sender. Anyone holding a public age
recipient can produce a new encrypted artifact; age encryption alone is not
sender authorization. The signed catalog below provides an alternative to manually retained digests.

Set the target object-store prefix to a fresh, unrelated prefix in the target
bucket, keeping the original cluster ID. Restore rejects the same source prefix,
ancestors, descendants and occupied targets, even in another bucket.

```sh
export GOAUTHY_RHIZA_OBJECT_STORE_PREFIX=restored-backups
./goauthy-backup restore -file ./snapshot.age \
  -key-file ./identity.txt -work-dir ./backup-work \
  -sha256 "$TRUSTED_BACKUP_SHA256"
```

Restore copies the ciphertext into owned staging while hashing, verifies the
trusted digest, then authenticates/decrypts and validates the complete manifest
before writing any target objects. It conditionally claims the fresh target and
validates the uploaded Rhiza data before success. Checkpoint-backed v1 restores
publish CURRENT last; initial archive-only v2 restores do not create CURRENT.
A failed target prefix must be abandoned. Start GoAuthy with the target prefix,
fresh emptyDir/DataDir and independently restored master keys only after success.

Defaults: 15-minute context timeout, 65,536 bundle entries, 1 GiB per object,
8 GiB total plaintext. Override with `-timeout`, `-max-files`, `-max-file-bytes`,
`-max-total-bytes`. Scratch needs capacity for ciphertext, captured objects and
Rhiza's verification files; these bounds are not a process memory or single-copy
disk ceiling. OS/provider calls have their own cancellation behavior.

`make test-backup-operator-s3` runs real MinIO/race tests for initial archive-only
and checkpoint artifacts (manifest versions asserted), preserved SQL data including
a post-checkpoint suffix, digest/identity/final-age-authentication rejection before
target writes, no-overwrite publication, occupied-target rejection, artifact
permissions and immediate scratch cleanup after negative controls. It is a transport/command-function test, not
by itself Kubernetes or full feature parity evidence.

The actual binary also passed `E2E_PORT=59361 sh scripts/e2e-kind-backup-restore.sh`
on 2026-09-09: live checkpoint export, original-cluster removal, unrelated-prefix
restore in a new Kind cluster, no GoAuthy PVC, original OAuth/JWKS/generated-key
continuity and new token verification across all three voters. The fixture's
MinIO PVC is independent. This Kind result covers v1 checkpoint artifacts;
Separate v2 archive-only and interruption results are recorded in the
[DR contract](no-pvc-dr.md) and [feature ledger](features.md); they are not
evidence supplied by this particular v1 command.

## Signed remote catalog

`publish`, `list` and `fetch` use the same validated object-store environment as
export/restore, but that environment should point at an **independent backup
bucket**. `-catalog-prefix` must be unrelated to the live Rhiza source prefix.
The source prefix in a publication is the environment's base prefix plus cluster
ID. Configure those two values to match the successful export being published.

Provision an Ed25519 signing key separately from age encryption identities:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out catalog-private.pem
openssl pkey -in catalog-private.pem -pubout -out catalog-public.pem
```

The publisher reads a mode-0600 native PKCS8 private PEM. Readers use a native
PKIX public PEM pinned through a trusted channel outside the backup bucket.
Publishing authority belongs to whoever holds that signing key; readers do not
need it. A signing key authorizes a catalog namespace only if its public key is
configured by the operator. Readers accept a PEM bundle of 1–32 distinct pinned
Ed25519 PKIX public keys (at most 16 KiB). Invalid, duplicate or untrusted keys
fail closed; keys embedded in remote records never establish trust.

For overlap rotation, generate a new signer with the commands above, distribute
an old-plus-new public bundle to every reader and server first, then roll servers
onto the new private key. The server reads `GOAUTHY_BACKUP_TRUST_KEY_FILE` at
startup; when omitted it trusts only its current signer. An explicit bundle must
include that signer. CLI `list`, `fetch` and `prune` accept the bundle through
`-key-file`. Existing immutable catalog records are not rewritten.

Keep the old public key while any retained record uses it. Removing it rejects
that record and makes catalog-wide listing/pruning fail closed, rather than
silently hiding it or deleting an unverified artifact. Old private signing keys
are not needed to read old backups; age decryption identities are independent
and remain necessary. Trust/signing changes require process restart; automatic
key generation, rotation cadence and secret distribution are operator-managed.

Only publish an exclusively controlled artifact from a successful Export. The
publisher checks the age header, exact size and local ciphertext digest; it does
not decrypt or establish that arbitrary caller-provided ciphertext contains a
valid Rhiza snapshot. Export and Restore perform the Rhiza validation.

```sh
./goauthy-backup publish -file snapshot.age \
  -catalog-prefix dated -key-file catalog-private.pem > completed.json
./goauthy-backup list -catalog-prefix dated \
  -key-file catalog-public.pem > catalog.json
./goauthy-backup fetch -catalog-prefix dated -id "$BACKUP_ID" \
  -key-file catalog-public.pem -file fetched.age -work-dir ./backup-work \
  > fetched.json
```

Publication creates a random immutable artifact object, streams it back to verify
its size and SHA-256, then conditionally creates the signed completion record.
Records sign their format, ID, publisher-supplied creation date, source prefix,
catalog prefix, size and SHA-256. The artifact path is derived from the signed
catalog prefix and ID; it cannot be redirected by unsigned fields. Failed or
ambiguous writes can leave unlisted orphans; the command never deletes them.
An ambiguous completion-write error can mean a valid record exists: inspect the
verified catalog rather than overwriting or assuming no publication occurred.

List verifies every record and rejects malformed or unauthorized records and
listing-limit overflow. Fetch verifies the exact named record before staging,
then checks every ciphertext byte before exclusive output publication. Use the
SHA-256 from the verified fetch result with the existing Restore command after
switching object-store environment to the fresh restore destination. Fetch scratch
and output must be on the same filesystem for exclusive hard-link publication.

A signed record proves authorized publication, not present object availability or
freshness. A bucket administrator can still delete artifacts/records or replay
old valid records. Named restore does not offer an automatic “latest” guarantee.
List reports recorded completion, while Fetch detects subsequent corruption or
loss. Completed-artifact retention and server scheduling are described below;
unsigned orphan cleanup remains open.

The final signed-catalog Kind gate passed on 2026-09-09. It publishes to a
separate MinIO outside Kind, removes the local ciphertext and original Kind,
then fetches by signed ID and restores to a new Kind/MinIO with fresh GoAuthy
emptyDirs. Original OAuth/JWKS/generated keys and new-token verification survive.
The catalog container and both Kind clusters are disposable and cleaned afterward.
This is not physical-host failure isolation or upload-SIGKILL qualification.

## Completed-backup retention

`prune` uses the externally pinned public key and backup-bucket environment.
It defaults to a read-only plan and 30 UTC days:

```sh
./goauthy-backup prune -catalog-prefix dated \
  -key-file catalog-public.pem -keep-days 30 > retention-plan.json
./goauthy-backup prune -catalog-prefix dated \
  -key-file catalog-public.pem -keep-days 30 -apply > removed.json
```

The plan is recomputed for each invocation; a dry run is not a reservation.
Records strictly older than the UTC cutoff are eligible. An exact-cutoff record
is retained. With the default `-retention-policy keep-latest`, the newest signed entry for every source prefix is retained,
even when every backup is expired. Equal timestamps use the signed ID as a stable
tie-breaker. Independent databases with identical source-prefix identities must
use separate catalog namespaces; retention groups by source prefix, not bucket.

Use `-retention-policy expire-all` for the Rauthy-compatible expiration policy:
all signed entries strictly before the cutoff are selected, including the last
backup of a source. `-keep-days 0` selects entries before the current UTC second;
with `expire-all`, this may remove every completed backup. The server's explicit
`GOAUTHY_BACKUP_RETENTION_POLICY=expire-all` selects the same behavior after Create.
Policy changes do not create a separate scheduler ownership scope. CLI deletion
still requires `-apply`; omitted policy preserves the existing default.

Before any deletion, all completion signatures are checked and every keeper's
remote ciphertext size and SHA-256 are verified. Malformed/untrusted receipts,
future timestamps, or missing/corrupt keepers stop the run without deletions.
Keeper verification streams full remote artifacts and therefore costs read I/O.
Keep-days accepts 0–65535; the signed-list bound is `-max-entries` (default 4096).

Apply deletes each expired artifact before its receipt. If receipt deletion fails,
that receipt can temporarily reference a missing artifact; retrying prune resumes
cleanup because an already-missing expired object is allowed. A nonzero exit can
follow earlier successful deletions. Re-list rather than assuming atomic rollback.
Concurrent cooperative pruners are supported. An in-flight fetch of an expired
artifact may fail safely; no restore lease is provided by this retention path.
Arbitrary external modification/deletion is outside keeper protection.

Only signed completed entries are eligible. There is no recursive prefix deletion,
no live Rhiza-object deletion, and no unsigned/orphan sweeping. Publish or operator I/O failures that
leave unsigned orphan artifacts require a separately scoped cleanup procedure.

## Complete single-run creation

`goauthy-backup create` composes the existing export and signed publication paths.
It publishes only after export and encrypted-file synchronization succeed, then
removes its owned temporary ciphertext. It retains no local backup file or PVC.
The returned JSON is a signed catalog entry; both opened bucket clients must
close successfully before JSON is emitted. A reported error can still leave a
valid remote completion after an ambiguous write or a later cleanup/close error;
inspect the signed catalog rather than assuming no remote objects exist.

```sh
goauthy-backup create \
  -recipient-file /run/secrets/backup-recipients \
  -signing-key-file /run/secrets/backup-signing.pem \
  -catalog-prefix retained-backups \
  -work-dir /private-backup-scratch
```

Source configuration remains `GOAUTHY_RHIZA_OBJECT_STORE_*` and the cluster ID.
By default the destination is the same bucket, in the unrelated catalog prefix.
For an independent destination, set `GOAUTHY_BACKUP_OBJECT_STORE_*` with the same
provider/bucket/endpoint/region/security/credential rules as the source parser.
Once any destination setting is supplied, unspecified settings are **not** copied
from the source. Native ambient workload credentials still follow the selected
provider's existing authentication chain. `GOAUTHY_BACKUP_OBJECT_STORE_PREFIX` is
rejected: the explicit `-catalog-prefix` owns that namespace. Source metadata in
the receipt always identifies the original source prefix, not the destination
configuration used for validation.

The recipient file uses native age syntax; the signing file is native Ed25519
PKCS8 PEM with no group/other permissions. Limits and timeout match export.
Only S3 transport is presently qualified; this command does not add GCS live
qualification. The command is one complete trigger. The server worker below
composes it with scheduling, cooperative ownership and post-success retention.
Manual `prune` retains its existing dry-run/apply contract.

## Server scheduled backups (opt-in)

The server reuses the CLI's native recipient/key readers and destination parser.
No PVC is required: mount a disposable private `emptyDir` directory for work.

| Environment variable | Default / requirement |
| --- | --- |
| `GOAUTHY_BACKUP_ENABLED` | `false`; enable explicitly |
| `GOAUTHY_BACKUP_SCHEDULE` | `0 30 2 * * * *` (seconds through optional year) |
| `GOAUTHY_BACKUP_TIMEZONE` | `Local`; use `UTC` or an explicit IANA zone for consistent replicas |
| `GOAUTHY_BACKUP_CATALOG_PREFIX` | Required, disjoint from the live Rhiza prefix |
| `GOAUTHY_BACKUP_WORK_DIR` | Required, directory with no group/other permissions |
| `GOAUTHY_BACKUP_RECIPIENT_FILE` | Required native age recipients |
| `GOAUTHY_BACKUP_SIGNING_KEY_FILE` | Required private Ed25519 PKCS8 PEM, no group/other permissions |
| `GOAUTHY_BACKUP_TRUST_KEY_FILE` | Optional PKIX PEM public-key bundle; defaults to current signer |
| `GOAUTHY_BACKUP_LEASE` | `1m`; allowed `1s`–`1h` |
| `GOAUTHY_BACKUP_TIMEOUT` | `15m`; allowed `1s`–`24h` |
| `GOAUTHY_BACKUP_KEEP_DAYS` | `30`; allowed 0–65535 |
| `GOAUTHY_BACKUP_RETENTION_POLICY` | `keep-latest` (default) or `expire-all` |
| `GOAUTHY_BACKUP_MAX_ENTRIES` | `4096`; allowed 1–1048576 |

Optional `GOAUTHY_BACKUP_OBJECT_STORE_*` selects an independent destination using
complete destination settings, without inheriting explicit source credentials.
`GOAUTHY_BACKUP_OBJECT_STORE_PREFIX` is rejected; use the catalog variable.
Without these settings, the source bucket is also the catalog bucket. Independent
DR requires a destination whose failure/lifecycle boundary meets your deployment.
Startup checks the catalog with the configured trust bundle (default: current
signer's public key); it does not prove PUT permission. Untrusted existing
receipts fail closed. Keep keys independently recoverable outside disposable
GoAuthy storage and use the overlap procedure above when changing signers.

Each successful Create is followed by Prune. Limits are 65536 files, 1 GiB per
file and 8 GiB total. Work is serial per process and uses a replicated cooperative
lease and completion marker; this is not exactly-once publication fencing. See
[the scheduling contract](backup-scheduling.md) for failure and verification limits.

`create` retries snapshot acquisition at most six times for Rhiza v0.12.3's
exact moving-head, archive-maintenance-busy or checkpoint-publisher-busy error.
Backoff is 100, 200, 400,
800 and 1600 ms, cancellable by the caller context. Every attempt resets the
private ciphertext file; publication is attempted only once after a successful
export. Integrity, transport, joined cleanup and publication errors are not
retried. This addresses a real three-voter scheduled capture collision without
weakening checkpoint verification or introducing an unconditional upload retry.
