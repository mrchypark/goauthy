# Encrypted dated backups: implementation evidence

Status: encrypted Export/Restore and signed remote catalog operators implemented;
manual completed-artifact retention is implemented; scheduling, key rotation
and orphan cleanup remain incomplete.
The baseline remains Rhiza v0.12.3, no GoAuthy PVC and object-store before-ack DR.
Dated encrypted backups must restore from an independent backup destination;
Rhiza's live checkpoint GC is not a dated-backup retention policy.

## Requirements and package mapping

| Requirement | Reuse candidate | Completion evidence required |
|---|---|---|
| Consistent checkpoint plus certified archive suffix | Rhiza `recovery.Manager.BeginRecoverySnapshot`, `checkpoint.Manager.OpenRoot` and `PinRecoveryRoot` | Fresh-prefix restore while source advances and GC runs |
| No private Rhiza codec implementation | Rhiza `DecisionsFrom`, `DownloadAndVerifyRootFiles`, `PromoteCertifiedCurrent` | Exact captured objects restore with original OAuth/JWKS/generated key |
| Streaming encrypted artifact | Public Go library `filippo.io/age`; stdlib `archive/tar`, `io` | Tamper/truncation/wrong-key rejection and bounded-memory round trip |
| Dated catalog and completed publication | Existing object-store conditional writes, stdlib JSON/time/hash | Interrupted upload never appears as completed backup |
| Scheduled execution and single active publisher | Native Kubernetes CronJob or existing application coordination, to be selected | Overlap/leader loss/retry E2E; no duplicate or partial completion |
| Keep-days retention | Delete only completed backup artifacts in an independent prefix | Boundary-time tests; retain newest valid backup; never delete live Rhiza objects |
| Restore | Independent target prefix plus separately provisioned identity/master keys | Real MinIO/Kind fresh emptyDir restore and original credential continuity |

The [Rauthy v0.36.2 backup guide](https://github.com/sebadob/rauthy/blob/v0.36.2/book/src/config/backup.md)
requires scheduled backups, retention and named restore. Feature-goal parity
does not imply binary compatibility with Hiqlite's artifact format.

## Snapshot export investigation

The `rhiza.DB` facade has no backup/export handle. That does **not** establish
that online export is impossible: its public checkpoint/recovery managers can
be constructed with the same bucket, cluster prefix and configuration ID.
The current node uses `path.Join(ObjStorePrefix, ClusterID)` and config ID 1.
See [node setup and recovery](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/node/node.go)
and [archive snapshots](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/recovery/archive.go).

A candidate integration must perform the following under renewable leases:

1. Begin an archive recovery snapshot; preserve its exact loaded head bytes.
2. Read its certified base seal, open that exact checkpoint root, verify the
   state hash, and register its checkpoint pin.
3. Traverse all snapshot decisions through its fixed tip and verify every
   checkpoint file using Rhiza's own readers. Capture complete successful
   object reads, retaining conditional-write version semantics.
4. Export only the captured head, archive blocks, selected root and checkpoint
   blocks. Exclude live GC locks, recovery pins and unrelated mutable metadata.
5. Restore into an empty destination; use `PromoteCertifiedCurrent` to create
   CURRENT through Rhiza rather than writing its private encoding.

This is a prototype hypothesis until a real clean-prefix restore proves it.
There is no public export-manifest contract promising the exact object set.
A capture adapter depends on pinned-version reader behavior and must fail on
partial reads, lease loss, missing objects or failed validation. GC races and
concurrent head advancement require explicit tests. Unconditional recursive
copy of a running prefix cannot stand in for this evidence.

## Encryption decision boundary

The [age project](https://github.com/FiloSottile/age) supplies a Go library and
specified streaming encryption format with existing implementations. It is a
used by `internal/backup` to avoid custom AEAD framing; v1.3.2 is pinned in go.mod.
Stdlib AES-GCM alone is a primitive, not an authenticated streaming archive
format. Do not claim custom framing is unavoidable before evaluating age.
Key provisioning, rotation and backup metadata authentication still need an
explicit contract. Do not publish plaintext staging or expose key material in
logs. Complete authentication before activating restored state.

## Independent consultation

The optional Pro consultation was not sent: the in-app project creation UI
reported memory disabled and did not offer Project-only memory. The skill's
required project context could not be established. No project was created,
account memory setting changed or task packet transmitted. Local source
research continues; this is not a blocker for the overall implementation goal.

## age package probe (2026-09-09)

`sh scripts/test-backup-age.sh` passed in an isolated temporary Go module using
`filippo.io/age v1.3.2` (0.470s). The native X25519 recipient probe encrypts more
than two payload chunks, verifies exact plaintext recovery and rejects a wrong
identity, missing final byte, modified final chunk, trailing byte and a writer
that was never closed. Shell syntax and ShellCheck also passed. It does not
modify the application's go.mod/go.sum or provision persistent encryption keys.

The [pinned Go API](https://github.com/FiloSottile/age/blob/v1.3.2/age.go)
requires closing the encryption writer and returns a streaming decryption
reader. Header success is not whole-artifact authentication: consume and check
its final result before publishing restored state. This probe uses bounded test
data in memory; it is not a large-backup memory benchmark or atomic restore
implementation. Native key choice and application master-key integration remain
to be decided. Public-recipient encryption is not sender authentication; backup
origin/catalog authorization must be established separately. No custom streaming
AEAD format is justified by the current research.

## Artifact implementation (2026-09-09)

`internal/backup` uses age encryption and stdlib USTAR streams, `io.CopyN`,
`os.MkdirTemp` and `os.OpenRoot`. It validates object names, declared sizes,
duplicate entries and explicit file/count/total limits. Extraction stages regular
files beneath a new private directory, rejects special entries and consumes the
age stream beyond tar EOF before returning an inventory. Failure discards only
the owned staging directory. A failed writer does not finalize a partial artifact.

Application-specific code is limited to these object-bundle constraints and the
staging lifecycle: age supplies encryption/authentication, while tar and rooted
filesystem operations supply encoding and confinement. Neither library selects
Rhiza's certified object set or decides when GoAuthy may publish restored state;
those application responsibilities cannot be delegated to an encryption primitive.
No custom cipher or Rhiza codec is introduced.

The snapshot qualification now writes an encrypted artifact with an ephemeral
native Hybrid key, authenticates/extracts it and streams staged files into the
fresh destination before Rhiza recovery. Capture still holds its source objects
in memory. A versioned self-contained manifest now carries the selected checkpoint
reference and object inventory, as described below. Production capture integration,
trusted catalog, key provisioning, commands, scheduling, retention and Kubernetes
E2E remain required.

### Self-contained snapshot metadata

The implemented format retains age/USTAR and reserves `manifest.json` inside
the encrypted stream. Object entries use `objects/<source-relative object key>`.
Manifest version 1 records pinned Rhiza version, source prefix/cluster/config ID,
selected checkpoint index/root hash/state hash, and each object's size and SHA-256.
The manifest is at most 1 MiB. It is application metadata; checkpoint and archive
object bytes retain Rhiza's own encoding unchanged.

Restore must authenticate the bundle, validate strict manifest syntax and version,
require an exact inventory, and hash each staged regular file before any upload.
It must reject a source/destination prefix collision or incompatible target
identity. Public Rhiza managers then validate/open the manifest-selected root and
publish CURRENT into the empty target prefix. This removes an out-of-band source
checkpoint parameter; independent master keys and cluster identity provisioning
are still required. SHA-256 inventory checks do not authenticate the sender:
trusted backup catalog/publication authorization remains a separate requirement.

### Restore publication contract

`backup.Restore` receives an already authenticated staging result and a configured
object-store bucket. It validates the manifest before writing, requires a fresh
prefix disjoint from the source, and uses native conditional writes for a retained
restore marker and uploaded objects. A failed attempt leaves its fresh prefix for
inspection; callers must choose a new prefix rather than overwrite or delete it.
The marker arbitrates GoAuthy restore attempts only. The target must remain offline
and exclusively owned: the marker does not fence arbitrary Rhiza writers.

Before publishing CURRENT, the function uses Rhiza's public checkpoint manager to
verify the root and download/hash all referenced files, and the public archive
manager to verify its certified base and complete decision suffix. Scratch files
are private and disposable. This adds no database codec. Operator commands and
automatic startup fencing for incomplete restore targets remain separate work;
the function is not an authorization to start an application against failed or
unverified target state.

The integrated gate now calls the product Restore function. Four corruption
fixtures recompute a valid outer manifest and encrypt successfully, while altering
only a checkpoint root, checkpoint data block, archive head or archive block.
Their manifest validation succeeds; Rhiza then rejects each target and CURRENT
remains absent. A valid restore is followed by a second attempt against the occupied
prefix; rejection leaves CURRENT byte-for-byte unchanged. Real filesystem tests
also exercise no-write identity/occupied-prefix rejection, upload failure and
two requests synchronized at native marker CAS with exactly one successful owner.

The first product S3 run exposed a transport bug: a `LimitedReader` with declared
size plus one advertised the wrong Content-Length through objstore's size helper.
The failed 31.37s run is not acceptance evidence. An intermediate SectionReader
candidate passed real MinIO in 13.314s, including all four corruption and
occupied-prefix controls, but objstore's native size helper does not recognize
that reader type. The final implementation rechecks the private regular file's
size and passes the stdlib `*os.File` directly: native size discovery and retry
seeking both work without a custom adapter. Staging remains exclusively owned
throughout the upload.

The final native-file candidate passed
`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3` with race detection in
132.060s. It covers actual source publisher expiry/paired-pin GC, encrypted
manifest-driven product Restore, all four authenticated corruption fixtures,
occupied-prefix preservation and original credential continuity. The package race
suite and vet also passed, including a regression that applies objstore's real
size discovery to each upload, reads the bytes and rewinds/re-reads them before
delegating to the filesystem bucket. At least one non-marker object must be
checked, so the later malformed-root failure cannot mask a transport regression.
All disposable MinIO containers/networks were removed after terminal runs.

### Product snapshot exporter

`backup.Export` now orchestrates the public archive/checkpoint managers, a
disk-backed capturing bucket, the v1 manifest and age bundle writer. It acquires
both pins under a random owner, renews them immediately, every 30 seconds and
before returning, and treats renewal/cleanup failures as export failure. The
caller must discard output on **any** error, even if the encrypted stream was
already finalized; only successful return authorizes later publication.

Captured bytes go to private temporary files with incremental SHA-256, not a map
of byte slices. File/count/aggregate capture limits include active and duplicate
temporary reads. EOF plus successful Close is required; a non-EOF error remains
fatal even if a caller later retries to EOF. Duplicate identical reads reuse the
first file; conflicts fail. The encoder opens one staged object at a time rather
than retaining a file descriptor for every object. Capture and verification files
are removed on completion or failure, with cleanup errors reported.

These limits bound this adapter's staging, not all memory allocated by Rhiza's
public decoding routines. Verification temporarily also materializes checkpoint
files; it is not a single-copy disk budget. A writer that blocks inside Write
must still obey its own I/O timeout; context checks cannot forcibly interrupt an
arbitrary io.Writer. Snapshot acquisition can fail if the source head changes
during its initial chain load; callers may retry a failed unpublished export.
The v1 checkpoint branch requires a certified base. The v2 archive-only branch
below supports initial state before the first checkpoint.

### Initial archive-only capture investigation

Rhiza v0.12.3 `BeginRecoverySnapshot` explicitly requires a checkpoint recovery
base; the DB facade exposes no on-demand checkpoint operation. This is a limit
of its pin API, **not** proof that every finite archive-only capture is impossible.
Public `Manager.Load` stabilizes the head and validates its exact extent chain;
without another Load, its tip and references stay fixed. `DecisionsFrom(1)` can
then validate every decision through that selected tip. Complete reads of the
head and immutable blocks can therefore form a finite archive-only capture.
Deletion during collection may make that attempt fail and require a retry; no
retention pin protects availability. It must never fall back to recursive copy
or silently accept missing decisions.

The initial-state prototype in `verifyNoPVCInitialArchiveCapture` runs before
closing the source DB or creating any CURRENT. After fixed Load it acknowledges
a source write and verifies the original manager tip remains fixed while an
independent manager advances. It deletes one required source block, requires a
public decision read to fail, restores the exact original bytes, then completes
the capture and restores into a separate empty prefix with no CURRENT. Original
account authentication, signing key and generated API-key permissions survive;
the post-snapshot marker is absent. The local race gate passed in 11.928s.

This was initially a raw-object prototype using an in-memory test capture.
The product integration described below supersedes that export/restore limitation.
Initial-state encrypted interruption and Kubernetes qualification remain open. The tested failure is an explicit object deletion, not proof
that a particular background GC policy deleted it.

The same initial-state prototype also passed against disposable MinIO as part of
`make test-no-pvc-export-s3` with race detection (17.025s). This final run includes
the actual missing-block rejection and original-byte repair before clean-prefix
recovery. The remaining checkpoint-backed encrypted product roundtrip and its
corruption controls passed in the same run. Fixture container/network cleanup
and `git diff --check` passed.

The main integration now restores the product Export artifact, checks original
account/signing/generated-key continuity, and excludes a source write injected
while checkpoint data is being read. The older capture prototype is retained for
its independent GC/deletion and corruption-fixture evidence. Product periodic
renewal and prototype GC are distinct interleavings; the latter does not by itself
prove that product Export was reading concurrently with GC.

Capture/bundle/manifest/restore package race checks passed in 1.977s with vet.
The product export integration passed locally with race detection in 9.012s,
including rejection of an injected checkpoint-pin renewal failure and scratch
cleanup. The initial MinIO product exporter roundtrip passed in 12.380s before
that additional fault assertion. Final long-run results are recorded separately.

The final long-run MinIO gate passed with race detection in 162.488s
(`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3`). Product Export was blocked
at a checkpoint-data read until the third successful update of **both** pins;
acquisition and immediate renewal account for the first two updates, so this
observes its actual periodic renewal before allowing capture to continue. It also
checks pin-renewal failure rejection and scratch cleanup. The separate prototype
then performs the established publisher-expiry/GC deletion scenario, and product
Restore verifies the product artifact with all credential/corruption controls.
This proves those specific interleavings, not continuous concurrent exporter/GC
stress or Kubernetes exporter qualification.
The returned private staging directory must remain exclusively owned by the
restore process until upload finishes; validating a file does not authorize
another process to replace it afterward. Rooted filesystem reads confine paths,
but do not make staging immutable.

`internal/backup/manifest.go` uses stdlib JSON, SHA-256 and rooted file operations.
The existing repository's JSON-token validation approach is reused to reject
duplicate keys; an exact fixed-field check rejects casing aliases that normal
`encoding/json` struct decoding accepts. This policy glue is needed because
`DisallowUnknownFields` alone does not reject duplicate or case-folded members.
No generic JSON codec or additional package is introduced. Limits on extraction
remain caller-supplied; manifest sizes must be positive and leave room for a
one-byte overrun check without integer overflow.

Final manifest/bundle tests passed with race detection (1.640s) and `go vet`.
Negative metadata tests mutate otherwise valid controls and update the inventory
size, so parsing failures cannot be explained by unrelated missing fields or a
stale length. Tests include nested duplicates/casing, invalid UTF-8, null/zero/
overflow sizes, same-length altered object bytes, missing physical files and
symlinks. The first real MinIO manifest-driven roundtrip passed in 11.741s;
the final manifest-driven GC run passed with race detection in 132.482s
(`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3`). It restored the manifest's
selected checkpoint/archive into a separate empty S3 prefix after actual GC,
preserving account/signing/generated-key continuity and excluding post-snapshot
writes. No original checkpoint object was passed to the restore helper.

Artifact checks passed with race detection (1.598s) and `go vet`. They compare
multi-chunk plaintext bytes, cover X25519/Hybrid keys, wrong keys, same-length
final-byte tampering, truncation, encrypted/plaintext trailers, unsafe/duplicate
entries, limits, file permissions, preservation of parent contents and cleanup.
Input failure after a complete earlier object and output failure after a complete
age payload chunk both leave an unauthenticated artifact. The integrated MinIO
snapshot gate passed with race detection in 11.699s. Its first launch stopped at
a MinIO readiness connection reset before running Go tests; the final runner
retries readiness transport errors with a fixed retry bound, then passed.
The encrypted path also passed the real S3 paired-pin GC gate with race detection
in 131.448s (`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3`). This supersedes
the earlier unencrypted-artifact integration for that deterministic GC scenario.

## Public-manager capture prototype (2026-09-09)

`TestNoPVCPublicRhizaSnapshotCapture` in
`internal/storage/no_pvc_export_test.go` passed (2.709s; race 8.296s).
It captures complete successful allowed object reads through a filesystem bucket
wrapper, pairs archive/checkpoint pins, validates decisions and checkpoint files,
and restores only captured objects into a separate empty object directory.
Public `PromoteCertifiedCurrent` generates CURRENT. A fresh Rhiza DB authenticates
the original account and retains the signing key ID and generated API key with
its existing permissions. No private Rhiza binary codec was implemented.

The source DB is closed first to produce a certified checkpoint. Therefore this
proves static public-manager export/import feasibility, not online backup, crash
capture, MinIO behavior or GC concurrency. Objects are held in memory; there is
no streaming staging bound, lease renewal loop, encrypted artifact, scheduler,
retention or production CLI. The next required evidence is writer/head advancement
and GC while both leases are renewed, followed by clean-prefix recovery of the
selected snapshot. This prototype does not complete the backup feature.

Capture-adapter negative control (2026-09-09):
`TestNoPVCExportCaptureRejectsIncompleteObjects` passed (0.831s). Starting from a
complete object set, it rejects partial reads, a failing reader Close and a
second successful read with conflicting bytes. The complete identical read
passes. These are parser/adapter controls; they do not prove a consistent online
snapshot or lease-renewal behavior.

## Live writer snapshot boundary (2026-09-09)

The extended `TestNoPVCPublicRhizaSnapshotCapture` and capture-negative controls
passed together (3.063s; race 9.089s). After creating the initial checkpoint,
the real source DB is reopened and acknowledges a pre-snapshot row. While both
snapshot pins are held, it acknowledges a post-snapshot row. A separate public
archive manager proves the live archive tip advanced; the captured snapshot tip
remains fixed. Both pin Renew calls succeed, and their Close errors are checked.

A clean-prefix restore contains the pre-snapshot row and excludes the acknowledged
post-snapshot row, while preserving original account authentication, signing key
ID and generated API-key permissions. This proves a deterministic live-writer
interleaving at the selected snapshot boundary. It supersedes the static-only
limitation for that case, but does not test simultaneous GC, overlapping exports,
lease expiry/loss, long-running renewal, MinIO or encrypted artifact publication.
The prototype still stages objects in memory and is not the production backup
implementation.

Lease-handle control (2026-09-09):
`TestNoPVCExportLeaseFencesStaleHandles` passed (1.032s). Public filesystem-backed
archive/checkpoint leases renew successfully, reject renewal after Close, and
fence stale Close handles after the same owner acquires replacement leases.
Replacement renewal remains successful. Close expires the leases directly, so
the check needs no wall-clock sleeps. It proves manager fencing, not a production
exporter's abort/publication behavior on lease loss.

GC integration findings (2026-09-09): publishing a newer checkpoint while an
archive snapshot is active can advance CURRENT but return `ErrArchiveBusy`
from archive trimming. Immediate checkpoint GC can then return
`checkpoint.ErrPublisherBusy` because the publisher claim is still active.
These are lease fences, not evidence that capture/import is impossible. The
GC qualification must wait for the publisher's real expiry, renew both snapshot
pins throughout that wait, prove an unpinned retired root is actually deleted,
and only then demonstrate recovery of the pinned older snapshot. No claim is
forcibly removed.

The slow qualification is exposed as `make test-no-pvc-export-gc` (race enabled,
six-minute process timeout). It requires CURRENT to have advanced beyond the
selected root before collecting with keep=1, renews both export pins while the
publisher claim blocks GC, and requires removal of an unpinned retired root.
The normal focused test does not enable this wall-clock gate. Passing the normal
test cannot substitute for the opt-in GC result.

GC qualification PASS (2026-09-09): `make test-no-pvc-export-gc` completed with
race detection in 128.710s. CURRENT was newer than the selected checkpoint;
public GC first reported the publisher busy, then succeeded after real lease
expiry while both pins were renewed. The unpinned retired root was deleted and
the selected older root remained readable. Public archive Cleanup also succeeded.
Clean-prefix restore recovered the selected checkpoint and its pre-snapshot
archive suffix, original account, signing key and generated API-key permissions,
while excluding the post-snapshot write. The final default focused suite passed
in 3.301s.

This is a deterministic filesystem-objectstore interleaving, not continuous
writer/GC stress or MinIO/Kind export qualification. Archive Cleanup success does
not establish archive-block deletion or pin-specific archive retention: archive
trimming was fenced. In-memory staging, overlapping exports, production abort on
lease loss, encrypted publication, scheduling and dated retention remain open.

Real S3 transport PASS (2026-09-09): `make test-no-pvc-export-s3` ran the same
snapshot capture and clean-prefix restore against disposable MinIO with race
detection (11.646s). Both the live Rhiza DB and public managers use S3; the
destination is a separate, initially empty prefix in the fixture bucket.
The source is not deleted. Account/signing/generated-key continuity and the
pre/post snapshot markers passed. The runner reuses the existing pinned MinIO
fixture, adds a host-capacity preflight and removes its container/network on exit.
This is a local container S3 integration gate, not a Kubernetes export gate.
Use `GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3` for the additional
publisher-expiry/paired-pin GC qualification; ordinary export success does not
prove that optional gate. Production encrypted publication remains unimplemented.

Real S3 GC qualification also PASS (2026-09-09):
`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3` completed with race detection
in 132.171s. The same explicit newer-CURRENT, publisher-busy/real-expiry,
paired-pin renewal, retired-root deletion, selected-root survival and clean-prefix
restore assertions passed against MinIO. Archive Cleanup retains the limitation
above: this does not prove deletion of archive blocks. Both fixture runs exited
successfully; shell syntax, ShellCheck and diff checks passed. The filesystem-only
lease-handle test explicitly clears the S3 selector and passed again (0.937s).

### Product archive-only encrypted recovery (2026-09-09)

Export now probes the public recovery manager, then captures a single stable
initial head and all decisions from genesis through its fixed tip. A checkpoint
appearing between probe and capture rejects the unpublished attempt for retry.
Format v2 explicitly records `recovery_mode: archive-only` and `archive_tip`;
it excludes checkpoint objects. Format v1 encoding and strict reading remain
compatible. Neither branch implements a private Rhiza codec.

Restore validates the authenticated staged inventory, claims a fresh prefix with
conditional writes, and uses the public recovery manager to verify no checkpoint
base, the exact manifest tip, and every contiguous decision starting at slot 1.
It returns without creating CURRENT. Targets remain offline and exclusive until
success; failed prefixes must be abandoned. Archive-only capture has no retention
lease: missing required objects fail collection rather than permit partial DR.

The initial-state test now exports a Hybrid age artifact and restores it through
the product APIs before opening Rhiza on a fresh local DataDir. It verifies the
original account, signing key, generated API key and pre-export marker, excluding
the subsequent source write. The independent raw-manager source-advance and
actual object-deletion controls remain alongside this product roundtrip.
Local race integration passed (13.573s), full backup race tests (1.747s), vet,
and real MinIO product roundtrip (17.597s). Operator commands, authorized catalog,
key provisioning, scheduling and retention parity are still incomplete.

The final wrong-tip control changes only the manifest tip, updates inventory
length, and first proves ReadManifest accepts the fixture. Restore then rejects
the actual archive mismatch without CURRENT. The final local integration passed
in 12.236s and real-MinIO race gate in 18.943s. Backup race tests including v1
unknown/null-field rejection passed in 1.995s; vet passed.

The unchanged product implementation also passed the long real-MinIO
`GOAUTHY_EXPORT_GC_TEST=1 make test-no-pvc-export-s3` gate in 168.186s:
paired periodic pin renewal, injected renewal failure, independent raw-capture
GC controls, encrypted checkpoint and initial archive-only roundtrips. This run
started before the additional wrong-tip test; that test passed separately in the
18.943s final gate. These are S3 tests, not new Kubernetes artifact evidence.

### Offline operator command (2026-09-09)

`cmd/goauthy-backup` provides export and restore using the application's validated
object-store environment without opening a DB. Export uses private staging and
exclusive hard-link publication after success; it never replaces an artifact.
Restore requires an independently trusted SHA-256, copies ciphertext into owned
staging while hashing, and authenticates age before claiming the remote target.
The digest is a manual trust input, not an automated or signed catalog. See the
[operator contract](backup-operator.md) for commands, defaults and limitations.

The final real-MinIO race command-function gate passed in 4.261s. It explicitly
inspects manifests to prove both v2 initial and v1 checkpoint branches, reopens
the source after its shutdown checkpoint, writes a suffix and verifies both SQL
rows after checkpoint restore. It rejects an existing output, wrong digest,
wrong identity, a corrupted final age authenticator even with matching outer
digest, and occupied target; failure controls assert immediate scratch cleanup.
The target marker is absent after pre-upload authentication failures. This is
S3 evidence; GCS operator transport remains untested.

The actual operator executable passed the default exact-three Kind gate:
`E2E_PORT=59361 sh scripts/e2e-kind-backup-restore.sh` (exit 0; log
`/tmp/goauthy-encrypted-operator-kind-20260909.log`). A live three-voter source
exports an encrypted checkpoint-backed artifact, then its whole Kind cluster is
deleted. The operator restores into an unrelated prefix of new Kind MinIO before
GoAuthy deployment. CURRENT and restore marker are observed, then fresh emptyDir
voters preserve original OAuth token, JWKS and generated API key behavior, and
a newly issued token is verified by all three voters. Both GoAuthy deployments are
asserted PVC-free; MinIO has an independent fixture PVC. Cleanup left no Kind
clusters. This does not qualify v2 archive-only artifacts in Kind, physical
failure-domain independence, or encrypted-export interruption behavior.

### Signed completion publication (2026-09-09)

`Publish` writes an immutable artifact to an independent prefix, verifies the
remote size and digest, then writes an immutable Ed25519-signed completion record.
`ListCompleted` verifies records and their namespace binding; `FetchCompleted`
authenticates a named record before downloading and verifies exact ciphertext
bytes into owned private staging. CLI `publish/list/fetch` use native PKCS8/PKIX
PEM keys, with private permissions enforced and public trust pinned externally.
One signer is supported; rotation, scheduling and retention remain open.

The real-MinIO operator pipeline passed in 5.275s with race detection for both
v1 and v2 artifacts: Export, signed Publish/List/Fetch, then Restore. Filesystem
catalog tests additionally exercise wrong trust, copied records, signed payload
mutation, remote corruption/missing objects, oversized records, list/download
limits, immutable completion collisions and failure cleanup. An artifact upload
that succeeds remotely but returns an error remains an unlisted orphan; corrupt
readback and failed completion publication also remain unlisted. These are
injected I/O-failure tests, not process-SIGKILL upload qualification.

A completion record describes authorized publication, not guaranteed current
availability or freshness. The creation date is supplied by the publisher.
Named Fetch rejects subsequently missing or changed bytes. Publish accepts an
opaque age artifact from its authorized caller; only a successful Export establishes
Rhiza snapshot validation, and Restore still verifies the actual Rhiza content.
The catalog cannot infer that arbitrary age ciphertext is a recoverable database.

Final namespace validation also rejects invalid UTF-8 before tar/JSON encoding.
A regression first demonstrated that malformed source bytes were accepted and
would be replaced by JSON encoding; the shared `validName` guard now protects
manifest, object, export/restore and catalog names. Final backup/CLI race suites
passed (2.828s / 1.803s), vet passed, and the final real-MinIO operator pipeline
passed in 4.273s. Fetch corruption keeps the exact ciphertext length so the
negative control exercises digest verification, not just a size mismatch.

The final candidate passed the exact-three Kind executable gate (exit 0;
`/tmp/goauthy-signed-catalog-kind-final-retry-20260909.log`). The script publishes
and lists a live checkpoint snapshot in a disposable MinIO outside Kind, removes
the owned local ciphertext, deletes the original Kind cluster, then fetches from
the externally pinned signed catalog and restores into new Kind/MinIO. Original
OAuth/JWKS/generated-key behavior and newly issued token verification on all three
voters survive with no GoAuthy PVC. MinIO fixtures have independent lifecycle from
the app, but share the Docker host; physical failure isolation is not established.
A prior final build failed at the Go module proxy with unexpected EOF; the same
unchanged build/test retry passed. The earlier pre-UTF8-guard Kind run also passed,
but the final retry is the authoritative candidate evidence.

### Completed-artifact retention (2026-09-09)

`Prune` and CLI `prune` provide a dry-run plan or explicit apply, defaulting to
30 UTC days. All receipts are authenticated first. The newest entry per signed
source prefix is retained and its entire remote artifact verified before any
delete. Only older nonkeepers strictly before the cutoff are removed. Invalid
receipts, future dates or unavailable/corrupt keepers fail the run without writes.
Deletion is artifact-first, then completion record; not-found allows interrupted
expired-pair cleanup to resume. There is no atomic rollback, restore lease,
unsigned orphan sweep or deletion of live Rhiza namespaces.

The real-MinIO operator test passed in 4.304s: an authorized 40-day-old fixture
is selected by dry-run without mutation, apply removes both its artifact and
receipt, and the fresh signed artifact remains fetchable/restorable for both
archive-only and checkpoint modes. Unit tests include per-source newest retention
with all entries expired, exact-cutoff nonkeeper preservation, corrupt keeper and
invalid metadata rejection, partial deletion retry, source sentinel preservation,
and two concurrent pruners synchronized after the same verified listing.

Final retention Kind gate also passed (exit 0): dry-run/apply against an expired
signed fixture, then source Kind and local ciphertext removal, external-catalog
fetch and fresh-cluster credential recovery. Log:
`/tmp/goauthy-retention-kind-diagnostic-20260909.log`. This proves no GoAuthy PVC,
not physical-host independence or automatic scheduling.
