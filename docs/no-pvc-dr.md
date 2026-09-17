# No-PVC and object-store DR contract

The project default is no GoAuthy PVC. Rhiza v0.12.3 uses a disposable local
`DataDir` (`emptyDir` in Kubernetes) and shared object storage with fixed
`before-ack` durability. Master keys, issuer, cluster ID, node/member identities
and object-store namespace must be restored independently and remain consistent.
A local-directory backup is not the default DR mechanism.

## Verified Rhiza contract

Pinned source: [Rhiza node](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/node/node.go),
[request acknowledgement](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/network/server.go),
and [embedded tests](https://github.com/mrchypark/rhiza/blob/v0.12.3/rhiza_test.go).

- Before acknowledging, the node calls `EnsureDurable` and archive `SyncThrough`.
  Cached receipts pass the acknowledgement barrier too. Object-store failure
  cannot silently become an acknowledged local-only write.
- Empty local state recovers from a checkpoint and the certified archive suffix.
  SQLite/LatticeDB are materializations, not an independently backed-up authority.
- `TestEmbeddedObjectStoreBeforeAckRecoveryWithoutClose` demonstrates recovery
  into a different `DataDir` without relying on graceful close. This single-voter
  test does not alone prove all-three-voter disaster recovery.
- `Ready` indicates recovery completion, not proof of an available write quorum.
  Identity and membership changes are not an implicit restore procedure.

GoAuthy's `internal/storage/config.go` already fixes object-store durability to
before-ack. Default Kubernetes profiles additionally require object storage so
missing configuration cannot silently select standalone local-only persistence.

## Deployment and evidence

GoAuthy data uses disk-backed `emptyDir`; secret volumes remain independent.
The bundled MinIO is a local E2E object-store fixture with its own storage and
failure boundary. Production uses an external durable object store. A fixture
MinIO PVC is not a GoAuthy persistence dependency or a production DR design.
Existing PVC StatefulSets cannot be changed in-place by applying an immutable
volume-template change: migrate through a separate verified recovery deployment.

- [x] Final no-PVC HA and standalone manifest checks (2026-09-09).
- [x] Live exact-three no-PVC object-prefix restore, original credentials/JWKS
  continuity and successful new writes (TTL0 Kind profile, 2026-09-09, exit 0).
- [x] Live generated-export expiry and rolling restart with disposable pod data
  (300-second Kind profile, 2026-09-09, exit 0).
- [x] Abrupt loss of all three voter processes and all pod-local state against
  the surviving object-store fixture, including acknowledged writes without any
  checkpoint (Kind live PASS, 2026-09-09). Physical-node independence is untested.
- [x] Object-store service outage: strict OAuth failure on every voter, then
  recovery without replacing app pods (Kind live PASS, 2026-09-09).
- [x] Malformed archive head: all three fresh pods reject startup, then recover
  after restoring the preserved original object (Kind PASS, 2026-09-09).
- [x] Missing archive blocks with intact head: all fresh voters reject startup,
  then recover after restoring retained blocks (Kind PASS, 2026-09-09).
- [x] Block content inconsistent with its referenced hash: all voters reject
  startup and recover after original blocks are restored (Kind PASS, 2026-09-09).
- [x] Invalid checkpoint CURRENT reference: all voters reject startup and recover
  after restoring the original pointer (Kind PASS, 2026-09-09).
- [x] Referenced checkpoint root content: all voters reject mismatched bytes and
  recover after restoring only the original root (Kind PASS, 2026-09-09).
- [x] Same-length checkpoint data-block corruption: all voters reject hash mismatch
  and recover after byte-verified original copies (Kind PASS, 2026-09-09).
- [x] Interrupted checkpoint download with retained partial local state: observed
  block bytes, SIGKILL, same-pod recovery (filesystem race and Kind PASS, 2026-09-09).
- [x] Fresh-pod replacement after interrupted download: all partial pods removed,
  original objects unchanged, new emptyDir recovery (Kind PASS, 2026-09-09).
- [x] Real journal installation at all five phases: SIGKILL after journal rename,
  before parent-directory fsync; retained/fresh account/JWKS/generated-key recovery (Linux
  filesystem-object-store container PASS, 2026-09-09).
- [x] MinIO/Kind journal installation interruption at all five phases with
  retained-Pod OAuth/generated-key/JWKS continuity (2026-09-09).
- [x] Native tc peer partition: majority writes, minority availability error,
  unchanged-Pod OAuth/JWKS recovery (Kind PASS, 2026-09-09).
- [x] Generated API-key partition qualification: original export/authentication,
  Clients read/update denial and minority fail-closed behavior (Kind, 2026-09-09).
- [x] Operator encrypted live checkpoint export, original Kind deletion, fresh
  Kind/MinIO prefix restore before app startup, no GoAuthy PVC, existing token/
  JWKS/generated-key continuity and new-token cross-voter verification
  (2026-09-09, exit 0; [operator details](backup-operator.md)).
- [x] Signed external catalog: publish outside Kind, remove local ciphertext and
  original Kind, fetch verified artifact into fresh Kind/MinIO, preserve original
  OAuth/JWKS/generated keys with no GoAuthy PVC (2026-09-09, final exit 0).
- [x] Completed-backup retention: dry-run preserves expired objects; apply deletes
  the expired signed pair while preserving the newest backup; external-catalog
  restore after local artifact and source Kind removal passes (2026-09-09).
- [x] Single `create` trigger to independent destination, retention then source/local
  artifact loss and fresh Kind recovery with credential continuity (2026-09-09, exit 0).
- [x] Actual server scheduled backup on three voters, single signed completion,
  source Kind/local-artifact removal and external-catalog fresh-Kind DR
  (2026-09-09, exit 0; [schedule evidence](backup-scheduling.md)).
- [x] Source-storage outage across a scheduled slot: no signed completion,
  storage recovery, next-slot success and full fresh-Kind DR (2026-09-09, exit 0).
- [x] Two-voter SIGKILL across a scheduled slot: ownership timeout and empty
  catalog, same-Pod recovery, next-slot success and full external-catalog
  fresh-Kind/emptyDir DR (2026-09-09, exit 0).
- [ ] CNI policy enforcement.
- [x] Live scheduled signing-key rotation: all three Pods replaced, old/new
  signatures verified, both backups retained, original Kind/local ciphertext
  removed, and new-key backup restored to fresh Kind/emptyDirs with credential
  continuity (2026-09-09, exit 0; [schedule evidence](backup-scheduling.md)).

Earlier fresh-PVC restore PASS entries remain historical evidence; they do not
satisfy the project's no-PVC deployment requirement. Status is updated only after
the final no-PVC candidate runs. Object-prefix backup transfer tests also do not
claim that an object store can be destroyed without its own durable replica or
backup.

## All-voter abrupt-loss acceptance

`make e2e-kind-no-pvc-crash-recovery` targets a different failure from backup
transfer: keep the object-store fixture running, prevent voter auto-restart, kill
all three application processes with SIGKILL, and remove all three pod identities
so their replacements receive new emptyDir volumes. Container exit status must
prove the kill; an API delete request alone does not prove process termination.
MinIO identity must remain unchanged, and no local GoAuthy data or object-prefix
copy may be used as a restore input.

The profile must establish that the acknowledged test write is absent from a
checkpoint (or newer than an unchanged checkpoint), then recover it through the
certified archive, authenticate existing credentials, preserve JWKS, and accept a
new write. Generated API-key plaintext is retained only in private test files;
application logs are checked without dumping raw logs. A passed test qualifies
all-voter process/local-state loss, not simultaneous loss of the object store,
physical-host independence, network partitions, or corruption recovery.

Live result (2026-09-09): the all-voter profile exited 0 (approximately 98s).
Before and after killing the voters, successful MC JSON listings proved a
certified archive head and no checkpoint CURRENT. All three container exits were
137 before any recovery began. Every replacement pod had a different UID and
emptyDir data with no PVC reference. MinIO retained both pod and container ID.
Original OAuth introspection, identical generated API-key export/authentication,
JWKS continuity, app-log redaction and new OAuth issuance/introspection on every
voter passed. Temporary Kind clusters were removed. No object-prefix or local
data copy was used.

The mechanism reuses Kubernetes, systemd and containerd commands inside the
disposable owned Kind node. No custom database recovery implementation or new
package was added. The fixture shares a physical Kind node with the voters; the
fault targets voter processes, not the physical machine or object-store service.

## Object-store outage acceptance

`make e2e-kind-object-store-outage` keeps all three no-PVC voters running and
scales only the disposable MinIO fixture down. Successful Kubernetes reads must
prove no store pod/endpoints remain. A credential-validated OAuth write against
each voter must return an actual 500/503 OAuth server-error response with no
access token; transport timeouts do not count as correct API behavior. After the
store returns, every voter must issue a new token and all voters must introspect
it. Existing keys/JWKS and all application pod identities must remain unchanged.

An unsuccessful acknowledgement does not prove an uncommitted transaction.
Rhiza can report an uncertain outcome after local quorum certification while
object publication is unavailable. The test therefore checks refusal to
acknowledge success, recovery of service, and secret redaction; it does not
assert rollback of every failed request. Live status is recorded separately.

The first outage run rejected the response shape rather than treating any 500 as
sufficient. A controlled diagnostic rerun confirmed HTTP 500 in 16 seconds with
Fosite's unclassified `error` code. The token endpoint now normalizes only that
HTTP 500 fallback to `server_error`; typed 409 conflicts and explicit OAuth
protocol errors are preserved. Request/response failures and cancellation were
reproduced in deterministic tests before the fix. No client timeout extension or
relaxation of the accepted live response codes substitutes for this correction.
Final live results remain separate from the diagnostic attempts.

Final live result (2026-09-09): a fresh image containing the HTTP 409 preservation
guard passed the exact-three outage profile (exit 0). All three writes returned
the required HTTP/JSON failure rather than timing out. After MinIO recovery,
all nine new-token issuer/verifier combinations passed, app UIDs and no-PVC
volumes were unchanged, and JWKS/generated-key continuity and full-token/bare-secret
log checks passed. The fixture retained its object data; this does not test
object-store data loss or network partition. Temporary Kind clusters were removed.

## Corrupt archive acceptance

Rhiza v0.12.3 already validates the archive head in
[`decodeHead`](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/recovery/archive_codec.go#L160)
and propagates archive-load errors from
[`Node.Open`](https://github.com/mrchypark/rhiza/blob/v0.12.3/pkg/node/node.go#L205)
when before-ack durability is selected. GoAuthy must preserve that startup failure,
not initialize a replacement identity or serve from an incomplete materialization.
No custom repair algorithm or additional dependency is needed for this gate.

`TestNoPVCRejectsCorruptArchiveAndRecovers` uses the existing separate-process
account/signing-key recovery test and the filesystem object-store boundary. A
writer exits without Close; a successful recursive listing establishes one archive
head and no checkpoint CURRENT. Deliberately invalid header bytes must fail Open
with the pinned archive decoding error in a new local directory. Restoring the
original bytes permits another fresh-directory recovery with account authentication,
wrong-password rejection and signing-key continuity. Both no-PVC subprocess tests passed the final race run in 25.276s
(2026-09-09), including proof that failed startup leaves the corrupt object unchanged. This subprocess result is distinct from the live S3/HA result below.

`make e2e-kind-archive-corruption` is the corresponding Kind gate. It must
stop all writers before saving/replacing the head, prove actual archive startup
failure on all three fresh pods, restore the preserved original object, and verify
credential/key continuity plus new writes. Merely waiting for readiness to time out
is not sufficient. This tests malformed head rejection and operator restoration of
a known-good object; arbitrary corruption correction, missing extents, checkpoint
corruption and interrupted recovery remain separate requirements.

Live result (2026-09-09): the final corruption profile exited 0. All writers were
SIGKILLed (exit 137), their pods deleted, and no checkpoint CURRENT was present
before preserving the head. Every fresh no-PVC pod failed with the exact archive
decoder startup error and was not Ready. After deleting the failed controller/pods,
the corrupted remote object still matched the injected bytes. Restoring the original
object and creating fresh pods preserved original OAuth/API keys/JWKS and passed
all nine issuer/verifier combinations for new tokens. Source/failed/restored pod
UIDs changed; MinIO pod/container identity remained unchanged. Failed and recovered
logs passed full-token/bare-secret checks. This is known-good-object restoration,
not automatic reconstruction of lost or corrupt remote data.

The shared SIGKILL helper was also verified by rerunning
`make e2e-kind-no-pvc-crash-recovery` on the final script (exit 0). Temporary
Kind clusters were removed after both final runs. Storage vet, shell syntax and
HA rendered-manifest checks passed; shellcheck retains pre-existing
SC1091/SC1007/SC2015 findings.

## Missing archive blocks acceptance

A valid head is not sufficient if its referenced decisions are unavailable.
Rhiza v0.12.3 `readExtent` fetches generation-qualified objects under
`archive/blocks/` and propagates missing-object errors through before-ack Open.
The application must not serve a fresh identity or accept a partial archive.
This uses the existing Rhiza reader; no application archive parser is introduced.

The `missing-blocks` subtest of `TestNoPVCRejectsCorruptArchiveAndRecovers`
keeps the original head, moves the complete nonempty block directory outside the
filesystem fixture, and starts a fresh process/local directory. It requires an
archive-load error wrapping `os.ErrNotExist`, unchanged head bytes and no recreated
blocks. Restoring the saved directory permits account/signing-key recovery.
Both malformed-head and missing-block subtests passed race in 25.768s, and storage
vet passed (2026-09-09). This is deterministic filesystem-boundary evidence;
`make e2e-kind-archive-missing-blocks` is the separate S3/three-voter gate.

The live profile must save all blocks only after every writer is stopped, remove
only the disposable fixture's blocks prefix, prove successful listings show no
blocks while the head remains, and observe actual missing-object startup errors
on all three fresh no-PVC pods. After stopping those failed pods, the head must
remain byte-identical and blocks absent. Restoring the saved blocks must recover
existing credentials/JWKS and permit new writes on every voter. This is restoration
from a retained copy, not reconstruction of data whose only remote copy was lost.

Live result (2026-09-09): the final missing-block profile exited 0. Successful
listings proved a nonempty block set before removal, no blocks and an intact
archive head after removal and failed startup, and restored blocks afterward.
Every fresh no-PVC voter failed with the actual archive-load S3 missing-key error,
not merely a readiness timeout. The head remained byte-identical; the failed
controller/pods were removed before restoring blocks. Existing OAuth/API keys/JWKS
and all nine new-token issuer/verifier combinations passed, application UIDs were
replaced, MinIO identity stayed unchanged and logs passed secret checks.

The final shared lifecycle also passed the malformed-head Kind regression.
Shell syntax, storage vet and 11 listing positive/negative cases passed, including
transport failure, malformed JSON and null keys. Both temporary Kind runs were
cleaned up. Network partition, checkpoint corruption, individual block integrity
corruption and interrupted recovery remain unverified by this missing-block gate.

## Archive block integrity acceptance

Rhiza v0.12.3 `readExtent` compares `sha256.Sum256(data)` with the referenced
extent hash before decoding or applying any decisions. The GoAuthy qualification
keeps the object keys and valid head, replaces block contents with known wrong
bytes, and requires `archive extent integrity mismatch` during before-ack startup.
It must not classify a missing-object error or generic readiness timeout as proof
of content-integrity checking. Existing Rhiza validation is reused without a new
hashing/recovery implementation in GoAuthy.

The `corrupt-blocks` filesystem subtest saves original blocks outside the fixture,
creates the same object names with invalid content, and starts a new process with
fresh local storage. Failed Open must leave those bytes and the head unchanged,
without adding extra block objects. Restoring the saved originals must recover
account authentication and the original signing key. Its live counterpart is
`make e2e-kind-archive-block-corruption`; final results are recorded separately.
This gate covers content that disagrees with the existing reference, not a complete
assessment of coordinated manipulation of archive heads, certificates and blocks.

The final filesystem test run covered malformed head, missing blocks and corrupt
block contents: race PASS 37.344s (2026-09-09), with storage vet PASS. These are
separate-process filesystem tests; the Kind integrity result is not inferred from
them.

Live result (2026-09-09): the final block-corruption profile exited 0. With every
writer stopped and pod-local data removed, original blocks were saved and the same
object keys received deterministic invalid contents. Every fresh no-PVC voter
failed startup with `archive extent integrity mismatch`. After removing those
failed pods, the head and every injected block were unchanged. Restoring originals
with the existing MinIO mirror command preserved OAuth/API keys/JWKS and passed
all nine new-token issuer/verifier combinations. App UIDs changed, MinIO identity
was preserved, and failed/recovered logs passed secret checks. Five object-key
extraction cases verified relative/full-prefix names and rejected invalid names.

The missing-block Kind profile also passed on the final shared lifecycle. Both
live runs exited 0 and left no Kind clusters. Checkpoint corruption, network
partition and interrupted recovery are still separate uncompleted gates.

## Checkpoint pointer corruption acceptance

Rhiza v0.12.3 `checkpoint.Manager.Load` reads CURRENT and its exact immutable root.
An invalid root hash is rejected before archive recovery; `Node.Open` propagates
this as `load checkpoint manifest: invalid CURRENT:`. GoAuthy must not treat an
invalid existing pointer as the normal absence of an initial checkpoint.

The `checkpoint-pointer` subprocess test first closes a real writer to publish a
checkpoint, then requires exactly one CURRENT object. It replaces the pointer with
valid JSON containing an invalid root hash, starts with fresh local data, and
requires the checkpoint-specific Open error. Failed startup must leave the injected
bytes unchanged. Returning the original pointer permits account/signing-key recovery.
The final four-fault filesystem race run passed in 48.282s, and storage vet passed
(2026-09-09). No new database validation or recovery code was required.

`make e2e-kind-checkpoint-corruption` is the separate live gate. Unlike archive-only
profiles it enables checkpoint publication, proves both CURRENT and archive head
exist, stops every writer, and saves the valid pointer before modifying it. It
requires the actual checkpoint validation error from all three fresh no-PVC pods,
then stops those failed pods before checking pointer/head preservation and restoring
only CURRENT. The existing credential/JWKS/new-write/UID/log checks remain required.
This tests pointer validation and retained-original restoration; it does not qualify
checkpoint root/data-block corruption or interrupted checkpoint restoration.

Live result (2026-09-09): the final checkpoint-pointer Kind profile exited 0.
Successful listings proved CURRENT and archive head existed; the actual saved
pointer contained a positive index and 64-hex root hash. After all writers were
SIGKILLed and pod-local data removed, valid JSON with an invalid root hash replaced
CURRENT. Every fresh no-PVC voter failed with the checkpoint-specific validation
error. After deleting failed pods, the head and injected pointer remained unchanged.
Restoring only the saved pointer preserved credentials/JWKS and passed all nine
new-token issuer/verifier combinations, UID replacement, stable MinIO identity and
secret-log checks. Six checkpoint-listing positive/negative cases also passed.

The final shared archive-head corruption regression also exited 0. Both Kind
runs were cleaned up. Storage vet and shell syntax passed; shellcheck retained
pre-existing SC1091/SC1007/SC2015 findings. The broader checkpoint corruption
requirement remains open for immutable roots and data blocks.

## Checkpoint root integrity acceptance

Rhiza v0.12.3 `readRoot` bounds the downloaded root and compares SHA-256 against
CURRENT's root hash before parsing. A content mismatch returns
`load checkpoint manifest: checkpoint root integrity mismatch` through Node.Open.
The new gate keeps CURRENT valid and corrupts only its referenced immutable root,
so a pointer-parser failure is insufficient evidence for this case.

The subprocess test publishes a real checkpoint, decodes CURRENT using stdlib
JSON/hex, and derives the existing root key (`roots/<20-digit-index>_<hash>.json`).
It saves that object, replaces its content, requires the root-specific Open error
with fresh local state, and checks both injected bytes and original CURRENT remain
unchanged. Restoring the saved root must recover account/signing-key identity.
This is test fixture addressing, not a new application archive decoder or repair
implementation. `make e2e-kind-checkpoint-root-corruption` is the corresponding
three-voter gate; results are recorded separately. Checkpoint data blocks and
interrupted recovery remain distinct conditions.

Final filesystem evidence (2026-09-09): all five fault subtests passed race in
58.749s; storage vet passed. The root case recovered through its original CURRENT
and restored root, rather than replacing checkpoint identity.

Live result (2026-09-09): the final checkpoint-root Kind profile exited 0. It
addressed the exact root named by the saved CURRENT (checkpoint index 121), stopped
every writer and removed pod-local data, then corrupted only that root. All three
fresh no-PVC voters failed with the specific root-integrity error. After failed
pods were removed, CURRENT/head were unchanged and the corrupt root bytes persisted.
Restoring only the saved root preserved credentials/JWKS and passed all nine new
token issuer/verifier combinations, app UID replacement, stable MinIO identity and
secret-log checks. Profile checks explicitly proved root/pointer checkpoint modes
use 1s while archive-only modes use 1h.

The final shared CURRENT-pointer corruption regression also exited 0. Both Kind
runs were cleaned up. Checkpoint data-block integrity and interrupted recovery
remain open; root integrity does not substitute for those checks.

## Checkpoint data-block integrity acceptance

Rhiza's checkpoint validator reads referenced data blocks with a size bound and
checks both byte count and SHA-256. During archive-base recovery, a mismatch
propagates through `RestoreCheckpointBase` to Open; actual file download performs
its own size/hash checks too. The gate corrupts block content while keeping CURRENT,
its referenced root and archive head valid, so metadata rejection alone cannot pass.

The `checkpoint-blocks` subprocess case publishes a real checkpoint, preserves
its block directory, writes wrong bytes under the same keys, and starts with fresh
local state. It requires the checkpoint-block integrity error, unchanged root and
CURRENT, unchanged injected blocks and no unexpected new block files. Restoring
original blocks must preserve account/signing identity. The corresponding live gate
is `make e2e-kind-checkpoint-block-corruption`; final live evidence is separate.
The fault uses the existing validators and fixture orchestration, not a new
application hashing or repair implementation.

Final filesystem evidence (2026-09-09): all six fault subtests passed race in
75.802s with same-length first-byte flips for block corruption, including the exact `restore checkpoint recovery base: checkpoint block
integrity mismatch` error. Storage vet passed. These tests do not substitute for
the separate live three-voter result.

The initial Kind block-corruption run passed with a length-changing payload. That
run demonstrates rejection but cannot distinguish size validation from hashing.
The final gate therefore preserves each original block length and XORs only its
first byte, verifies equal lengths and different contents before upload, and
compares the same mutated bytes after failed startup. The final live result below
uses this stronger content-hash fault.

The first same-length Kind run rejected corrupt data correctly but failed to
recover: restored pods remained in CrashLoopBackOff. Pinned MinIO `mc mirror
--overwrite` was then reproduced skipping different same-size contents in a tiny
local fixture; explicit `mc cp` replaced them. The checkpoint-block restore path
now copies every saved original explicitly, downloads each remote object again,
and compares its bytes in the helper before starting voters. The failed run is
not final DR success; the corrected path was verified in a fresh live run below. This also
means mirror completion alone is not evidence of content restoration into an
existing destination.

Final live result (2026-09-09): `make E2E_PORT=59361
e2e-kind-checkpoint-block-corruption` exited 0 after cleanup. All three fresh
no-PVC voters rejected same-length corrupt checkpoint blocks with the specific
integrity error. CURRENT/root/head and injected bytes remained unchanged. Each
original block was explicitly copied, downloaded and byte-compared before restart.
Recovered voters passed original OAuth/API-key/JWKS continuity, all nine new-token
issuer/verifier combinations, pod UID replacement, stable MinIO identity and
secret-log checks. The existing MinIO fixture retains its own PVC; this proves
GoAuthy local-state loss recovery from retained object storage, not loss of that
object store. Two preceding runs stopped at an occupied local port before fault
injection and are infrastructure failures, not DR acceptance evidence.

The subsequent checkpoint-root regression on the same candidate failed before
fault injection: CURRENT did not appear during the 60-attempt polling loop. All
three baseline pods were Ready at collection but had restarts. This is not a root
regression PASS, and the earlier root PASS does not resolve this verification gap.
Owned test clusters were cleaned up.
Pod restart counts were 1/1/2. Cleanup removed the pod status and private temporary
artifacts; no retained diagnostic file was found. The exact restart cause (including
whether OOM or application exit) is therefore unknown and must not be inferred.

Follow-up verification (2026-09-09): after adding termination-status columns to
the existing failure cleanup diagnostics, `make E2E_PORT=59361
e2e-kind-checkpoint-root-corruption` exited 0 and cleaned up. This supplies the
root regression result for the current candidate; it does not identify or prove
resolution of the earlier intermittent CURRENT-publication failure. No production
resource limits, probes or test timeout were changed. The diagnostic uses native
kubectl columns (restart counts, current/previous termination reason and exit
status, previous signal), excluding log bodies, environment and termination
messages. A local API fixture exercised the real kubectl printer and verified
OOMKilled/137 presence and private message exclusion; shell syntax and diff checks
also passed. No failure diagnostic was emitted by the successful live run.

## Interrupted recovery acceptance (pending)

Use an observed checkpoint block read/download as the interruption boundary; a
sleep followed by SIGKILL or an already Ready process is insufficient. Require
actual killed-process status, preserved object-store bytes and original
credentials/signing identity after retry. Test retained partial local state
(container restart) and new emptyDir (pod replacement) separately. Rhiza's later
journaled SQLite/graph installation is a distinct interruption boundary and is
not covered merely by interrupting the download. The filesystem subprocess gate
and local three-voter Kubernetes gate must each report their own result before
this requirement is checked complete.

Filesystem implementation (2026-09-09):
`TestNoPVCInterruptedCheckpointDownloadRecovers` uses a FIFO at one owned SQLite
checkpoint block key. It first supplies the complete original for validation,
then waits for Rhiza's download directory and supplies only 64 bytes. It observes
those exact bytes in the temporary SQLite file before SIGKILL and checks the
process signal. After restoring the original regular object, all object content
hashes must match the original snapshot. Retained partial-DataDir recovery and
fresh-DataDir recovery from an independent original snapshot both reuse the real
account/signing-key and invalid password/master-key assertions. Native filesystem
bucket Upload clones the latter snapshot with version metadata; raw file copying
proved insufficient. This is a local filesystem fault fixture, not real S3 or Kind
acceptance, and does not interrupt the later materializer journal installation.
The focused interrupted-download and ordinary recovery race run passed in 23.08s.

Final shared-helper regression: `go test -race ./internal/storage -run
'^TestNoPVC' -count=1 -timeout=5m` passed in 86.152s, including all six corruption
cases, ordinary recovery and the new interrupted-download case. Storage vet and
diff check passed. No Kubernetes interrupted-recovery result is claimed.

The real-MinIO candidate is `make E2E_PORT=59361
e2e-kind-checkpoint-interruption`. It starts from a published checkpoint after
removing all original voters, then injects a test-only native sidecar into fresh
no-PVC pods. The sidecar must observe a partial SQLite download on each first
main-container attempt before deliberate SIGKILL. Restart retains those pod UIDs,
emptyDirs and sidecar identities. A test-only 300-second startup-probe budget
allows observation of the injected stall; normal deployment probes are unchanged.
The existing object-store init container is preserved. Baseline/injected renderer
checks reject duplicate YAML keys and prove both init containers remain present.
Proxy race tests passed in 1.357s and vet passed. Live acceptance is pending and
will be recorded separately; this candidate does not cover loss of the partial
emptyDir after interruption or journaled SQLite/graph installation interruption.

The first Kind attempt stopped before fault injection: Kubernetes rejected
unnecessary sidecar port names longer than 15 characters. The loopback proxy and
control endpoints need no declared container ports, so those declarations were
removed. The extracted renderer confirms their absence and preserves the native
sidecar and original init container. The failed attempt was cleaned up and is not
live interruption acceptance evidence.

The second Kind attempt applied the replacement pods but failed the partial-file
observation gate. All three app containers were running with zero restarts; no
SIGKILL acceptance was reached. Sidecar status values were lost during cleanup,
so failure diagnostics now print only the validated boolean state fields before
cleanup. Source inspection found MinIO's full-buffer Read behavior incompatible
with the initial 64-byte stall. The revised candidate delivers 32 KiB before
stalling and rejects selected blocks no larger than that. This revision remains
pending real-MinIO verification; it must not be reported as a passing chaos gate.

The 32 KiB revision passed proxy race tests in 1.582s and vet. The client-side
regression requests a fixed 32 KiB independently of the proxy constant; an isolated
Go overlay changing only the proxy back to 64 bytes failed that test as expected.
This proves the regression detects the buffering mismatch, while the revised
real-MinIO run remains separate acceptance evidence.

Final live result (2026-09-09): the 32 KiB candidate
`make E2E_PORT=59361 e2e-kind-checkpoint-interruption` exited 0. Every fresh voter
reported blocked and partial-written on its first app attempt while not Ready.
CURRENT, referenced root, selected block and archive head were byte-compared while
those downloads were blocked. Each main container then received SIGKILL with exit
137; request cancellation and release were checked. The same pod UIDs, emptyDirs
and native sidecar container identities survived, while all main container IDs
changed. Recovered voters preserved the original OAuth token, generated API key
and JWKS identity, passed all nine new-token issuer/verifier combinations and
recovered-app secret-log checks. MinIO pod/container identities stayed unchanged.
The owned Kind cluster was cleaned up. This supersedes the candidate's pending
status above, but proves retained partial-data recovery only: post-interruption
pod replacement, materializer journal installation interruption and network
partition remain separate open gates. MinIO's fixture PVC remains outside the
GoAuthy no-PVC failure boundary.

### Fresh-pod retry after interrupted download

`make E2E_PORT=59361 e2e-kind-checkpoint-interruption-fresh-pods` reuses the
observed 32 KiB download boundary and exit-137 assertions. Its replacement flag is
valid only with the interruption profile. Before SIGKILL it orphans the controller;
while kubelet is stopped it requests deletion of all interrupted pods. After
kubelet resumes, successful API reads must show every old pod absent. With no app
writers, CURRENT/root/selected block/head must still match their saved bytes.
Normal pods are then created with no fault sidecar and no PVC. Each recovered pod
UID and main-container ID must differ from the interrupted one, and the shared
authentication/keys/3×3 token/MinIO identity checks run again. This proves new
emptyDir use, not physical erasure of old host storage blocks. Static flag and
renderer checks passed; live acceptance is recorded separately when complete.

Final fresh-pod live result (2026-09-09):
`make E2E_PORT=59361 e2e-kind-checkpoint-interruption-fresh-pods` exited 0. All
three first-attempt downloads reached the observed partial-file boundary before
SIGKILL/exit 137. The interrupted pods were deleted, and CURRENT/root/selected
block/head matched the originals before any fresh app started. All recovered pod
UIDs differed from the interrupted UIDs, with normal sidecar-free emptyDir
deployment. Original OAuth/API-key/JWKS continuity, all nine new-token
issuer/verifier combinations, recovered-app log redaction and stable MinIO
pod/container identities passed. The owned Kind cluster was cleaned up. Together
with the separately passing retained-pod gate this covers both local-state retry
modes for interrupted checkpoint download. Journaled SQLite/graph installation
interruption and network partition remain uncompleted; no production recovery
code or new dependency was introduced.

## Peer partition OAuth acceptance (candidate)

The existing Cilium deny policy isolates goauthy-2 peer traffic on TCP/UDP 8444;
it leaves object-store traffic available. The strengthened gate must keep all
application pod/container identities unchanged, prove majority request success
and structured minority token failure, then verify acknowledged majority tokens
on all three voters after healing. A transport timeout is not an acceptable OAuth
failure response. These are stateful checks: `CreateAccessTokenSession` persists
access-token/request rows through `storage.Execute`, and `GetAccessTokenSession`
reads the request using Rhiza linearizable consistency. A failed request does not
prove rollback of an ambiguous commit; the gate asserts that no token was returned.
Readiness/JWKS checks alone do not satisfy this acceptance condition. Sequential
issuance is not concurrent-write chaos; broader concurrency and complete feature
parity remain separate requirements.

Candidate validation (2026-09-09): shell syntax/ShellCheck, custom-image rendering,
required DCR Secret and strict token extraction checks passed. Six isolated
response-oracle checks accepted the two allowed structured errors and rejected a
returned token, wrong status, invalid JSON and transport timeout. The public Make
target is `make E2E_PORT=59361 e2e-kind-network-partition`. No live partition PASS
is claimed: current Docker kernel is `6.12.30-dory`, with no evidence that the
previous Cilium 1.20.0 route-reconciler `protocol not supported` failure has been
resolved. The unchanged failing environment was not rerun for this candidate.

A subsequent non-mutating probe narrowed the current prerequisite failure:
Linux/arm64 stdlib `syscall.Socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, protocol)`
succeeded for NETLINK_ROUTE (0) and NETLINK_NETFILTER (12), but NETLINK_XFRM (6)
returned `protocol not supported`. It ran in disposable `busybox:1.36.1` with
read-only root, no network, all capabilities dropped, no-new-privileges and an
8 MiB executable tmpfs for the probe. It sent no netlink requests and changed no
routes or host settings. A first bind-mount attempt failed before executing the
probe because the Docker daemon could not see the macOS temporary path; streaming
the same binary into the container tmpfs produced the result above. A kernel
providing XFRM netlink is a necessary prerequisite, not proof that all remaining
Cilium requirements or the OAuth partition gate will pass.

## Journal installation process-crash recovery — Linux PASS

`make test-no-pvc-journal-linux` exited 0 on 2026-09-09. The final candidate passed
all five real Rhiza phases (`prepared`, `sqlite-backed-up`, `graph-installed`,
`sqlite-installed`, `committed`) in 37.40 seconds, plus the trace-boundary oracle
checks. `GOOS=linux GOARCH=arm64 go vet ./internal/storage` also passed.

Each case writes a real certified checkpoint, then starts recovery under pinned
strace in a non-root container with read-only root, no external network, all
capabilities dropped and a disposable executable tmpfs. The test verifies the
tracee PID/parent before SIGKILL, actual journal phase and SQLite/graph backup
layout before and after termination, the successful delayed journal rename,
PID-qualified SIGKILL and absence of any subsequent parent-directory fsync start.
A negative oracle case rejects even an unfinished fsync after that rename. A
separate socket-free native control confirmed that the directory-path filter
actually records `fsync` calls (its first output assertion was too strict about
strace column whitespace; the captured call itself succeeded).

Object bytes remain unchanged at the interrupted boundary. Existing account,
wrong-password and signing-key checks pass after restarting with the retained
partial directory and independently with fresh local state backed by a native
object-store snapshot preserving required version metadata. Retained recovery
also removes the journal and both backup paths. Production GoAuthy/Rhiza code and
module dependencies are unchanged; strace is confined to the test image.

This qualifies a process crash after the journal rename and before parent-folder
fsync. It does not prove power-loss durability, generated API-key behavior at
this boundary, or MinIO/three-voter Kubernetes recovery. Those scoped gates remain
open. The previous 37.72-second pass preceded the stricter fsync trace oracle;
the final 37.40-second run is the acceptance evidence.

### Generated API-key continuity added to all no-PVC recovery cases

The final shared-helper candidate passed `go test -race ./internal/storage -run
'^TestNoPVC' -count=1 -timeout=10m` in 97.772 seconds and `go vet
./internal/storage`. This covers ordinary archive recovery, six corruption and
original-copy recovery cases, and the FIFO interrupted-download retained/fresh
filesystem cases with generated-key assertions added.

`make test-no-pvc-journal-linux` then passed all five journal stages and the trace
oracle in 37.89 seconds. In both retained and fresh recovery, the original
Generate key authenticates **before** any bootstrap/export. Modified tokens fail;
Clients Read is allowed and Update denied before and after export. The fresh
artifact contains the same winner, the shared singleton retains TTL0, and the
total API-key row count remains one. Only an expected test token is copied into
the fresh test root, not the original export; the bootstrap configuration still
contains Generate. No production restore path consumes that expected-token file.

This supersedes the earlier account/JWKS-only Linux scope. MinIO/Kind interruption
at these journal stages remains unverified; TTL0 adds no expiry-boundary claim.

Real S3 transport regression also passed: `sh scripts/e2e-no-pvc-s3.sh` exited 0
with the enhanced shared helper in 4.815 seconds. The disposable MinIO fixture
survived the writer's ungraceful exit without Close, and fresh local state
recovered the original account, signing key and generated API key/permissions.
The fixture container and network were removed. This is standalone archive
recovery over S3, not journal interruption over MinIO or a Kubernetes quorum test.

## MinIO/Kind journal interruption candidate

`make E2E_PORT=59361 e2e-kind-journal-interruption` selects `sqlite-installed` by
default. `GOAUTHY_E2E_JOURNAL_INTERRUPTION_PHASE` can select one of the five known
phases; it is mutually exclusive with the other fault profiles. Each run creates
its own three-voter no-PVC application and MinIO fixture using the existing
backup/restore harness. The baseline uses the normal image. Only replacement
recovery pods use `journal-fault`, which contains the unchanged GoAuthy binary,
pinned strace/jq and a test-only shell entrypoint.

The wrapper kills the real GoAuthy child after a successful delayed journal
rename and rejects a later directory fsync in the trace. It proves the exact
child PID's SIGKILL and actual local layout, then holds without an application
until all three proofs are collected. CURRENT/root/selected SQLite block/head
are compared while all three children remain dead. Release causes the wrapper
to exit137; kubelet restarts the same Pod and emptyDir, and a phase-bound marker
makes the wrapper exec normal GoAuthy. The child's SIGKILL proof and the wrapper's
later exit137 are distinct assertions, not interchangeable crash evidence.

The gate requires fresh recovery Pod UIDs relative to the source, unchanged UIDs
across release, new main-container IDs, noPVC, original OAuth/generated-key/JWKS
continuity, new tokens across all nine issuer/verifier pairs, log redaction and
unchanged MinIO Pod/container identity. The test-only startup budget allows the
observation window; production settings are unchanged. A five-case extracted
shell trace oracle passed, including rejection of fsync after rename and of the
wrong killed PID. Live results are recorded separately; a candidate is not PASS.

Candidate correction: the initial sqlite-installed Kind run exited 0 but emitted
missing source-UID file errors. The newly added comparison had not captured
those UIDs before stopping source pods, and a failed command substitution became
an empty string that incorrectly compared unequal. That run is not final
acceptance. The gate now captures source UIDs first and requires successful,
nonempty reads before comparing them. `make test-e2e-journal-oracles` executes
the actual shell predicates against missing/empty/equal/distinct UID fixtures and
trace failure cases; it is a prerequisite of the Kind journal target. The
corrected candidate is verified separately.


## MinIO/Kind journal interruption final acceptance (2026-09-09)

All five final runs exited 0 with the phase-specific exact-three PASS marker:

| Phase | Final execution session |
|---|---|
| prepared | 17658 |
| sqlite-backed-up | 36199 |
| graph-installed | 37346 |
| sqlite-installed | 24096 (corrected UID guard) |
| committed | 56700 |

The final runs verified the child-kill, retained-Pod recovery and identity/token
assertions described above. The shell trace and UID negative regression gate
passed. Every owned Kind cluster was removed after execution. The initial
sqlite-installed session 80810 remains excluded from acceptance.

These runs use three voters on one Kind node and retain the recovery Pod's
emptyDir across the journal fault. They do not establish physical-node
independence, power-loss durability or fresh-Pod recovery after this journal
fault. Object comparisons cover CURRENT, its root, one SQLite block and archive
head, not every object in the prefix. MinIO's independent fixture PVC survives.
Network partition and encrypted scheduled-backup/retention parity remain open.

## Native peer-partition gate

`make E2E_PORT=59361 e2e-kind-tc-network-partition` uses the existing OAuth
partition harness with iproute2 fault injection. The Cilium target remains
separate. Its owned, single-node Kind cluster has three no-PVC GoAuthy voters;
the runner resolves goauthy-2's UID and ready CRI sandbox, then revalidates the
sandbox PID and non-host network namespace before each `tc` operation.
Eight unique-priority ingress/egress TCP/UDP source/destination-port 8444 drop
filters isolate peer traffic. A preexisting clsact is rejected, live counters
must observe traffic, and healing removes the owned qdisc. The app's security
context and object-store configuration are unchanged.

The target first runs an isolated kernel capability check and the actual
harness counter predicate against negative fixtures. Live acceptance additionally
requires majority token issuance/introspection, a structured minority OAuth
500/503 without token (transport failure is rejected), all-three readiness after
healing, pre-fault/majority token continuity, new-token 3×3 verification, no app
PVC, unchanged app/MinIO identities and unchanged JWKS. Static checks alone do
not complete this gate. It does not establish CNI policy enforcement or
physical-node fault independence.

First native Kind execution (2026-09-09, session 32460) failed and is not
acceptance: the minority became unready, majority OAuth operations succeeded,
but the isolated voter's token endpoint returned HTTP 401 rather than the
required structured 500/503. The owned cluster was removed. This exposed a
client-authentication error-classification path requiring investigation; the
harness was not loosened to accept authentication rejection as availability
failure. Log: `/tmp/goauthy-tc-partition-20260909.log`.


Native peer-partition final acceptance (2026-09-09): corrected execution session
77395 exited 0 with `network peer partition OAuth/no-PVC recovery passed`.
The unchanged gate passed all listed assertions, including live filter counters,
majority issuance, strict minority failure and healed 3×3 token verification.
No Kind clusters remained after cleanup. Final log:
`/tmp/goauthy-tc-partition-fixed-20260909.log`. The prior 401 run is excluded.
The application correction preserves typed bootstrap scope lookup failures and
normalizes wrapped availability failures at the token response boundary; focused
real-Fosite/Rhiza regression and race checks passed. This profile does not yet
exercise generated bootstrap API keys under network partition. Cilium policy
support, physical-node independence and full backup-retention parity remain open.

### Generated-key partition candidate

The native/Cilium shared harness now uses the existing generated-bootstrap
overlay and a Clients Read-only `generated-reader` key, TTL0. It checks matching
exports and self-test/Clients scope read before the fault; a malformed scopes
PUT must fail with 403 before decoding. During the partition, majority voters
retain those permissions while the minority's self-test and protected scope
read return their existing fail-closed 401 responses without protected data.
After healing, each voter must export the original token, authenticate it,
permit read and deny update. Full token and bare secret are checked against
current container logs before and after the fault. Export tokens must match the
exact generated alphanumeric format before creating the private curl config;
comparison failures do not print secret values. This adds no production code or
package. A live result is required before checking the qualification complete.


Generated-key partition final acceptance (2026-09-09): session 18312 exited 0
with `network peer partition OAuth/no-PVC recovery passed` after executing the
expanded generated-key baseline/partition/heal checks above. The original key
and read-only permissions survived, the minority returned no protected data,
and current-container logs contained neither full token nor bare secret.
The OAuth, packet-counter, noPVC, JWKS and app/MinIO identity assertions also
passed. Log: `/tmp/goauthy-tc-generated-partition-20260909.log`.
All owned Kind clusters were removed. This completes generated-key continuity
under this native peer partition; it does not qualify concurrent bootstrap
writes during partition, Cilium policy enforcement or physical-node failures.

### 2026-09-09 explicit expire-all retention qualification

`GOAUTHY_E2E_BACKUP_EXPIRE_ALL=1 KIND_CLUSTER=goauthy-backup-restore-e2e-ra9 E2E_PORT=59361 ./scripts/e2e-kind-backup-restore.sh`
passed (exit 0), log `/tmp/goauthy-retention-expire-all-kind-20260909.log`.
The default policy preserves the only expired backup of a retired source;
expire-all dry-run leaves its artifact/receipt intact and apply removes both.
The current source backup survives, is fetched after source Kind and local
ciphertext deletion, and restores into a new exact-three Kind with emptyDirs.
Original credential/JWKS/generated-key continuity and newly issued tokens on
all three restored pods pass. This is the manual retention profile, not a
paused scheduler-holder qualification or physical-host independence test.

### 2026-09-09 scheduled paused-holder qualification

The scheduled `PAUSE_HOLDER=1` profile completed with exit 0, log
`/tmp/goauthy-scheduled-kind-pause-native-errors-20260909.log` (source cluster
`goauthy-backup-restore-e2e-sp11`, slots 11:27/11:30 UTC). A holder stopped beyond
its lease window is superseded, resumes without changing the successor's
certified completion watermark, and fails with scratch cleanup. Source node,
storage and voter identities remain healthy/unchanged during the fault. The
same gate then removes source Kind and local ciphertext and completes the
external-catalog fresh-Kind no-PVC credential/key/token recovery checks.
Immutable duplicate publication remains allowed; this is not an S3 fencing test.

## Schema86 failure metadata recovery (2026-09-11)

`TestNoPVCAccountAndSigningKeyRecovery` now includes a real failed password-grant attempt before the writer exits without Close. A new process with a fresh data directory recovers exactly one failed attempt and a positive last-failure timestamp alongside the existing account and signing-key checks. `sh scripts/e2e-no-pvc-s3.sh recovery` passed with race detection against disposable MinIO in 17.105s (`/tmp/goauthy-schema86-s3-recovery.log`). This proves S3-backed crash recovery for these fields; it does not cover retained password OAuth tokens or loss of the object-store host.

### 2026-09-12 schema87 focused recovery evidence

`TestNoPVCAccountAndSigningKeyRecovery` now checks the recovered dynamic-client backchannel URI and password subject/client association in addition to retained refresh-token and signed ID-token claims. Separate processes use fresh local data directories. Filesystem object-store passed 3.220s; disposable MinIO S3 with `-race` passed 20.676s via `scripts/e2e-no-pvc-s3.sh recovery` (`/tmp/goauthy-schema87-s3.log`). These checks do not establish multi-host loss or Kubernetes recovery. Linux interrupted-install qualification subsequently passed all five SIGKILL phases (41.52s total) and trace-cut checks via `make test-no-pvc-journal-linux`; log `/tmp/goauthy-schema87-journal-linux.log`. This is not physical power-loss evidence.

`TestNoPVCBackchannelDeliveryRecovery` additionally passed with `-race -count=1` (13.110s, `/tmp/goauthy-recovered-backchannel-race.log`). A writer subprocess queues a subject logout using the real user-deletion producer and exits without closing storage; a fresh-directory recovery subprocess delivers it over TLS with restored signing material. The receiver verifies signature, issuer, audience, subject and absent SID; a second worker step produces no additional delivery. This fixture seeds the association directly and uses filesystem object storage, so it does not independently establish password issuance, S3 delivery recovery, or multi-host resilience.
