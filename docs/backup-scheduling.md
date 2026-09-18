# Backup scheduling implementation

The target remains Rauthy v0.36.2's configurable backup schedule, encrypted
object-store publication and retention, using Rhiza v0.12.3 without GoAuthy PVCs.
Calendar, replicated lease/completion slots and server worker lifecycle are
implemented and qualified. Basic scheduled DR, source-storage outage,
two-voter loss/recovery, signer rotation and paused-holder fresh-Kind DR passed
on 2026-09-09. Operator-managed recovery keys remain required; automatic secret
distribution is optional. Earlier dated pending/failed records below are
historical and superseded by the final named PASS records, not deleted evidence.

## Package selection and direct code

Go's `time` package supplies calendar arithmetic, timezone data loading and
`Time.ZoneBounds`; it has no cron parser. The investigated candidates and exact
counterexamples are in [package research](package-research.md). robfig lacks a
year field; gorhill and HashiCorp cronexpr differ in year range and weekday/day
semantics; go-quartz rejects simultaneous restricted day fields and skips the
second repeated fall-back time. Its parsed fields are private. An intersection
of public Quartz triggers still needs independent timezone and grammar handling.
These findings justify a bounded compatibility parser/calendar component rather
than claiming that an unmodified candidate preserves the required behavior.
They are evidence about the investigated versions, not proof that no other
package exists. No new production dependency was added.

`internal/backupschedule` uses only standard packages. Parsed field values are
sorted and immutable. `Next(ctx, after)` searches allowed calendar fields inside
constant-offset timezone intervals, advancing across gaps and repeats. It returns
a strictly later whole second, zero on exhaustion of 1970–2100, or an error on
cancellation/unsupported synthetic timezone offsets outside ±24 hours. Native
IANA timezone changes, including non-hour changes and date-line skips, are covered
by deterministic chronological checks. The server embeds standard `time/tzdata`
so named IANA zones work in the scratch image.

## Deliberate correction to upstream

The pinned Rust cron 0.17 iterator can move backward in UTC during a fall-back:
`0 * 1 * * * *` in New York on November 7, 2027 yields 01:00 EDT, 01:00 EST,
then 01:01 EDT. Starting inside the late repeated hour can also return an earlier
instant. A runnable upstream regression documents this behavior in
[test/compat/rauthy-cron](../test/compat/rauthy-cron/README.md).
GoAuthy deliberately returns matching instants in chronological order, including
both repeated occurrences. It does not reproduce past-time dispatch. This is a
behavioral correction, not a claim of byte-for-byte iterator parity.

## Reproducible checks

```sh
go test -race ./internal/backupschedule
go vet ./internal/backupschedule
# Optional cross-language development gate; Rust/Cargo required:
CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target go test -tags cronoracle ./internal/backupschedule
```

The opt-in gate runs the pinned Rust parser and compares acceptance and exact
field sets with Go for a generated grammar corpus. It does not execute backup
jobs and does not replace the required real MinIO, Kubernetes or chaos tests.

## Native timezone boundary regression

A far-future New York schedule exposed a non-advancing `ZoneBounds` result at
2040-12-30 19:00 EST. The installed Go `time/zoneinfo.go` POSIX rule expansion
uses a 365-day year-end bound even in leap years. Advancing by a nanosecond
does not fix the entire final day; jumping a day would skip valid executions.
The evaluator therefore checks whole seconds only while the native bound is
stale, preserving exact-boundary and later-in-day matches and cancellation.
This rare path costs up to a day's second checks per affected year; normal
intervals retain calendar jumps. A regression checks a 2100 target from 2027,
two matches at/in the stale interval, and an impossible February 30 schedule.

Final component verification (2026-09-09): Go race with `cronoracle` passed
in 8.137s; vet passed. Rust reference tests passed (three tests, including the
upstream backward-iteration reproducer). This does not qualify automatic
backup execution or HA ownership.

## Complete execution primitive

`goauthy-backup create` now provides a complete export→signed remote publication
operation reused by the server dispatcher. It cleans its owned temporary ciphertext and
can use an independently configured destination store. The operator real-MinIO
gate passed (4.710s), including fetch, authenticated restore and SQL continuity.
Final backup/CLI race tests passed (1.974s/2.167s) and vet passed. See
[operator options](backup-operator.md). The CLI itself does not acquire job
ownership or schedule retention; the server composes Create with RunSlot and
Prune as described below.

## HA ownership research (component implemented below)

Rhiza v0.12.3's public `DB.KVCAS` is the smallest candidate for coordination:
`KVMutationRequest` carries an exact expected value/existence condition and
`TTLMS`; the replicated materializer treats expired values as absent before
performing the comparison. `MutationReceipt.Applied` distinguishes a won CAS
from a losing attempt. Use a namespaced deterministic key, random holder token,
fresh request IDs, renewal by exact token CAS, and cancel work on any failed or
ambiguous renewal. Native TTL decisions use the command submission's observed
wall clock; clock skew and pause recovery need explicit tests. The before-ack
mutation path and all-voter restart must be qualified for this use.

This avoids a new SQL migration or an independently implemented object-store
lease protocol. Checkpoint publisher claims cannot be repurposed: they reserve
checkpoint indices and mutate checkpoint lifecycle state. Existing export pins
protect recovery data from GC, not scheduled-job ownership.

A lease is not a publication fence. A paused former holder can resume after
expiry and publish alongside a successor. Current random-ID conditional catalog
objects preserve safe immutable duplicates; they do not provide exactly-once
backup execution. The dispatcher relies on cooperative cancellation. Renewal-loss, quorum-outage
and paused-owner qualification remain separate requirements; a preliminary
ownership read alone is not publication authority. This research alone does
not complete a scheduling checklist item.

Final `create` Kind qualification passed (2026-09-09, exit 0): independent
source/destination MinIO, signed publication, retention, local artifact/source
Kind deletion, fresh Kind restore, original credentials and new-token validation
on all three voters. Log: `/tmp/goauthy-create-kind-20260909.log`. GoAuthy uses
no PVC. This manual gate does not prove physical-host independence or automatic
scheduling; the later scheduled gate is recorded below.

## Replicated lease component

`WithLease` now wraps a callback with native Rhiza KV CAS/TTL ownership. A
SHA-256-namespaced scope key carries a fresh random holder value; acquisition
requires absence and renewal requires that exact value. Committed receipts and
`Applied` are checked separately. Each RPC has a TTL/3 deadline, and a slow
acquisition/renewal receipt is rejected before starting/continuing work.
The renewal worker cancels the callback context on errors or non-applied CAS.

Cleanup stops and joins renewal even on callback panic, then conditionally
expires only its own token with a one-millisecond TTL. It never unconditionally
deletes the key, so cleanup cannot delete a successor. Cleanup has a bounded
context independent of parent cancellation; any release error is returned.
Callbacks must honor cancellation; Go cannot forcibly terminate a callback that
ignores its context. Callers choose a TTL between one second and one hour.

WithLease alone does not record slot completion or provide exactly-once
publication. RunSlot supplies the completion watermark, and the server wires
the timer and configuration described below. Three-voter failure qualification
remains required before marking automatic backup parity complete.

Lease component verification (2026-09-09): real standalone Rhiza tests cover
competing/independent scopes, positive renewal past the original TTL, callback
errors/cancellation, forced token replacement with successor preservation, and
panic cleanup. Focused race passed in 4.340s and vet passed. These tests do not
prove three-voter quorum failure, object-store durability or scheduled execution.

## Durable completion slots

`RunSlot` now composes the lease with a linearizable read of a namespaced
completion watermark. It skips a due slot if that scope has already completed
it or a later slot. The callback runs before any completion update; an error or
canceled context leaves the slot retryable. The post-success write is a native
KV CAS against the exact previously read value, without TTL. A late old holder
cannot overwrite a changed successor record. No schema or package was added.

Markers use canonical positive Unix seconds through year 2100. Malformed or
future markers and future/non-whole-second due times fail before executing the
callback. The callback must return success only after the full backup operation
completes. `executed` reports callback entry, not remote publication success.
A crash/ambiguous error between remote publication and marker commit can still
produce a duplicate on retry; this is not an exactly-once protocol.

Real standalone Rhiza checks cover successful replay/older-slot suppression,
failure followed by retry, concurrent newer-marker preservation, cancellation,
corruption/future-state rejection, and reopen persistence. Focused race and vet
passed (2026-09-09). Reopening the same local data directory does not prove
no-PVC/object-store DR. Timer/configuration/backup-retention integration and
three-voter/Kind failure tests remain outstanding.

## Timer dispatch and actual S3 pipeline

`Schedule.Run` now selects future slots, waits with cancellable standard timers,
and invokes `RunSlot` serially with a per-attempt timeout. Failed attempts are
reported and the next future slot is selected; missed intervals are not replayed
in a burst. Long waits recheck civil time at least once per minute, including
backward clock corrections. Reporting callbacks must return promptly and avoid
logging provider errors that could contain credentials.

The real-MinIO operator gate now runs this actual timer against standalone
Rhiza. Its callback performs `backup.Create` and `backup.Prune`, then the test
fetches and authenticates the signed remote artifact, restores a fresh prefix,
opens Rhiza on a new data directory and verifies original SQL rows. The extended
gate passed in 6.845s (2026-09-09); log:
`/tmp/goauthy-scheduled-s3-20260909.log`. Fixture containers were cleaned up.
Focused race tests cover failure followed by the next run, job deadline
cancellation and cancellation during a future wait; vet passed.

This exercises real dispatch through remote backup/restore in a test runtime.
Production configuration/key loading, embedded timezone data, worker lifecycle
and sanitized reporting are now wired. `make test-backup-scheduled-s3` invokes
the production runtime against real MinIO and standalone Rhiza, then fetches
and restores the signed encrypted backup into fresh storage. It passed in
6.757s on 2026-09-09 (`/tmp/goauthy-server-backup-s3-20260909.log`). This is
not a server-process or three-voter test. The later basic scheduled Kind DR
gate and two-voter-loss gate passed; paused-holder qualification remains open.

## Three-voter scheduled DR gate

`make e2e-kind-backup-scheduled E2E_PORT=59361` enables the real server worker on
all three source voters. It schedules a single future UTC slot, requires all
source credential checks and readiness before that slot, then requires one
signed catalog entry and the post-completion-marker server success log. The
external MinIO fixture lives outside the Kind cluster. The existing gate stops
the source servers, checks retention, removes the local artifact and source Kind,
and restores into a new no-PVC three-voter cluster before testing old credentials.
This fixture proves neither physical-host independence nor scheduler failure
recovery; quorum-loss, paused-holder and scheduler restart cases remain separate.
Live qualification results belong in the dated status record, not in this
command's existence alone.

### Node clock and source-storage outage profile

The Kind gate derives schedule epochs and wait deadlines from the source Kind
node, avoiding comparisons between a desktop clock and its Docker VM clock.
`sh scripts/test-backup-schedule-clock.sh` checks the real scheduling helpers with
an external Docker boundary stub, including clock errors and year rollover.
`make e2e-kind-backup-scheduled-outage E2E_PORT=59361` selects two finite slots
120 seconds apart, takes source MinIO down for the first, requires a failed
attempt at that exact slot and no signed completion, restores storage before
the second, and requires its exact success log before the existing full DR flow.
Implementation/render checks are not live chaos qualification; consult status.

`make e2e-kind-backup-scheduled-quorum E2E_PORT=59361` uses the same two
slots with the default 60-second lease and a 10-second attempt timeout. It stops
the single fixture node's kubelet, kills voter containers 1 and 2 through
containerd, and confirms exit 137 while preserving Pods and emptyDirs. During
this fault, logs come directly from CRI because Kubernetes log access needs
kubelet. The first slot must fail with an empty signed catalog. Recovery requires
new running container IDs for both killed voters, unchanged Pod UIDs and an
unchanged survivor container before the second slot and full DR checks.
This profile does not simulate a paused former lease holder.

The initial quorum run (`/tmp/goauthy-scheduled-kind-quorum-20260909.log`)
exited 1 without observing a failure log. A confirmed observer bug discarded
container stderr: [crictl preserves stdout and stderr separately](https://github.com/kubernetes-sigs/cri-tools/blob/master/cmd/crictl/logs.go),
while Go's default logger writes stderr. The CRI helper now merges both streams
before exact-message/slot filtering. The regression reproduces discarded stderr
and passes after this correction. The failed run is not quorum qualification.

### Basic scheduled Kind qualification

The final exact-three server gate passed on 2026-09-09 (exit 0), log
`/tmp/goauthy-scheduled-kind-stage-20260909.log`. It verified a single signed
completion and the exact slot's post-marker success log, retention, source Kind
and local-artifact removal, external-catalog fetch into a fresh Kind/prefix,
no GoAuthy PVC and original/new credentials across all three restored voters.
The fixture was cleaned up. Earlier generic failures are not retrospectively
explained by this pass. Scheduler failure/chaos and key rotation remain open.

### Source-storage outage qualification

The first live outage gate passed (exit 0) on 2026-09-09; log
`/tmp/goauthy-scheduled-kind-outage-20260909.log`. With source MinIO unavailable,
the first exact slot failed and the signed catalog was empty. After source
recovery, the second exact slot completed, followed by retention and complete
external-catalog fresh-Kind DR with credential continuity. All fixtures were
cleaned up. Quorum-loss and paused-holder cases are not covered by this result.

### Two-voter loss qualification

The final quorum profile passed (exit 0) on 2026-09-09; log
`/tmp/goauthy-scheduled-kind-quorum-stderr-20260909.log`. Both targeted containers
exited 137 with kubelet stopped. The 08:22 UTC slot timed out at ownership after
10 seconds and the signed catalog remained empty. With the default 60-second
lease unchanged, kubelet recovery replaced only the two killed containers,
preserved all Pod UIDs and survivor 0's container, and restored readiness before
08:24. That exact slot completed once, followed by retention, source Kind and
local artifact removal, external-catalog fresh-Kind/emptyDir restore and old/new
credential checks across all three voters. Cleanup left no fixture clusters or
containers. This does not qualify paused-holder resumption or physical-host loss.

### Signing-key overlap implementation

Catalog readers now accept a locally pinned native PKIX public-key PEM bundle
(1–32 distinct keys, 16 KiB maximum); the writer still uses one native PKCS8
private key. Server `GOAUTHY_BACKUP_TRUST_KEY_FILE` defaults to its current
signer's public key and, when explicit, must include that signer. Both startup
catalog validation and retention use the full bundle. Trust is loaded at startup;
changing keys requires restart and does not change the replicated ownership scope.
See [operator procedure](backup-operator.md) and [package rationale](package-research.md).

The production-runtime MinIO test passed in 13.420s on 2026-09-09, log
`/tmp/goauthy-server-backup-rotation-marker-s3-20260909.log`. It verifies old/new
scheduled completions and exact linearizable slot markers, refuses startup when
old trust is removed with old records retained, and decrypts/restores both backups
into independent fresh prefixes with SQL continuity. Library/CLI/config race
checks and vet passed. This evidence alone is not a three-voter rolling-key gate;
the later live qualification is recorded below.

`make e2e-kind-backup-scheduled-rotation E2E_PORT=59361` schedules two finite
source-node UTC slots 180 seconds apart. All three source Pods initially trust
both keys and sign with the old key. After the exact first completion, the gate
checks an old-only fetch, removes that local copy, updates the signing Secret
and rolls all three Pods before the second slot. It requires changed Pod and
container IDs and readiness. The second exact completion must use the new signer
(verified by new-only fetch), while listing the mixed catalog requires both keys.
Both real entries survive retention of a third, expired fixture. Local copies
and source Kind are removed before external-catalog restoration of the new backup
into fresh emptyDirs. The default 60-second lease is unchanged.

The first live rotation run (`/tmp/goauthy-scheduled-kind-rotation-20260909.log`)
completed its first backup and old-key fetch, then exited 5 before rotating.
Its helper had not initialized the expected Kind node required by the existing
container-ID checker. The helper now runs the existing single-node preflight
before capturing identities. That run does not qualify live key rotation.

The next run (`/tmp/goauthy-scheduled-kind-rotation-node-20260909.log`) completed
the 09:00 UTC old-key backup and all three rolling restarts, but its 09:03
scheduled attempt failed at `stage=create` with the generic error classification;
the gate exited 1 and cleaned up. Its cause is not established. Safe native
checkpoint publisher-busy/fenced classifications were added for diagnosis,
without changing retries or relaxing the successful-completion requirement.

`TestCreateCheckpointPublisherClaimBlocksThenReleases` independently reproduces
native checkpoint publisher contention: holding `AcquirePublisherClaim` makes
Create return `checkpoint.ErrPublisherBusy`, with no destination uploads and
empty scratch; explicit claim release makes the same inputs publish successfully.
The focused race check passed in 2.290s. This establishes a contention case,
not the cause of the generic Kind failure above. The classified live retry uses
`/tmp/goauthy-scheduled-kind-rotation-classified-20260909.log`; it passed as below.

### Live signing-key rotation qualification

The classified rotation gate passed (exit 0) on 2026-09-09. It verified the exact
09:16 UTC old-key completion, all three Pod/container replacements, and the exact
09:19 new-key completion. Named fetches independently proved both signing keys;
single-key listing rejected the mixed catalog while the combined bundle accepted
it. Retention preserved both real entries and removed only the expired fixture.
All local ciphertext and the source Kind were removed before restoring the new
backup from the external catalog into a fresh three-voter Kind with emptyDirs.
Old OAuth/JWKS/generated API keys and new cross-voter tokens passed; no fixture
cluster or container remained. This pass does not retrospectively explain the
earlier generic failure. Publisher-busy retry was subsequently qualified below;
paused-holder resumption and automated secret distribution remain open.

### Bounded checkpoint publisher contention retry (2026-09-09)

Create now includes the exact native `checkpoint.ErrPublisherBusy` error in its
existing six-attempt Export retry allowlist (100, 200, 400, 800, 1600ms cancellable
backoff). Fenced and joined cleanup errors remain fail-closed without retry;
publication happens only after a successful export. No dependency was added.

`make test-backup-checkpoint-busy-s3` passed on real MinIO in 6.595s
(`/tmp/goauthy-checkpoint-busy-final-s3-20260909.log`). Native held claims produce
six reads, zero uploads and empty scratch; explicit release permits publication.
A second case releases the native claim during a later read and proves the same
Create call retries successfully. Both results are fetched, decrypted and
manifest-verified. A temporary Go overlay removing only the retry addition fails
this transient case with `checkpoint publisher is active`; focused current race
checks pass (6.652s). The first S3 run failed test cleanup due to canceled t.Context;
fresh bounded cleanup context and prefix-before-copy registration fixed it.

Updated-candidate production scheduled S3 passed (13.207s) and manual full Kind
external-catalog/no-PVC DR passed (exit 0), including original source/local
ciphertext removal, fresh emptyDirs and credentials on all three voters. Logs:
`/tmp/goauthy-checkpoint-busy-scheduled-s3-20260909.log` and
`/tmp/goauthy-checkpoint-busy-kind-20260909.log`. Kind did not inject publisher
contention; the forced-contention evidence is the native MinIO test. These results
do not establish the cause of the earlier generic rotation failure.

### Paused-holder qualification boundaries (2026-09-09)

Pinned Rhiza v0.12.3 `pkg/network/server.go` stamps KV command observation and
expiry at submission; `pkg/materializer/materializer.go` applies CAS only when
expiry/existence and expected bytes match. GoAuthy uses that native comparison
for renewal and conditional release. A separate read of ownership cannot fence
a later S3 write, and checkpoint publisher claims are not scheduler leases.
No replacement lease package or custom distributed lock is warranted here.

The remaining process-pause gate must observe an actual holder token before
pausing its container, retain the other two voters, and wait for native expiry
and a successor's completed slot. Resume the original container with the same
container identity, then check that its old attempt does not regress completion
or expire the successor token. Check every listed artifact's signature and digest,
then remove the source and local artifacts and restore into fresh Kind emptyDirs.
In-flight immutable duplicates are permitted by the current publication contract;
exactly-once S3 publication must not be inferred from one successful schedule.
A callback blocked by a test channel is only cooperative-cancellation coverage,
not evidence of Linux SIGSTOP/SIGCONT, TTL expiry or remote-write fencing.

`TestRunSlotLostHolderCannotCompleteOrDeleteSuccessorLease` now qualifies the
cooperative boundary with real Rhiza: replace the owner through native KV, wait
for cancellation, let the old callback return nil, and require ErrLeaseLost,
no completion marker and the exact successor token still present. Focused race
passed (2.439s); the full backupschedule race suite passed (14.727s), log
`/tmp/goauthy-backup-lost-holder-race-20260909.log`. Production code was unchanged.
The process-pause gate above remains unchecked.

A temporary Go overlay removing only RunSlot's post-job context check still
passed this regression (1.268s): native Rhiza also rejects the canceled-context
marker mutation. The test proves observable suppression across the composed
path, not that one particular guard is necessary or sufficient.

### Process-pause gate implementation in progress

The `e2e-kind-backup-scheduled-pause` target uses
`GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER=1`. It is not yet qualified.
The test-only `scripts/testdata/backup-watermark` observer uses native Rhiza
`OpenReadReplica`/`Sync`/`KVGet` against certified checkpoint/archive objects,
with a fresh disposable directory per invocation. It checks the exact expected
scheduler watermark; it does not join quorum or claim a linearizable read.
The observer's Linux build and vet passed; real object-store execution remains
part of the pending Kind gate. No production diagnostic endpoint was added.

The profile integration and shell regression checks passed (holder evidence,
node-clock slot calculation, and existing signer-rotation guard). The first live
candidate was launched with:

```sh
GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER=1 \
KIND_CLUSTER=goauthy-backup-restore-e2e-sp9 E2E_PORT=59361 \
./scripts/e2e-kind-backup-restore.sh
```

Log: `/tmp/goauthy-scheduled-kind-pause-20260909.log`. At this entry's writing,
the local BuildKit build is running; no Kind qualification pass is claimed.
Scratch presence plus an established catalog connection identifies a Create
holder connected to the paused catalog; it does not prove a specific PUT has
already been sent. The gate checks certified completion before resume and after
the old attempt settles, then preserves the exact signed catalog entry set
through retention and performs the existing fresh-Kind/no-PVC restore.

The first live attempt exited 1 before fault injection: chmod could not find the
observer copied into Kind's `/tmp`. A bounded BusyBox reproduction established
that Dory `docker cp` succeeded for ordinary storage but left no visible file
inside a mounted `/tmp` tmpfs. The observer now streams through `docker exec -i`
into the running mount namespace with umask 077. The real Docker regression
`sh scripts/test-backup-pause-copy.sh` passes exact binary-byte comparison and
mode 0600. Shell syntax, holder and clock checks also pass. A new live attempt
uses `/tmp/goauthy-scheduled-kind-pause-tmpfs-20260909.log`; qualification remains
pending until its terminal result. The original failed log is retained.

The tmpfs-fixed run reached the actual fault: the node clock passed the first
10:09 UTC slot, kubelet was inactive, and `/proc` showed one GoAuthy process in
state T with two others in state S. Observer files were visible in Kind with
0700 executable and 0400 configuration modes. The second finite slot is 10:12
UTC; final successor/DR qualification is still pending at this observation.

The tmpfs-fixed attempt ended exit 1 at its successor-completion deadline.
The actual first-slot holder was goauthy-2 (host PID 5372, state T). At 10:12:20
UTC both surviving servers logged ownership-stage operation timeout for the
10:12 slot. Their readyz endpoints still returned 204; readiness alone therefore
did not prove writable backup ownership. No successor catalog/completion was
observed. The full gate did not reach resume/observer/DR success. Cleanup removed
both Kind and fixture containers. Root cause remains under investigation; this
is not evidence that the no-PVC DR or pause requirement is qualified.

Follow-up diagnosis preserves the same lease and fault duration. Scheduler errors
now retain their original causes while distinguishing `lease_acquire` from
`completion_read`; the generic ownership label alone could not identify which
native call failed. Full backupschedule race passed (15.434s), focused server
checks passed (0.991s), and vet/shell regressions passed. Before resuming a failed
fault, the gate now captures only fixed scheduler diagnostics and UDP socket
state. The next live candidate log is
`/tmp/goauthy-scheduled-kind-pause-diagnostic-20260909.log`; no success is claimed
until terminal verification. No evidence currently establishes a need to change
Rhiza quorum, lease length, or publication policy.

The diagnostic run also exited 1 and cleaned up. It specifically recorded two
`stage=lease_acquire` timeouts at 10:32:20 for the 10:32 slot. A concrete fixture
fault was observed before cleanup: stopping kubelet made the single Kind node
NotReady. MinIO and kube-dns EndpointSlices became ready=false, whereas the
GoAuthy peer service uses publishNotReadyAddresses. Direct MinIO Pod health
returned 200; the MinIO Service IP refused the connection. Thus the process-pause
fixture also disrupted the source storage/DNS service path, invalidating the
intended isolated-voter-pause premise. This does not establish a Rhiza quorum bug.

The next fixture keeps kubelet running and changes only test-rendered liveness
failure tolerance to allow SIGSTOP. It must assert stable container identities,
NodeReady and service endpoints throughout the pause. Native lease duration and
production probe defaults remain unchanged. Both previous failed logs are kept;
none is a successful paused-holder qualification.

The kubelet-preserving fixture is implemented and its shell/render regression
checks pass. Only the pause test's rendered liveness failureThreshold is 120 at
the existing 10-second period; production manifests and other profiles are
unchanged. It checks all three Pod UIDs/container IDs/CRI PIDs before and after
resumption, NodeReady, ready MinIO endpoints and authenticated Service/DNS access
through the existing mc helper. The new live attempt is
`/tmp/goauthy-scheduled-kind-pause-kubelet-20260909.log`; it has started and is not
yet a qualified pass. This candidate also contains the default-preserving
retention-policy implementation, but this pause profile does not test expire-all.

The first kubelet-preserving attempt ended exit 1 before app deployment because
the new pause-only liveness change failed the strict manifest-render guard.
Log: `/tmp/goauthy-scheduled-kind-pause-kubelet-20260909.log`. It did not inject a
pause or exercise DR. The fix must be reproduced against actual Kustomize output,
not only a source-text guard, before another live candidate is started.

The render failure was reproduced and fixed: actual Kustomize probe indentation
is 8/10 spaces, but the first matcher used source YAML's 10/12 spaces. The
replacement count therefore remained zero. `test-backup-pause.sh` now invokes
real apply_app rendering with actual Kustomize input and only kubectl stubbed;
pause requires exactly one liveness-specific threshold 120 and default requires
none. Render, clock, tmpfs-copy and diff checks passed. The next live attempt log
is `/tmp/goauthy-scheduled-kind-pause-render-20260909.log`; result is pending.

### 2026-09-09 paused-holder observer execution correction

The `pause-render` Kind run reached a successor completion at 10:55 UTC while
its former holder was stopped, but exited 126 before watermark verification:
the observer executable under `/tmp` was denied execution. This is not a full
paused-holder or DR pass. The fixture now installs the executable under
`/usr/local/bin`, keeps private input files under `/tmp`, and executes `-h`
before fault injection. The Docker regression verifies private byte-preserving
copy into a noexec tmpfs and successful execution outside that mount. Both it
and the actual paused-holder manifest rendering regression pass. The corrected
full Kind run is pending; no completion checkbox is changed.

The subsequent `pause-executable` run failed before SIGSTOP: at 11:04 UTC
voter 0 reported `stage=lease_acquire reason="operation failed"`; the fixture
could not observe a blocked catalog request within its 90-second guard.
Node Ready and the source MinIO ready endpoint were independently observed.
This run does not prove a paused-holder failure, and the sanitized message does
not establish the native acquisition error's cause. No lease or quorum timing
was changed. The independent expire-all Kind DR profile is running next.

Static diagnostic classification now recognizes public Rhiza v0.12.3
`ErrCommitUnknown`, `ErrNotReady`, `ErrQuorumUnavailable`,
`ErrDurabilityUnavailable`, `ErrRequestConflict`, and `ErrInvalidRequest`.
Unknown commit takes precedence over wrapped cancellation/timeout/availability
causes because the mutation may already have committed. Joined provider text
is never emitted. The focused regression (0.894s) and `go vet ./internal/backup`
pass. This changes diagnostics only, not acquisition/retry/lease semantics;
the 11:04 failure remains unexplained until a new observed classification.

### 2026-09-09 paused-holder full Kind qualification PASS

The `pause-native-errors` run completed with exit 0:
`GOAUTHY_E2E_SCHEDULED_BACKUP=1 GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER=1 KIND_CLUSTER=goauthy-backup-restore-e2e-sp11 E2E_PORT=59361 ./scripts/e2e-kind-backup-restore.sh`.
Log: `/tmp/goauthy-scheduled-kind-pause-native-errors-20260909.log`.
First slot 11:27 UTC; successor slot 11:30 UTC. The fixture observes Create
scratch plus a catalog connection, stops the exact CRI process for over 65s,
keeps Kubernetes/source storage healthy, and verifies unchanged voter identities.
The successor completes while the prior holder remains stopped. Fresh native
Rhiza read replicas observe the exact successor watermark before and after
resuming the old holder. The old attempt fails and cleans its scratch; every
remaining signed artifact is fetched/verified, the successor survives, and the
exact catalog set survives retention. Original Kind/local ciphertext deletion
and new Kind/emptyDir restore preserve credentials, JWKS, generated key access
and newly issued tokens on all three restored pods.

This test allows 1–2 immutable completions; it does not establish a strict
external publication fence or exactly-once behavior. The earlier 11:04 native
acquisition error remains unexplained; the passing run is not its root-cause fix.
