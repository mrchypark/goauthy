# API-key bootstrap secret compatibility

## Current verification checklist

This table distinguishes implemented behavior from the remaining deployment gates.
Historical entries below retain the context of earlier failures and intermediate
candidates; current dated results in [status.md](status.md) take precedence.

| Check | Existing packages/mechanism | Evidence/state |
|---|---|---|
| [x] Plain and cryptr-compatible Encrypted JSON import | stdlib JSON/filesystem; existing ChaCha20-Poly1305; Rhiza transaction | deterministic import/retry/tamper tests |
| [x] Shared Generate startup and one winning token | existing keyring envelope + fenced Rhiza transaction | final standalone and exact-three Kind live PASS 2026-09-09 |
| [x] Original deadline on restart or local export loss | encrypted shared payload + stdlib filesystem export | final standalone E2E; real Close/Open race PASS |
| [x] Export expiry without API-key revocation | existing authenticated purge and persistent NULL marker | final standalone 120-second wall-clock E2E PASS |
| [x] Key reference/retirement/rewrap integration | existing keyring and CAS worker | focused race and reference tests; local exports remain outside DB inspection |
| [x] Full-token and bare-secret log boundary | existing shell/curl/CLI E2E tooling | final standalone/Kind lifecycle logs checked |
| [x] Three-peer expiry and all-pod restart | same Kind harness, optional expiry profile | final 300-second live Kind profile PASS 2026-09-09 |
| [x] SIGKILL followed by recovery without local DB files | existing Go subprocess testing + Rhiza filesystem object store | focused race PASS 9.940s; isolated process test, not a Kind/S3 gate |
| [x] Standalone cold backup restores generated key without local export | existing cold-copy workflow + independently provisioned master key | live TTL0 restore PASS 35.56s |
| [x] Majority loss by stopping two peers and restoring three | existing StatefulSet scale + HTTP/CLI checks | live Kind quorum profile PASS 2026-09-09 |
| [x] Three-peer checkpoint/archive restore into fresh PVCs | existing object-prefix transfer + independently provisioned master keys | live TTL0 Kind restore PASS 2026-09-09 |
| [x] Expiring standalone cold backup preserves export deadline and prevents regeneration | existing cold-copy/CLI/HTTP workflow | live 120-second expiry profile PASS 2026-09-09 |
| [x] Expired three-peer backup restores without re-export | existing checkpoint/archive transfer, CLI and read-only test sidecar | live 300-second Kind restore/full rollout PASS 2026-09-09 |
| [x] All-voter SIGKILL and loss of every pod-local volume | existing containerd/Kubernetes fault injection + Rhiza before-ack archive | live no-checkpoint Kind recovery PASS 2026-09-09 |
| [x] Object-store outage and recovery with unchanged app pods | existing Kind/MinIO fault injection + Fosite error serialization | final live exact-three outage PASS 2026-09-09; key/JWKS/log continuity and 3×3 new-token verification |
| [x] Malformed archive head rejection and restored account/signing identity | Rhiza decoder + existing Go subprocess/filesystem boundary | final focused race 25.276s; final live Kind malformed-head rejection/original-object restoration PASS 2026-09-09 |
| [x] Missing archive blocks with intact head | existing Rhiza missing-object failure + Kind/MinIO retained block copy | final filesystem race 25.768s; live noPVC three-voter rejection/restoration PASS 2026-09-09 |
| [x] Archive block content integrity failure and original-copy restore | existing Rhiza SHA-256 validation + Kind/MinIO fixture | final three-fault filesystem race 37.344s; live three-voter integrity rejection/restore PASS 2026-09-09 |
| [x] Invalid checkpoint CURRENT reference and original-pointer restore | existing Rhiza checkpoint loader + Kind/MinIO fixture | final four-fault filesystem race 48.282s; live three-voter pointer rejection/restore PASS 2026-09-09 |
| [x] Referenced checkpoint root integrity and original-root restore | existing Rhiza root SHA-256 validation + Kind/MinIO fixture | final five-fault filesystem race 58.749s; live three-voter root rejection/restore PASS 2026-09-09 |
| [x] Same-length checkpoint data-block integrity and original-block restore | existing Rhiza size/SHA-256 validation + explicit MinIO copy and byte verification | final six-fault filesystem race 75.802s; live three-voter hash rejection/restore PASS 2026-09-09 |
| [x] Interrupted checkpoint download and installation | existing Rhiza recovery + filesystem FIFO and native bucket snapshot fixture | [x] observed partial SQLite download/SIGKILL, retained and fresh local-state recovery race; [x] real-MinIO three-voter Kind retained-partial-data recovery; [x] post-interruption pod replacement/new-emptyDir recovery (Kind, 2026-09-09); [x] generated-key five-phase Linux journal interruption, pre-export authentication/permissions and retained/fresh recovery (2026-09-09); [x] all five MinIO/Kind journal phases with retained-Pod generated-key continuity (2026-09-09; scope in [DR contract](no-pvc-dr.md)) |
| [x] Native peer network partition and healing | existing iproute2/Kind fault injection, generated-bootstrap overlay and CLI | live exact-three Kind PASS 2026-09-09: original key/permissions, minority fail-closed behavior, current-log redaction and unchanged identities |
| [ ] Concurrent bootstrap-write durability during partition | existing project chaos/restore infrastructure | dedicated concurrent Generate mutation evidence remains missing |
| [ ] General TOML secrets configuration parity | already installed `pelletier/go-toml/v2` | separate configuration surface; not an API-key JSON parser gap |


### Input-format research (2026-09-08)

The pinned upstream's advanced API-key bootstrap input is JSON, not TOML.
Its [loader](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/migration/bootstrap/mod.rs#L19-L53)
reads `<bootstrap_dir>/api_keys.json` as an array; the upstream
[sample](https://github.com/sebadob/rauthy/blob/v0.36.2/bootstrap/api_keys.json)
uses the same `name`, optional `exp`, `secret`, and `access` shape already
validated by GoAuthy's `parseBootstrapKeysWithDecrypt`.
Keep `encoding/json` and the existing validation and atomic import. Adding a
second TOML API-key payload format would not close an upstream parity gap.

Rauthy's [TOML bootstrap configuration](https://github.com/sebadob/rauthy/blob/v0.36.2/config.toml#L442-L542)
is a separate surface: directory/generated-artifact settings and the legacy
base64-JSON `api_key` plus separate `api_key_secret`. General TOML configuration
compatibility remains unimplemented; the already-installed
`github.com/pelletier/go-toml/v2` can parse that configuration when implemented.
Any adapter must retain existing secret validation, restricted access groups,
bounded input and atomic Rhiza import. It must not silently reinterpret a
missing legacy secret as an empty secret or generated key.

This format research alone does not establish deployed E2E parity; the shared
startup implementation and remaining deployment gates are described below.

`Store.Bootstrap` continues to accept GoAuthy’s existing `Plain` form. Encrypted
entries can be imported with `Store.BootstrapWithMasterKeyDir(ctx, path, dir)`.
The directory must contain the configured master-key files (raw 32-byte keys,
base64 raw URL encoded), using the same IDs and encoding as the OIDC keyring.

The reader matches Rauthy v0.36.2 (`cryptr` 0.10): version 1, ChaCha20-Poly1305,
big-endian header length/chunk fields, key ID in the header, and nonce followed
by authenticated ciphertext. Unknown keys, malformed headers, wrong keys, and
tampering fail closed. Decrypted values are validated as 64 ASCII alphanumeric
characters and wiped after use.

With Rhiza v0.12.3, import errors are propagated even when a linearizable read
can already see the matching key rows: those rows do not prove before-ack
object-store durability. The import request ID hashes the full SQL statements
and arguments, including the creation timestamp, so independent starters cannot
reuse one ID with a different command fingerprint. Existing atomic upserts keep
the original creation time. The real filesystem-store outage regression covers
the first attempt, identical retry, changed-clock retry and successful recovery;
full API-key and focused race evidence is in [status.md](status.md).

`Store.BootstrapWithGeneratedSecrets` now implements Generate import as a library
entry point. It persists the encrypted `bootstrap.secrets.enc`-shaped container
before importing digest-only API-key rows. An independent retry authenticates
and reuses the existing exact entry set without replacing the token or extending
the original deadline. Invalid/mismatched/expired artifacts fail closed.
New publication uses a unique sibling 0600 temporary file, sync/close and a
non-overwriting hard link. A competing publication returns an error rather than
claiming the caller's generated secret was saved. This is resumable ordering,
not a claim of a distributed transaction spanning a filesystem and Rhiza.

The stdlib CLI `go run ./cmd/goauthy-bootstrap-secrets -file PATH -key-dir DIR`
explicitly prints decrypted entries to stdout. Treat that output as credentials;
never send it to application logs. `-purge-expired` removes only an authenticated
expired artifact and prints a boolean result, never credentials. Expiry uses a
typed error; an unknown key whose name contains "expired" cannot trigger deletion.
The encrypted container version/deadline/entries layout matches pinned Rauthy's
[`generated_secrets.rs`](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/migration/bootstrap/generated_secrets.rs).

New deterministic real-Rhiza tests verify generated-token authentication,
independent retry, unchanged bytes/token/deadline, recovery from a prewritten
artifact and zero partial imports for malformed/tampered/expired/mismatched
artifacts. CLI tests verify exact retrieval, expiry equality, non-overwrite and
safe purge. `/tmp/goauthy-wide-batch-bootstrap-20260906.log` records the run.

### Shared Generate startup (schema85)

Server startup selects `BootstrapWithSharedGeneratedSecrets` when both
`GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_FILE` and
`GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS` are configured. The existing
`GOAUTHY_API_KEY_BOOTSTRAP_FILE` supplies JSON; TTL is an explicit unsigned
32-bit count of seconds, with zero meaning no expiry. No new dependency is used.
Without these settings, existing Plain/Encrypted startup remains unchanged.

The singleton encrypted payload and API-key digest/access rows commit in one
Rhiza transaction. Concurrent starters reuse the authenticated winner. Every
startup acknowledges it through a fresh fenced durable write before exporting
retrievable credentials. Commit-unknown errors remain errors. Input identity is
SHA-256 of the exact file bytes: even whitespace changes conflict with initialized
configuration. Retries retain the original deadline and never overwrite a
conflicting local export.

Expiry removes ciphertext but retains an immutable initialization tombstone.
Startup after expiry acknowledges that marker without generating replacement
keys. The server runs authenticated local/shared expiry purge immediately and
once per minute. Export expiry does not revoke the API key itself.

The shared envelope participates in master-key reference checks, retirement
counts and the existing CAS rewrap worker. Local exported files are outside DB
reference inspection: retain their original encryption key until retrieval is no
longer needed or authenticated expiry purge finishes. Shared rewrap does not
rewrite local exports; an unreadable existing export fails closed.

Custom code is limited to Rhiza transaction/retirement fencing, initialized-state
and local export coordination. Neither stdlib nor the existing crypto libraries
provides these application-specific transaction semantics. Cryptography, JSON,
randomness and filesystem operations reuse existing packages described above.
Deployed three-peer E2E, crash/quorum/restore chaos and log-boundary checks remain
open; concurrent in-process real-DB tests do not substitute for those gates.

### Filesystem publication durability follow-up

Publication now syncs the parent directory after the non-overwriting hard link.
Syncing the ciphertext file alone did not establish durability of its new name.
When reusing a prewritten artifact, bootstrap syncs both the file and its parent
before importing any API-key rows. This also retries the boundary after an earlier
link succeeded but directory sync failed. Errors propagate; the file is preserved
for authenticated recovery rather than replaced.

Final generated-artifact/import/recovery focused race PASS 36.773s:
`/tmp/goauthy-generated-artifact-durability-final.log`; API-key vet PASS.
This verifies the filesystem calls and import behavior on this host, not power-loss
or deployed HA durability.


Verified HA key-lifecycle integration points:

- `internal/oidc/key_status.go`: authenticate/count the new envelope family and
  include it in `MasterKeyReferenceStatus.Safe`.
- `cmd/goauthy/master_key_status.go`: expose the sanitized family in the server
  status aggregation.
- `cmd/goauthy/master_key_retirement.go`: include it in both old-key counts and
  non-active-reference counts; adding only the inspector family is insufficient.
- `cmd/goauthy/key_rewrap.go`: run its CAS rewrap in the existing worker lifecycle.

These DB integration points are implemented with old-key retirement and CAS
rewrap regression tests. See [status.md](status.md) for verification evidence.

### Pinned startup and repeated-purge behavior

Pinned [`migrate_init_prod`](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/migration/bootstrap/mod.rs#L65-L103)
skips initial production bootstrap once JWKS exist. Therefore an expired export
artifact does not by itself imply regeneration on every normal production restart.
The shared Generate tombstone preserves this initialization guard.

Pinned [`purge_if_expired`](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/migration/bootstrap/generated_secrets.rs#L223-L240)
returns false for an absent artifact. GoAuthy now matches that idempotent behavior:
repeated `-purge-expired` prints `{"removed":false}`. A missing key directory while
an artifact exists remains an error, with no deletion or credential output.
The prior repeated-purge test reproduced an ENOENT failure. After the fix, the full
CLI race suite passed 1.828s (`/tmp/goauthy-generated-purge-idempotency.log`), and
API-key/CLI vet passed. That earlier run predates the shared startup integration described above.

### Runnable deployment checks

- `make e2e-standalone-generated-bootstrap`: start the actual server, retrieve
  through the explicit CLI, authenticate through HTTP, restart without changing
  ciphertext/token, remove only the test export and recover the same token from
  Rhiza. Credentials stay in restricted temporary files; logs are checked.
- `make e2e-kind-generated-bootstrap`: exact-three deployment counterpart with
  cross-pod token agreement/authentication and pod replacement. Both scripts
  require the existing host-capacity gate before building. See status for live
  results; having a harness is not a passing deployed gate.
- `go test -race ./cmd/goauthy -run '^TestGeneratedBootstrapPurgeWorkerExpiresBothCopiesAndStops$' -count=1`:
  real Rhiza verifies immediate purge of both expired copies, retained DB marker
  and bounded cancellation of the background worker (PASS 8.732s).

The first deployment profiles use non-expiring exports to avoid a short wall-clock
TTL racing startup. Deployed expiry, restore, quorum-loss and log checks under
those faults remain separate completion requirements.

### Self-test authorization regression found by live E2E

The generated `Clients:read` token authenticated at `/auth/v1/clients`, but its
own `/auth/v1/api_keys/{name}/test` returned 403 because `Store.Get` required
`ApiKeys:read`. Pinned Rauthy's
[`get_api_key_test`](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/api_keys.rs#L139-L159)
returns the authenticated key's own metadata without that management grant.
GoAuthy now reads name, secret digest/expiry eligibility and access in one
linearizable query for self metadata. Collection
and mutation routes retain their existing authorization. The regression checks
scoped self access, other-name denial and a stale principal after rotation.

### Wall-clock export expiry profile

`make e2e-standalone-generated-bootstrap-expiry` adds a separate expiring DB/export
to the default lifecycle profile. The original credential is captured before
expiry, then the server stops. Bounded CLI polling must observe expiry without
plaintext output; two subsequent starts must retain the original API key and
publish no replacement export. The default TTL is 120 seconds, configurable
between 90 and 900 seconds using `GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS`.
This verifies export expiry independently from API-key validity, and startup
while an expired record has not yet been purged. It does not prove quorum-loss
or restore behavior. The final single-query candidate passed this live profile on 2026-09-09,
including the host-capacity gate and all assertions; see status.md.

Final deployment requalification (2026-09-09): standalone lifecycle plus wall-clock
expiry and exact-three Kind token convergence, authentication, pod replacement
and full/bare-secret log checks passed against the final single-query candidate.
Logs and remaining three-peer expiry/quorum/restore gates are recorded in status.md.

### Three-peer wall-clock expiry profile

`make e2e-kind-generated-bootstrap-expiry` selects an initial 300-second export
TTL (override `GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS`, 180–900 seconds). It
requires all three initially retrieved tokens to agree, then observes expiry or
purge with empty CLI stdout and retains authentication using the original token.
Only exit 1 with the exact application expiry or artifact-absence diagnostic is
accepted; Kubernetes transport failures and early expiry fail the test.

After rolling all three pods, the script verifies every UID changed and requires
exports to be absent. A successfully retrieved post-restart export fails
immediately; it cannot pass by waiting for a regenerated export to expire again.
Saved-token authentication and full/bare-secret log checks run after the restart.
The final 300-second live profile passed on 2026-09-09 after the earlier
capacity blocker cleared. This is not quorum-loss or backup-restore evidence.

### Cold backup/restore scope

The standalone cold-copy operator test is the existing backup mechanism: stop
the source cleanly, copy only its Rhiza data directory, then restore into a new
directory with independently provisioned encryption keys and bootstrap config.
The Generate extension checks same-token re-export without copying the local
credential artifact, restored HTTP authentication, and no full/bare secret in
stopped-server logs. It uses a non-expiring export; token equality alone is not
proof of an expiring backup's original deadline. Live results are recorded in
status.md; source assertions do not establish a passing backup gate.

No custom snapshot protocol is introduced. This reuses the existing cold-copy
workflow and Rhiza persistent state. Online backup, object-store retention,
corruption/interruption recovery and a three-peer restore remain distinct gates.

Cold backup/restore final live result (2026-09-09): the expanded
`make e2e-standalone-backup-restore` passed in 35.56 seconds, including generated
same-token re-export, API/OIDC checks and stopped-server log checks. The tested
export has TTL0; expiring-backup deadline verification remains open.

### Majority-loss profile

`make e2e-kind-generated-bootstrap-quorum` keeps the Rhiza membership at three
while scaling the disposable StatefulSet down to one running pod. It checks that
the original survivor remains alive (`/livez` 204), readiness fails (`/readyz`
503), and the saved API key receives an actual 401/503 response. Transport errors
are not accepted as an authorization-denial result.

After restoring three replicas, the profile compares the membership and replaced
pod UIDs, retrieves each export for token equality, rechecks authentication on
all three pods, and scans full/bare-secret logs. This tests majority loss by
stopping peers; it is not a network partition, concurrent-write durability, or
backup-restore test. Live verification state is recorded in status.md.

Majority-loss live result: the Kind quorum profile passed on 2026-09-09 with
liveness204/readiness503/API-key401-or503 during peer loss, followed by unchanged
membership, recovered pod identities, original token authentication and log checks.

### Clean three-peer backup restore

The extended `make e2e-kind-backup-restore` uses the existing Rhiza
checkpoint/archive object-prefix transfer. Generated keys are initialized in the
source's three voters before checkpoint export. The source cluster is removed
before the separate restore cluster starts. Restore independently provisions the
same master keys, member identities and JSON configuration; it has no GoAuthy
PVC before application deployment. Only the object prefix is transferred.

All three restored exports must match the source token and authenticate through
HTTP. Existing OAuth introspection, JWKS identity and post-restore write checks
remain. Token/log checks cover the running source and restore pods, not pod
shutdown logs. The profile uses TTL0 and does not prove expiring-backup deadlines,
backup corruption recovery or online snapshot correctness.

Final live result (2026-09-09): `make e2e-kind-backup-restore` exited 0.
Source and restored three-peer clusters passed generated-token equality, HTTP
authentication and running-pod log checks; OAuth/JWKS continuity and new issuance
also passed. Checkpoint index was 131, config_id 1, generation 11, with two files
and two blocks. Both disposable clusters were removed. The first attempt failed
before backup due to shell helper variables overwriting the loop variable; the
final run passed after using a separate ordinal loop variable.

### Expiring cold-backup verification contract

`make e2e-standalone-backup-restore-expiry` selects the expiry variant of the
existing standalone cold-copy workflow. Its acceptance criteria are a pre-expiry
backup, same-token recovery before the original export deadline, authenticated
expiry of both separately encrypted exports at that original deadline, and a
second clean restore of the original backup after expiry without a new export.
The saved API key must still authenticate: export expiry is not key revocation.
Secrets and local export files remain outside the data backup. This uses existing
shell, CLI and HTTP checks, with no new package or backup implementation.
Implementation alone is not a PASS; the dated status entry records live evidence.

Live expiry result (2026-09-09): the 120-second standalone profile exited 0.
Both exports expired within the original bounded deadline window, after delaying
the first restore by at least 20 seconds from source readiness. Restoring the
original pre-expiry backup into another clean directory after expiry produced no
export; original-key HTTP authentication passed there and after another restart.
This does not establish expiring three-peer object-store restore.

### Expired three-peer object-store restore contract

`make e2e-kind-backup-restore-expiry` selects a bounded expiring variant of the
existing checkpoint/archive transfer. The source must export its three-peer
winner and finish the backup before the original expiry floor. A private copy of
the source encrypted artifact is used to observe authenticated expiry before
starting the restored application. Only the object-store prefix crosses into the
new cluster; master keys and bootstrap configuration are independently supplied.
All three restored pods must authenticate the original API key without exposing a
new local export, including after a full rolling restart. OAuth/JWKS continuity
and post-restore token issuance remain required. This complements the standalone
original-deadline test; it does not claim network-partition or corruption recovery.
The dated status entry, rather than this contract, establishes live PASS evidence.

Live three-peer expiry result (2026-09-09): the 300-second profile exited 0.
Backup completed before the source deadline floor; the copied encrypted export
then returned authenticated expiry with empty stdout before restored application
startup. All three fresh-PVC pods returned the exact CLI missing-file result,
authenticated the saved original API key, and passed full-token/bare-secret app-log
checks. Every pod UID changed during the subsequent rollout and the same checks
passed again. OAuth/JWKS continuity and new token issuance also passed.

The final common-renderer TTL0 Kind backup/restore regression also exited 0.
Both profiles passed rendered-YAML checks; no disposable Kind clusters remained.

### No-PVC final candidate (2026-09-09)

After the user clarified that no GoAuthy PVC is the project default, both the
TTL0 and 300-second expiry Kind backup/restore profiles passed again with actual
source/restored StatefulSet and pod emptyDir/no-PVC assertions. The expiry full
rollout also passed on disposable pod data. See [the DR contract](no-pvc-dr.md)
for source guarantees and remaining all-voter abrupt-loss tests. Earlier fresh-PVC
results remain historical and are not substituted for this final evidence.
