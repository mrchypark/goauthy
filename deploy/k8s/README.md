# Rhiza runtime profiles

Production supports two explicit Rhiza `v0.12.0` modes. `standalone` uses one
embedded member and a single data directory. Both `standalone` and the legacy
`dev` profile reject peer and voter/admin-token inputs. `standalone` now also
accepts an optional S3 bucket and prefix with fixed `before-ack` durability,
using the same object-store validation as cluster mode; partial configuration
fails closed. `dev` remains local-only. The existing manifests below retain
their PVC layout; the dedicated [Ternal profile](../ternal-no-pvc/README.md)
is isolated and uses no PVC.
`make e2e-standalone` passed runtime smoke and restart verification, including
JWKS key persistence, plus the shared browser authorization-code/refresh flow
with primary and secondary URLs pointed at the same standalone endpoint.

The production `cluster` mode is exactly three embedded voters. Its Secret JSON
contains distinct voter tokens for each member and a separate
`GOAUTHY_RHIZA_ADMIN_TOKEN`; `GOAUTHY_RHIZA_PEER_TOKEN` is retained only as a
legacy admin-token alias. Source validation and static Kubernetes configuration
are verified. The exact-three base HA gate passed on the historical Rhiza `v0.10.0`
baseline. The fresh v0.12.0 full profile also passes pod replacement, quorum-loss
readiness 503, restoration and rolling restart; [verification details](../../docs/status.md)
separate this result from untested profiles and mixed-version upgrades.

## Local Kubernetes profile

`make e2e-kind` creates a dedicated `goauthy-e2e` kind cluster, loads the
locally built image, creates throwaway test secrets, and deletes that cluster
on completion. It verifies liveness, readiness, JWKS cache validation, valid
client-credentials issuance, and unauthenticated/invalid-client rejection. It
then deletes one peer, verifies service recovery, scales down to one peer to
assert readiness fails closed without quorum, restores all three peers, and
performs a StatefulSet rolling restart. JWKS key identity must persist through
each recovery.

This is a fixed **three-voter embedded Rhiza HA profile**. Each StatefulSet pod
uses its own PVC and its pod name as `NodeID`; all three receive the same,
ordered `quic://goauthy-{0,1,2}.goauthy.goauthy.svc.cluster.local:8444` member
list. A namespace-local VersityGW StatefulSet with a POSIX backend supplies
the shared S3-compatible checkpoint store, and the app chooses Rhiza
`before-ack` durability. The service is named `versity`. The object-store
credentials are throwaway E2E secrets, not a production object-store pattern.

This documents the HA topology; the exact-three base HA gate is verified.
Network
partitions and latency, object-store loss/corruption, empty-disk recovery, and
peer mTLS/key rotation remain separate pending chaos and Rhiza-release gates.

The deterministic exact-three backup/restore proof is `make
e2e-kind-backup-restore`. It first writes a sentinel token, gracefully stops
one orphaned pod while two voters remain so Rhiza can publish a certified
checkpoint, then stops the other pods and exports the complete
`goauthy-e2e/goauthy-e2e` object-store prefix. The restore uses a new Kind
cluster with fresh VersityGW and GoAuthy storage, restores the prefix before
starting GoAuthy, and re-creates the identical member/cluster secrets. It
checks `archive/head.bin`, `checkpoint/CURRENT`, the immutable root and all
referenced checkpoint blocks, then verifies the sentinel token, JWKS `kid`, and
a new cross-pod write/read. The latest gate passed with checkpoint index `82`,
`config_id` `1`, generation `11`, and `2` files / `2` blocks. The object-store
prefix is the backup; Kubernetes Secrets are re-provisioned separately.
The harness sets the cluster-only `GOAUTHY_RHIZA_CHECKPOINT_INTERVAL=1s` so
`checkpoint/CURRENT` appears deterministically; production overrides are bounded
to `1s` through `24h`, and standalone/dev reject the setting. Cluster S3
durability remains fixed at `before-ack`.

The namespace enforces Kubernetes Restricted Pod Security Admission. The
StatefulSet also sets non-root execution, `RuntimeDefault` seccomp, read-only
root filesystem, no privilege escalation, dropped capabilities, probes,
resource bounds, a PVC, preferred hostname anti-affinity, and default-deny ingress/egress.
The `goauthy` PodDisruptionBudget requires two available pods during voluntary
eviction; anti-affinity remains preferred so one-node Kind stays schedulable. The explicit ingress
policy permits port 8080 only from pods in the same namespace; `kubectl
port-forward` is used by the host E2E runner. NetworkPolicy enforcement depends
on the selected CNI, so manifest assertions are not proof of packet filtering.

## Password-reset profile

`E2E_PROFILE=password-reset` selects `deploy/k8s/password-reset`, adds the
throwaway SMTP sink and enables recovery with a mounted 32-byte reset key. It
also sets `GOAUTHY_POW_DIFFICULTY=10` and `GOAUTHY_POW_EXPIRY=30s`; difficulty
10 is test-only bounded work, not a production recommendation. Runtime defaults
outside this overlay are difficulty 19 (accepted range 10--98) and a positive
30-second expiry.

Schema v17 persists only SHA-256 digests for reset PoW challenges and their
single-use consumption attempts. Focused tests use injected clocks/randomness.
Fresh `E2E_PROFILE=password-reset E2E_PORT=28080 make e2e-kind` built schema
v17, readied three pods, passed `test/e2e` in `15.938s` and
`test/e2e/browser` in `1.320s`, including invalid proof denial, success and
cross-pod replay rejection. Email OTP is not deployed or tested by this overlay.

## User-deletion profile

`make e2e-kind-user-delete` is a source-integrated deterministic profile. It
opens registration for ordinary users, exercises self and admin deletion,
denies the deleted user's old session and relogin, checks replay `404` and
final-admin `409`, verifies UID-changing pod replacement and readiness, and
checks persistence after replacement. The live Kind run remains UNVERIFIED:
current Docker `fs.inotify.max_user_instances=128` is below the required
`256`. This profile does not mark overall User deletion or SCIM complete.

## SCIM profile

`make e2e-standalone-scim` uses a deterministic TLS SCIM fixture, a custom CA
via per-provider `ca_file`, and the SMTP sink. The latest prior standalone run
passed in repeated runs (`14.9s` and final post-hardening `18.6s`), covering registration, restart-immediate synchronization,
exact `externalId`, public admin deletion, restart-exact remote `DELETE`, and
login rejection; a rerun is pending. The exact-three-voter Kind harness passes
source/static checks but live execution stops at Docker
`fs.inotify.max_user_instances=128`, below the required `256`; no HA runtime
claim is made. Transport/DNS/TLS/drop failures and `429`/`5xx` retry, while
malformed/permanent `4xx` responses dead-letter. Full SCIM and group E2E remain
unchecked, and delivery is at-least-once across crashes rather than exactly-once.
