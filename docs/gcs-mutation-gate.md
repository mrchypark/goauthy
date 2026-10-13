# Standalone GCS mutation pacing

`GOAUTHY_GCS_MUTATION_GATE_ENABLED=true` opts a standalone native-GCS HTTP
process into one shared mutation gate. It defaults off; enabled configurations
must retain before-ACK durability. Dev, cluster, non-GCS and gRPC modes are
rejected. No dependency upgrade or object format change is involved.

The gate installs once before Rhiza opens its clients. It preserves the Thanos
HTTP transport settings and wraps all methods except GET and HEAD. At most one
mutation attempt runs at a time, followed by a one-second cooldown after
RoundTrip returns (response headers or transport error). This includes SDK
retries and resumable upload requests. Canceled requests waiting for admission
or cooldown close their bodies without reaching the underlying transport.
Generation preconditions, bodies, responses, errors and SDK retry policy are
unchanged. Cancellation after dispatch belongs to the underlying transport.

This is deliberately conservative: immutable uploads, checkpoint writes and
cleanup mutations also serialize. The gate has constant state, no object map,
and no distributed coordination. It is suitable only for the supported
standalone process, not a guarantee against other bucket writers. A previous
process's cooldown is not persisted across restart.

Three zero-latency sequential mutation attempts require at least two seconds;
sustained attempts cannot exceed one per second and network time adds to that.
A publication generally needs lock acquisition, extent upload, head publication
and lock release. A release has Rhiza's existing five-second budget; one
uncontended cooldown fits, but concurrent writers or slow requests can consume
that budget. No fairness, latency SLO or guaranteed shutdown duration is claimed.

Before rollout, measure login/device latency, startup migrations, checkpoint
completion and graceful termination. Preserve the bucket/prefix, identity,
keys and before-ACK contract. Compare GCS RESOURCE_EXHAUSTED counts, SDK retries
and archive phase timings using the same bounded workload. Keep timed-out
mutations unknown until reconciled; do not blindly replay non-idempotent work.
