# Standalone GCS mutation pacing

`GOAUTHY_GCS_MUTATION_GATE_ENABLED=true` opts a standalone native-GCS HTTP
process into mutation pacing. It defaults off; enabled configurations must
retain before-ACK durability. Dev, cluster, non-GCS and gRPC modes are rejected.
No dependency upgrade or object format change is involved.

The transport installs once before Rhiza opens clients and is never restored
while clients may be constructed. Existing Thanos transport settings remain.
GET and HEAD bypass the gate. Mutations use three fixed lanes:

- P: the exact configured `archive/PUBLISH_LOCK` object.
- H: the exact configured `archive/head.bin` object.
- O: other unambiguously named multipart uploads within the configured cluster.

The cluster prefix uses `path.Join(objectStorePrefix, clusterID)`, exactly as
Rhiza does. Only POST to the exact GCS JSON upload bucket path, with an
unambiguous `name`, `uploadType=multipart`, valid multipart content type and no
resumable markers, can select a single lane. Foreign, malformed, unsupported
or unnamed mutations acquire **all three lanes**. They are forwarded unchanged,
not rejected. Resumable initiation, chunks, status probes and retries therefore
fence every lane, without session tracking or a capacity limit.

Selected lanes are acquired in fixed P/H/O order. Dispatch waits for their
latest cooldown deadline. On RoundTrip return (response headers or transport
error), every selected lane receives a one-second completion cooldown before
permits are released. Thus named -> unknown -> named writes to the same object
retain spacing even when the request shape changes. Canceled requests waiting
for admission/cooldown close their bodies, release acquired permits and do not
change cooldowns or reach the network. Inflight cancellation is handled by the
underlying transport. CAS conditions, payloads, responses, errors and SDK retry
policy are unchanged; the gate adds no retries.

State is constant: three permits and deadlines, no object/session maps,
eviction or background callbacks. This is process-local pacing for the
supported standalone deployment, not distributed coordination. A previous
process's cooldown is not persisted across restart.

For zero-latency acquire-lock -> new extent -> head -> release-lock, artificial
waiting falls from three seconds with the original single gate to one second:
only the publication lock repeats. Different known objects can run concurrently.
Other named objects still share O; unknown/resumable traffic remains globally
conservative and can cause convoying. No fairness or latency SLO is claimed.

Rhiza retains its five-second lease-release budget. Unrelated known multipart
extent/head writes no longer impose a global cooldown on release, but unknown
requests or slow storage can still consume its budget. Startup/checkpoint and
graceful-termination timing must be measured before rollout.

Compare the same bounded login/due-session workload, GCS RESOURCE_EXHAUSTED,
SDK retry counts and archive phase durations. Preserve bucket/prefix, identity,
keys, grants and before-ACK durability. Keep timed-out mutations unknown until
reconciled. Separately verify session/JWKS/grant continuity after authorized
normal replacement; no production recovery or performance guarantee is implied
by the synthetic gate tests.
