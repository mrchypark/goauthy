# Master-key removal gate

The command's local master-key status combines the read-only
`oidc.InspectMasterKeyReferences` and (when passkeys are enabled)
`passkey.Service.InspectEnvelopeReferences` scans. It returns the configured
active master-key ID plus sanitized counts for OIDC signing keys, live DCR
idempotency responses, unexpired upstream transactions, and retained passkey
credentials/ceremonies. Passkey-disabled status has an explicit zero passkey
family. The startup status log contains no envelope, ciphertext, plaintext, or
per-old-key map and never deletes a key; the command-internal status is local
evidence, not a public endpoint.

`safe: true` means every scanned envelope authenticated and every enabled
family refers only to that caller's active ID. With passkeys enabled, old-key
references, legacy CookieKey ciphertext, malformed state, tampering, or an
unknown key keep `safe: false`; inspector errors fail closed. With passkeys
disabled, no passkey rows are probed and the explicit zero family does not
weaken the OIDC gate. Do not remove a key when `safe: false`.

Before removing key A, an operator must also verify every running pod reports
the same active ID, no old deployment can still write with A, DCR and upstream
TTLs have elapsed, and every signing-key retirement window has elapsed. The
scan uses bounded linearizable reads but is not a cluster-wide write barrier;
perform the check only after that rollout and retirement condition is stable.

## Cluster-wide retirement barrier (Stage A complete; Stage B/C pending)

Startup status is local, one-time evidence, not a cluster-wide write barrier:
separate linearizable family scans do not make one atomic cross-family snapshot.
The current startup caller is `cmd/goauthy/main.go:516-519`, while the OIDC
and passkey inspectors explicitly provide local evidence only.
For an exact three-node cluster, the minimum operator-controlled protocol is a
replicated two-phase barrier with states `prepared`, `fenced`, `ready`, and
`aborted`:

1. `prepared` records a monotonic epoch, candidate old key A, replacement B,
   and the exact three expected node IDs (or their membership digest).
2. `fenced` is the replicated commit point. Every compliant envelope-producing
   mutation must reject a writer using A at commit time while allowing B; a
   preflight check alone leaves a TOCTOU race.
3. `ready` requires fresh post-fence attestation from all three nodes, each
   carrying a new process `boot_id`, active key B, and sanitized all-family
   status with zero old/non-active/legacy/tamper references. `aborted` leaves
   keys untouched.

A two-node quorum may commit `fenced`, but a missing or partitioned third node
prevents `ready`; two unavailable nodes prevent linearizable progress. A crash
or restart gets a new `boot_id`, so stale attestations do not count. An old
binary can bypass a new SQL fence; operators must stop or externally fence old
deployments before manual removal. No transition deletes keys automatically:
after `ready`, operators still verify pod IDs and TTL/retirement windows, then
remove A manually.

Rhiza v0.10.0's `DB.Ready`, linearizable `DB.Query`, `DB.Execute`, and
`RequestStatus` supply fixed membership, replicated SQL, quorum-certified
reads, and request-status recovery (see the module's `rhiza.go:230-233` and
`pkg/network/server.go:1021-1041`). GoAuthy now supplies Stage A's
all-member attestation state and operator primitives, but runtime writer
fencing and automatic key-retirement integration remain absent. Schema v48
defines the barrier row plus per-member attestation rows, and the
operator prepare/fence/attestation/ready/abort primitives are implemented and
tested (Stage A). Runtime writer fencing and startup/worker integration (Stages
B/C) remain unimplemented; it is not a completed feature. Deterministic tests must cover
state replay, commit-time A rejection
and B allowance, exact-three fresh-boot attestation, old/legacy/tamper denial,
the passkey-disabled zero family, one-node-down (`fenced` but not `ready`),
two-node partition, crash/stale attestation, `CommitUnknown`/request status,
and the absence of HTTP exposure or automatic deletion.
