# Master-key retirement and removal

Master-key retirement is integrated with envelope writes, passkey passwordless
cookies, per-member attestation, and scheduled cleanup. A local status scan is
evidence for one process only; it does not replace the replicated fence,
retention deadline, reference inspection, or archival acknowledgment.

## Passwordless-cookie retention ledger

Schema v112 adds the private `passkey_cookie_key_retention` table. It stores a
monotonic maximum `max_ttl_ns` for each master-key ID that has sealed a
passwordless cookie. The v111-to-v112 migration adds this table and the schema
marker without rewriting existing application data or changing user-account
fields. The migration is idempotent and recovers an unknown commit by retrying
its stable request.

For each new cookie, GoAuthy fixes the cookie expiry, seals the cookie, and
reads the master-key ID from that exact envelope. It durably registers the
configured cookie TTL for that key before returning the cookie. The upsert
only raises the recorded maximum. A process may cache a successful registration
for a key, but it still performs a fresh linearizable writer-fence check on
every cookie issuance, after fixing the expiry. A registration or fence-read
error—including an unknown write outcome—fails closed: no cookie is returned.
The cache records successful TTL registration; it is not issuance permission.

## Retirement and automatic cleanup

The retirement worker runs on each member. After a replicated `fenced` state,
each process must use the replacement key and wait for the cookie-retention
window. It then inspects its local envelopes and submits fresh attestation
identified by its process boot ID. The replicated barrier becomes `ready`
only after the expected members attest with no old-key, non-active, legacy,
malformed, or tampered references. Read and attestation errors do not count as
clean evidence. Before fencing, stop or externally fence any older binaries
that do not enforce the replicated writer check.

The effective cookie-retention duration is the maximum of the supported
90-day default, the current configured TTL, and the durable per-key historical
TTL. Cleanup also honors the separate 24-hour retirement overlap. For the
current generation, the cookie deadline is measured from `fenced_at`; for an
older generation whose fence is no longer the singleton barrier, cleanup uses
the later `ready_at` as a conservative base. Disabling passkeys or reducing the
current TTL does not shorten a recorded per-key maximum or the 90-day floor.

The hourly `key-removal` housekeeping job processes completed generations. It
waits for the applicable retention and overlap deadlines, obtains a fresh
archival acknowledgment for that generation, and then calls `Keyring.RemoveKey`.
Read failures, malformed ledger data, missing fence times, failed archival
acknowledgments, and failed file removal stop that cleanup attempt and leave it
retryable. The worker does not delete a key merely because the barrier says
`ready`.

`Keyring.RemoveKey` removes the retired key from the process keyring and
unlinks its file from the configured key directory. This distinction matters
for read-only key mounts. The Kubernetes StatefulSet example mounts its Secret
key directory read-only. While a retired key file remains in that mount,
`os.Remove` fails; the cleanup job reports an error and the key remains loaded
in memory. The process cannot rewrite or prune the Kubernetes Secret. On a
writable key directory, the worker can remove both the file and the in-memory
key after all retirement checks pass. With a read-only Secret source, operators
must keep the Secret entry until the retention, reference, readiness, and
archival conditions are satisfied, then remove that entry from the source and
roll the pods so they load the intended key set. Do not interpret a cleanup
error on a read-only mount as successful key removal.

## Legacy history and operator limits

The ledger has no backfilled TTL for keys that predate schema v112. For
official application builds using the historical default, a missing ledger row
is covered by the 90-day default floor. The migration cannot infer a longer
cookie lifetime used by a custom fork before the ledger existed. Such operators
must establish that fork's actual maximum TTL and keep the old key under
operator control until that full historical window has elapsed; the 90-day
fallback is not a guarantee for unknown custom-fork history. Establish and
wait out that bound before beginning retirement for the affected key. Without
that operator hold, the worker has no evidence to extend its 90-day fallback
and may remove the key before a longer-lived custom-fork cookie expires.

The durable read and write paths are fail-closed, but the ledger cannot recover
history that was never recorded. A successful database migration is not
evidence that a custom fork's prior TTL was 90 days or less. The new policy
changes retention metadata only; it does not add or modify user-account fields.
