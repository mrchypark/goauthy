# Event notifications

The server now starts a context-owned notification worker when
`GOAUTHY_EVENT_NOTIFICATION_TARGETS` names one or more whitespace-separated
targets: `email slack matrix`. No targets means no worker and no destination
configuration writes. Shutdown cancels and joins the worker.

| Target | Configuration | Reused implementation |
|---|---|---|
| email | `GOAUTHY_EVENT_EMAIL_TO` plus existing `GOAUTHY_SMTP_*` settings | shared SMTP environment parser; existing `go-mail` MIME/TLS client |
| slack | `GOAUTHY_EVENT_SLACK_WEBHOOK` | stdlib HTTPS/JSON incoming webhook |
| matrix | `GOAUTHY_EVENT_MATRIX_HOMESERVER`, `GOAUTHY_EVENT_MATRIX_ROOM`, `GOAUTHY_EVENT_MATRIX_ACCESS_TOKEN` | stdlib HTTPS/JSON room-message PUT; stable event ID as transaction ID |

Each target has `GOAUTHY_EVENT_NOTIFICATION_<KIND>_LEVEL`:
info, notice, warning (default), or critical. The guarded Test event bypasses
the threshold, matching pinned Rauthy v0.36.2
[`notifier.rs`](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/notifier.rs).
HTTP endpoints require HTTPS; redirects are refused even with an injected
HTTP client. SMTP defaults to mandatory TLS; insecure mode is explicit.
Destination URLs, tokens and remote response bodies are not persisted in errors.

Schema v62 snapshots event payloads into Rhiza per-destination delivery rows.
Destination identities are full SHA-256 hashes of kind and destination, not
raw webhook secrets. A newly configured destination never receives historical
events. Local workers only select their own configured destination identities;
one node does not globally disable another node's destinations.

The worker reuses Rhiza atomic leases, lease-token acknowledgements and retry
timestamps. `Runtime.Step(ctx, now)` supports fixed-clock tests. Retries back
off from one second to 24 hours; normal delivery is at-least-once, not exactly
once. A crash after external acceptance but before acknowledgement can duplicate
Slack/email delivery. Matrix reuses its event transaction ID.
Each step claims one event per target and bounds the external call below its
one-minute lease. This intentionally bounded first implementation has a normal
throughput ceiling of roughly one event per target per second; it is not a
high-volume notification processor.

Verification:

- Actual Rhiza concurrent claim, stale acknowledgement, source-log retention,
  close/reopen and retry equality tests.
- TLS-local Slack/Matrix protocol tests, untrusted certificate/redirect
  rejection, SMTP MIME and redacted errors.
- Fixed-clock runtime threshold, retry-before/equality, concurrent worker and
  cancellation tests: `/tmp/goauthy-wide-batch-notify-race-20260906.log`
  (notify 36.948s, command configuration 2.199s, exit 0).
- Standalone server: guarded Test event on every configured URL reaches the
  local SMTP sink by exact event ID and recipient. Combined browser/HTTP/claims/
  email batch: `/tmp/goauthy-wide-batch-standalone-20260906.log`, exit 0.
- Current HA/Pod-replacement result is recorded in [status](status.md), rather
  than inferred from the queue tests.

Remaining: removed-target retirement, delivered/orphan-row retention, destination
configuration-change policy across nodes, delivery metrics, full upstream event
emitter/configuration parity and deployed Slack/Matrix TLS-fixture E2E. Removed
destinations currently remain enabled in Rhiza and accumulate snapshots; this
operational gap prevents marking the complete notifications feature done.
