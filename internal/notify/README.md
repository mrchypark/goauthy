# notify

## Overview
`notify` coordinates reliable outbound delivery of `eventlog.Event` records to configured Slack, Matrix, and SMTP email targets using a Rhiza-backed lease queue (`RhizaQueue`) with generation-gated configuration reconciliation, exponential backoff, and bounded retention cleanup.

## Interface
- Constants and types: `DefaultBatch`, `DefaultLease`, `MaxBackoff`, `DefaultRetention`, `Target`, `Identity`, `Delivery`, `Sender`, `SenderFactory`, `Runtime`, `Runtime.Maintain`, `Runtime.Step`, `Backoff`, and `HTTPClient` in [notify.go](file:///Users/cypark/Documents/project/goauthy/internal/notify/notify.go#L20-L177).
- Transports: `EmailConfig`, `EmailSender`, `NewEmailSender`, and `EmailSender.Send` in [email.go](file:///Users/cypark/Documents/project/goauthy/internal/notify/email.go#L17-L69); `HTTPFactory` and `HTTPFactory.Sender` in [http.go](file:///Users/cypark/Documents/project/goauthy/internal/notify/http.go#L18-L53).
- Replicated queue: `RhizaQueue`, `NewRhizaQueue`, `RhizaQueue.Targets`, `RhizaQueue.Claim`, `RhizaQueue.Ack`, `RhizaQueue.Cleanup`, and `RhizaQueue.Fail` in [queue.go](file:///Users/cypark/Documents/project/goauthy/internal/notify/queue.go#L18-L221).

## Invariants
- `NewRhizaQueue` requires a positive `generation` and claims `event_notification_config_generation` monotonically in the same Rhiza transaction as target upserts/retirements, preventing stale pods from re-enabling retired targets ([queue.go:NewRhizaQueue](file:///Users/cypark/Documents/project/goauthy/internal/notify/queue.go#L34-L117)).
- `Runtime.Step` clamps `Batch` to 1, bounds each delivery attempt below `min(10s, lease/2)`, allows `eventlog.Test` at any threshold, and records only a fixed `"delivery failed"` error string via `safeError` to avoid persisting remote secrets ([notify.go:Step](file:///Users/cypark/Documents/project/goauthy/internal/notify/notify.go#L85-L170)).
- HTTP transports require `https://` URLs without userinfo and disable redirects (`http.ErrUseLastResponse`); `EmailSender` enforces TLS 1.2+ unless `AllowInsecure` is explicitly set ([notify.go:HTTPClient](file:///Users/cypark/Documents/project/goauthy/internal/notify/notify.go#L172-L185), [email.go:deliver](file:///Users/cypark/Documents/project/goauthy/internal/notify/email.go#L70-L80)).

## Side Effects
- Reads and mutates `event_notification_config_generation`, `event_notification_targets`, and `event_notification_deliveries` in Rhiza.
- Makes outbound HTTPS requests (Slack webhooks, Matrix rooms) and SMTP connections.

## Verification
- Run: `go test ./internal/notify`
