# Review disposition and retained limits

This review's runtime campaign is representative endpoint evidence, not a
complete performance qualification. It measured authorization-code token
exchange, UserInfo, refresh grant, and direct Argon2 verification using
synthetic local fixtures. It did not measure SaaS provider calls,
back-channel logout throughput, browser login/session validation, expired-token
cleanup backlog, multi-node traffic, or deployment/HA stress. The reported
latency is descriptive under uncontrolled host load; see [the measurement
report](README.md).

The following existing contracts and limits remain deliberate and unchanged:

## SaaS preflight failures remain uncertain and fail closed

`CredentialStore.CallAPIKey` performs its current credential/provider
preflight before calling the connector. A preflight error returns immediately,
so no provider request is sent from that failed attempt; unclassified errors
remain `error_class=unknown` rather than being treated as an absent credential
or an invitation to retry. The same no-send rule applies to OAuth refresh when
the durable pre-send claim cannot be confirmed, including an unknown Rhiza
commit outcome. See [`api_key_call.go`](../../../internal/saas/api_key_call.go#L13),
[`connection-use-grants.md`](../../connection-use-grants.md#L61), and
[`TestSaaSPoolProviderReadErrorFailsClosed`](../../../internal/saas/http_provider_test.go#L396).

## Connector-bound API-key rotation requires the same consent binding

The legacy `PutAPIKey` rotation path rejects a connector-bound credential.
Rotation through `PutBoundAPIKey` is accepted only when the registered enabled
connector and its current consent digest match. This preserves the consent
contract across rotation; it is not a general prohibition on same-binding
rotation. See [`api_key_store.go`](../../../internal/saas/api_key_store.go#L72)
and [`TestBoundAPIKeyConsentAndCustodyRotation`](../../../internal/saas/api_key_binding_test.go#L11).

## Back-channel delivery remains one record per worker step

`Worker.Step` claims at most one due delivery (`LIMIT 1`), and `Worker.Run`
invokes a step immediately and then on its configured ticker. Production
configuration uses a tick interval bounded from one to five seconds. This
bounded drain behavior is retained; no back-channel throughput or queue-drain
capacity measurement was part of the HTTP campaign. The one-record limit is
per worker step, not a claim about aggregate throughput across multiple nodes.
See [`worker.go`](../../../internal/backchannel/worker.go#L35),
[`worker.go`](../../../internal/backchannel/worker.go#L106),
[`worker.go`](../../../internal/backchannel/worker.go#L137), and
[`main.go`](../../../cmd/goauthy/main.go#L2480).

No global cache, broader endpoint benchmark, or deployment/HA stress claim is
introduced by this report.
