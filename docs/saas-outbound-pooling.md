# SaaS outbound connection reuse

`internal/saas/http_pool.go` uses private, explicitly HTTP/1 stdlib transports.
It does not use the default transport, proxies, custom TLS dialing, verification
callbacks, alternate protocols, or an application retry loop. TLS verification,
TLS 1.2 minimum, compression suppression, 8 KiB response-header limits, and
redirect rejection remain in force.

## Ownership and admission

Registered OAuth adapters borrow the `ProviderStore` owner. Registered API-key
connectors borrow the `CredentialStore` owner. Reconstructing an adapter does
not lose its pool, and metadata-only construction creates no pool entries.
Direct adapters have private owners; GitHub shares its OAuth adapter's client.
Entries retain transport policy and accounting, not adapters, secrets, user
credentials, or caller authority closures.

The key is owner scope, provider ID/revision, and canonical HTTPS hostname/port.
Each owner has one immutable TLS policy; test roots are isolated by owner.
Host overrides must identify the same canonical origin. The URL keeps its logical
hostname; only the TCP dial uses a validated literal address. Different provider
IDs, revisions, origins, ports, or owners cannot share connections merely because
DNS resolves them to the same IP.

Registered dispatch checks the provider's current revision, kind, enabled and
deleted state with a linearizable read, including on cache misses and identity
requests following token exchange. Read errors fail closed. API-key provenance
is checked with the credential-loading policy; a matching configuration digest
does not let a direct or stale connector dispatch a registered credential.
Existing caller/collection/generation/version/claim and post-call checks remain.

Limits per owner:

| Resource | Limit |
| --- | --- |
| Charged entries, including provisional and retiring generations | 32 |
| Request leases per entry, from preflight through body completion | 4 |
| Connections per canonical transport authority | 4 |
| Idle connections per entry | 2 |
| Idle timeout | 30 seconds |
| Maximum age for new reuse admission | 5 minutes |
| Whole HTTP operation, including body consumption | 15 seconds |

Admission rejects excess work instead of creating an overflow transport or an
unbounded wait queue. A per-entry, context-cancellable gate serializes policy/DNS
validation. The owner mutex is not held during DNS or database work. Quiescent
entries can be evicted; 32 is not a lifetime origin quota.

## DNS, retirement and deadlines

Every logical request validates the entire DNS answer before reuse; every new
TCP connection validates it again. Empty answers, resolution errors (including
errors accompanied by addresses), and mixed safe/unsafe answers are rejected.
Addresses are unmapped, copied, sorted and deduplicated; order changes alone do
not invalidate a pool.

A changed preflight address set retires the old generation and allows one fresh
selection before HTTP delegation. A change found inside a dial retires that
generation and fails the operation. TCP failures can try another address from
that validated set, with a bounded share of the remaining deadline. TLS errors,
HTTP errors and response errors never trigger application fallback/retry.

Entry identity and terminal retirement fence late DNS/dial completions. Entries
remain charged until leases, dials and tracked raw connections are all gone.
`CloseIdleConnections` assists retirement but is not its state or completion
proof. Thin connection wrappers account for closure; stdlib still selects and
reuses sockets. There are no per-connection age timers or custom socket pools.

Go detaches connection establishment from request cancellation. Dial contexts
therefore carry an independent absolute deadline, and raw socket deadlines bound
the subsequent stdlib TLS handshake too. `GotConn` clears that socket deadline
only for the exact verified connection acquired for a live operation. TLS's
close-notify write deadline cannot extend the operation budget or delay idle
retirement. Body EOF, Close, errors and cancellation release leases exactly once;
an abandoned body is closed at cancellation/deadline. Preflight rejection closes
the request body without dispatching it.

Successful local provider update/delete invalidates both store owners. The
application wires `ProviderStore.OnPolicyChange` to
`CredentialStore.InvalidateProviderConnections`; embedders with both stores must
do likewise. Observing a newer revision retires older origins in that owner;
monotonic revisions prevent an older observation from retiring a newer one.
Deleted provider IDs cannot be recreated by the provider API. Remote changes are
detected at dispatch, not through a new watcher.

These are admission guarantees, not an atomic transaction between policy reads
and remote network effects. Already admitted operations may finish. New DNS
observations can disagree legitimately: failing a changed dial, or saturation
after a refresh claim, can require reconnect. Neither error resets a refreshing
claim to ready or authorizes replay.

## Replay and shutdown contracts

The final delegated request clone has `GetBody=nil`. The real nonempty OAuth code
exchange/refresh POSTs and GitHub revoke DELETE cannot be rewound by the inspected
HTTP/1 retry path. Explicit OAuth authentication style still prevents the OAuth
library's authentication-style probing retry. The caller's request is unchanged.
Read-only GET recovery inside stdlib is permitted within the same admitted
logical operation; this is not a claim of one physical attempt for every GET.

The application drains inbound HTTP work before sealing outbound owners. Request
contexts survive the initial shutdown signal, allowing token/identity/commit
sequences to drain during the existing 10-second server shutdown window. It then
forces cancellation/closure and allows six seconds for handlers to finish cleanup
while storage remains open. If handlers ignore cancellation beyond that allowance,
the application reports an error and does not close Rhiza underneath them. Direct
adapter/store owners expose idempotent `CloseConnections` for other embedders.

## Validation and measurement

Validated toolchain: `go version go1.27.0 darwin/arm64`, Apple M1, 2026-09-28.
The retry/deadline assumptions were checked against the installed `net/http`
transport, request replay predicate, TLS close/handshake code, and OAuth2 v0.36.0
token-request construction. Re-run the adversarial tests on toolchain upgrades.

`http_pool_test.go` and `http_provider_test.go` exercise the real wrapper, raw TCP
and stdlib TLS. Coverage includes reconstructed registered adapters, provider/
origin/owner isolation, credentials changing between requests, stale adapters after
eviction, remote revisions, cross-owner local invalidation, DNS rebinding/races,
preflight/body/entry bounds, late dial retirement, stalled TLS/body deadlines,
redirect/certificate/proxy/alternate-TLS rejection, and actual mutation callers
under zero-byte write, partial write and lost-response failures. Existing refresh
uncertainty tests also run through the public loader with the real wrapper.

Reproduce the local comparison with:

```sh
go test ./internal/saas -run '^$' -bench '^BenchmarkSaaSRegisteredRefreshPool' -benchtime=100x -count=3 -benchmem
```

The baseline reproduces the previous one-DNS-lookup, first-address, new
non-keepalive-transport policy. Both paths reconstruct registered OAuth adapters
and use the local database and TLS fixture. Concurrent runs use waves of four.
DNS counts are resolver calls, TCP counts are successful connects, and TLS counts
are server-observed ClientHello starts. Resource cleanup is outside the timing
window and completes before reporting counters. Speculative connects may be
closed without completing TLS. These are local fixture measurements, not external
DNS timing, production latency percentiles or deployment capacity qualification.

Observed results (three 100-operation runs, timing shown as median):

| Workload | Previous policy | Pooled |
| --- | --- | --- |
| Sequential time/op | 2.000 ms | 0.235 ms (range 0.226–0.841 ms) |
| Sequential allocations/op | 1305 | 541 |
| Sequential DNS/TCP/TLS counts per 100 operations | 100 / 100 / 100 | 101 / 1 / 1 |
| Four-way time/op | 0.750 ms | 0.170 ms |
| Four-way DNS counts per 100 operations | 100 | 110–113 |
| Four-way TCP/TLS counts per 100 operations | 100 / 100 | 10–13 / 10–12 |

The retained per-operation DNS check is intentional: this optimization reduces
connection/handshake work, not DNS validation. Shared-host scheduling and
speculative connection acquisition make timing and concurrent counts variable.
