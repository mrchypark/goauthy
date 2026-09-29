# Frozen standalone #113 measurement protocol

Base: 510b94d547e9112152d4f50272e71899f5734d9d. Measurement only; no production
admission, configuration, schema or dependency changes. Exact-three is blocked
by the previously established lack of a permitted shared conditional-write
object store. No infrastructure probe/redeployment is part of this tranche.
#113 remains open; these thresholds are not production SLOs.

The exact-three topology is not runnable with this fixture. It opens one local
Rhiza database and creates its HTTP servers inside a single test process; three
copies would create three independent databases, not three application members
sharing conditional writes. Once an approved store and a Rhiza-supported
three-member runtime are available, reuse this manifest, arrival schedule,
handler-level flow oracles and offline comparisons through a separate tagged
setup adapter that starts the real members against that store. First verify
shared conditional refresh claims and identity/session behavior across members.
Do not count three standalone runs as topology coverage or derive a production
budget from this manifest.

One excluded pilot completed in 93.72 seconds. Then exactly three fresh
non-race/non-coverage test executable processes use the adjacent manifest.
Each has a 125-second test deadline, bounding pilot plus primary process budgets
to 500 seconds plus process startup, below 600 seconds. No rerun to erase failed
or inconclusive primary results. Evidence ceiling: 256 MiB, individual result
ceiling 8 MiB. Correctness preflights are separately recorded, not load samples.

The manifest freezes 16s healthy baseline, 16s mixed, 50s recovery. One IAM
arrival/second rotates four identities/peers with unchanged DefaultPolicy
(19 MiB, t=2, p=1, four KDF slots, 100ms wait, memory gate off); login policy is
on (20 attempts/minute/peer). Every flow starts without a cookie, GETs interaction
and CSRF, POSTs the real password, then verifies rotated session/subject.
One arrival/second per SaaS route: oauth-healthy, oauth-header, oauth-cancel,
api-healthy, api-body, api-dial. Recovery offers only IAM and the two healthy
routes for 12s, then allows 38s of natural drain/idle expiry. No pending queue,
catch-up dispatch or retry. Generator allocations are 12 OAuth fault + 12 API
fault + 4 OAuth healthy + 4 API healthy, and four separate IAM slots. They are
not server admission. Reservations last until actual handler completion, even
if the client cancels; an unobserved handler triggers abort without releasing
its reservation. Every expired scheduled slot stays in the denominator.

Inventory: baseline and mixed each have 16 distinct bindings per route; recovery
has 12 untouched bindings for each healthy route; one control binding per route.
Total 222 bindings. No state/version reset. Providers, revisions, origins and
response shape stay fixed across phases. All measured refreshes use expected
old version 1. API-key keys and OAuth credentials are synthetic, held only in
memory and encrypted fixture storage; published counters use separate synthetic
IDs. Pilot credentials used synthetic IDs directly; the primary fixture uses
random opaque secrets mapped to IDs, without changing production code.

Faults: OAuth header stall occurs during identity GET after a successful token
POST; API body stall flushes headers and a partial JSON body; API dial fault
uses a closed local TCP listener address and the route always sends Connection:
close while healthy, so its mixed dispatch cannot use a baseline idle socket;
OAuth cancellation occurs only after the provider has accepted its token POST.
Request deadline: 3s. Refresh cleanup retains its production detached 5s budget.
No fixture RoundTripper, insecure TLS, public-egress fallback or permissive
measured authorizer. DNS and raw TCP mapping plus private test roots are the
only outbound injections; both owners reject unmapped DNS and TCP destinations.

Actual login/RBAC handlers share one Rhiza DB with both SaaS stores. API invoke
uses a real managed-client code/PKCE bearer token and production
AuthorizeConnectionUse; refresh uses the actual browser session/CSRF boundary.
Setup uses a subject-existence seed guard, outside measured traffic. The local
HTTPS app wrapper injects four fixed test peer addresses into the real runtime
peer middleware; no such header is trusted by normal binaries. This selected
composition does not claim to execute every startup worker/middleware in run().

Before phases: incorrect password/CSRF/bearer rejection; positive login, refresh
and API invocation; revoked grant no-dispatch; old-version no-replay; concurrent
same-binding single mutation. A separate deterministic test holds a handler
after client cancellation and proves its reservation remains charged.

Experimental acceptance, fixed before primary sampling:

- Zero unauthorized release, repeated token mutation per old version, accepted
  negative control or wrong successful session binding.
- Every baseline arrival and every protected IAM/healthy arrival launches and
  succeeds. Policy failures or generator drops invalidate baseline rate; fault
  errors remain separate from capacity/overload errors.
- For each protected route separately within a process, mixed and recovery
  P95 <= max(1.25 * baseline P95, baseline P95 + 25ms), P99 <=
  max(1.5 * baseline P99, baseline P99 + 50ms). Use individual complete-flow
  samples, report all outcomes and n; n=16/12 makes P95/P99 extreme statistics.
- Resource abort ceilings: RSS 314474496 bytes; heap 124526000 bytes; 390
  goroutines. Derived from twice pilot healthy peaks (157237248 RSS, 62263000
  heap) and pilot healthy 134 goroutines +256. Host has 16 GiB RAM. These are
  investigation abort limits, not leak proofs/defaults.
- By recovery end: workflows, leases, dials and tracked connections drain,
  following 30s idle timeout plus slack after the last probes. Reusable entry
  count need not reach zero. No GC forcing, restart or CloseConnections before
  freezing observations. Cleanup/shutdown follows afterward.

All request outcomes, scheduled/actual dispatch times, client/handler completion
and pool snapshots are retained. Synchronised snapshots report existing leases,
dials, connections and active/retiring entries; no invented waiters or idle
counts. Sample interval 100ms; sampled peaks are lower bounds on instantaneous
peaks. RSS is RUSAGE_SELF historical high-water, not instantaneous RSS. CPU,
heap and goroutines include colocated app, generator and TLS provider. Counter
locks, timer reads, request/body parsing and the sampler remain in the process;
JSON evidence encoding and final durable inspection occur outside phase timers.
The primary fixture also refines client/dispatch timestamp placement after the
excluded pilot; it does not subtract any instrumentation cost.

One noisy latency breach is inconclusive; repeatable breaches warrant review,
not automatic admission. Even three clean runs qualify only this standalone
workload. No 32-entry saturation, five-minute pool age, exact-three, external
provider service cost, production tails or cluster-wide admission claim.
