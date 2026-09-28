# #112 access/refresh serialization reuse experiment

**Decision: stop this candidate and retain production formats and behavior.**
The owned-snapshot/equality work removes no repeatable cost advantage and raises
allocation in every paired sample. No production reuse, overlay of production
writers, endpoint A/B benchmark, compact PKCE, BLOB conversion, migration or
dependency change follows this stop decision. Issue #112 remains open.

Base: `b7893d6413c1321ff127427f9c3e192e06e53553`. Full supplied Pro design read;
source assertions checked against local GoAuthy, Fosite v0.49.0 and Rhiza v0.12.3.
Go 1.27.0 darwin/arm64, Apple M1, GOMAXPROCS=4. All inputs synthetic.

## Verified source contract

Fosite `handler/oauth2/flow_authorize_code_token.go:126-174` reloads the code
session, validates it, grants scopes/audiences, generates both token values,
begins the transaction, and invalidates the code before calling the two writers.
Both writers receive separate `requester.Sanitize([]string{})` results. Fosite
`request.go:164` copies the request shallowly and creates a filtered form map;
session and other state are not thereby immutable. Default allowed form fields
are grant_type, response_type, scope and client_id.

GoAuthy `grant_storage.go:567-592` persists ID, client ID, requested time in
milliseconds, requested/granted scopes and audiences, the finally filtered form,
three token expirations, username, subject, Extra, and managed/ephemeral
metadata. The descriptor-free, managed and ephemeral branches differ. Form
multivalues are copied; `Extra` is not copied by the production projection.
Managed descriptor fields are ID/revision/generation/enabled/confidential,
redirect URIs, scopes, default scopes and grant types. Ephemeral fields are
ID/name/redirect URIs/scopes/allowed resources/resource-presence flag.

`CreateAccessTokenSession` (`grant_storage.go:976-1290`) encodes first, then builds
scope/audience indexes, guards, cleanup, last-used and logout-association SQL.
For the code transaction, `mutate` only appends statements. The intervening
code branch does not call setters on the persisted request/session projection.
`accessResourceAudiences` reads audience/Extra values and constructs an index
list; it does not update the persisted request audience. Managed, principal,
DPoP and OIDC guards remain required. Refresh storage (`1373-1440`) performs its
prechecks and independently encodes before staging guarded cleanup/INSERT.
Expiry/token generation occurs before this consecutive writer pair in Fosite;
this is not the separately capped, differently sanitized code/PKCE issue pair.

The actual-writer test calls those production writers in a transaction that
**stages but does not submit SQL**, for static/managed/ephemeral clients. It
compares the persisted projection before/between/after the calls and compares
the candidate bytes against the actual access and refresh INSERT arguments.
That validates the fixture's local equivalence, not universal request immutability
or a complete candidate HTTP/commit path. No SQL, ID, guard, current-authority
lookup or decoder is rewritten. SQL consumers of JSON managed/ephemeral fields
and OIDC session IDs, the attempt-specific consumption proof, and exact-request
uncertainty recovery remain intact in production.

## One test-only candidate and oracle

`snapshotReusePair` is created for exactly one two-call experiment, never put in
Store, a registry or a shared cache. On the first call it runs the actual encoder
and unmarshals the successful bytes into an owned typed requestRecord. This
avoids aliasing mutable Extra, forms and metadata. On the second call it rebuilds
the complete typed projection, including the production copies/filter, and
compares it to the owned record. Only equality can reuse the first string;
otherwise it calls the normal encoder. Third calls always use the normal encoder.
Errors on the first call do not create a reusable entry. A failed ownership copy
also cannot change the successful encoder return into an error.

`reflect.DeepEqual` alone is insufficient: -0 and +0 compare equal but produce
different JSON bytes. The candidate therefore also marshals and compares Extra's
representation, with the first-side ownership representation and both costs
included. JSON normalization can cause conservative misses (for example int64
versus decoded float64); no hit is inferred from request/session pointers.
The tested unchanged JSON-compatible fixture qualifies for reuse. Unsupported
session and unencodable Extra return the production byte/error result.

The oracle checks exact strings, error concrete types and error text, outside
all timed regions. Mutations cover all 14 record fields (both descriptor branches
included), all nine managed fields and six ephemeral fields, each of three
expirations, nested Extra, signed zero, number-type changes, nil/empty Extra/forms,
retained multivalues, changed transient values and unsupported sessions. The
record-field inventory is asserted so additions require revisiting the experiment.
A separate explicit 20-name sensitive-input list is independent of the production
filter map/constants, checks both calls, and checks form nonmutation.

Two test-file-only overlay negative controls were observed to fail:

- Bypass the full projection equality: changed request/client IDs return stale
  bytes; byte oracle fails (1.125s).
- Bypass Extra's representation equality: signed-zero mutation returns stale
  bytes; byte oracle fails (0.952s).

These are expected failures, not passing tests. No production source or Rhiza
file was overlaid or modified. An early oracle pilot had an incompletely
constructed ephemeral fixture and panicked; it was corrected to use the real
constructor before any performance sample. Its log is preserved, not counted
as a successful experiment.

## Paired fresh-process comparison

Five cases only: small/medium/large static, medium managed and medium ephemeral.
The existing 2/8/32-scope, 256/2048/16384-claim-byte and 256/2048/8192-form-byte
shapes are reused, with a small nested Extra fixture and expirations for all
three token types. Client categories concern **encoding metadata**, not removal
of their different authority/decode work. Both calls include the Fosite sanitation
cost. Baseline encodes twice; candidate includes first encoding, ownership
unmarshal, Extra representation work, second projection copies, full comparison
and fallback if needed. There is no oracle/instrumentation serialization inside
the benchmark's two calls.

Three fresh process pairs per case, 10,000 timed serialization pairs/process:
30 processes, 300,000 timed pairs. Order is baseline/candidate, candidate/baseline,
baseline/candidate. Each process has a 30-second timeout; no databases, archive
or network workloads are started by these benchmarks. No Cartesian expansion,
rerun selection or discarded slow sample. Other laptop work was active; raw load
snapshot retained. Results are per-process benchmark means, not request tails.

| Case | Paired elapsed deltas, candidate minus baseline (µs/pair) | Additional B/pair (range) | Allocs/pair baseline → candidate |
|---|---|---:|---:|
| small static | +9.878, +10.942, +6.855 | 4,617–4,626 | 71 → 152 |
| medium static | +16.940, -3.765, +8.424 | 8,675–8,682 | 71 → 168 |
| large static | +56.675, +58.442, +57.515 | 43,135–43,176 | 71 → 220 |
| medium managed | +15.171, -2.857, +15.701 | 8,909–8,922 | 81 → 184 |
| medium ephemeral | +18.678, +18.564, +15.336 | 8,867–8,881 | 79 → 181 |

The two negative deltas coincide with slow medium baseline samples; they do not
justify selecting favorable runs or claiming improvement. Large static baseline
means were 57.071–59.075 µs/pair versus 114.586–116.499 µs candidate. Small static
was 8.595–9.289 versus 16.144–19.537 µs. All absolute means are in `samples.tsv`;
`pairs.json` preserves the paired differences.

`/usr/bin/time -l` supplies whole-process user/system CPU and peak RSS. Dividing
CPU by the 10,000 timed pairs gives the following **amortized process** µs/pair,
including fixture setup/runtime overhead and rounded process counters:

| Case | Baseline CPU range | Candidate CPU range |
|---|---:|---:|
| small static | 14–19 | 25–32 |
| medium static | 29–59 | 54–72 |
| large static | 94–97 | 170–174 |
| medium managed | 35–53 | 52–53 |
| medium ephemeral | 28–37 | 53–64 |

These are not isolated method CPU times or total HTTP-flow costs. Elapsed
benchmark means and process CPU are distinct quantities. Peak process RSS was
approximately 47.5–49.6 MB, not allocation per pair. Absolute allocated bytes and
allocation counts come from the Go benchmark, not RSS differences.

## Stop decision and remaining gates

The candidate fails the predeclared copy/check-cost gate. Keeping the owned
projection safe is more expensive here than encoding twice. It is rejected;
there is no reason to add transaction plumbing or a mutable cache to run an
endpoint experiment for this candidate. This does not prove every possible
future no-format-change optimization loses. It rules out the one bounded
candidate measured here, with no optimistic saving extrapolation.

**No actual-redemption A/B timing was run after the stop.** Therefore no absolute
endpoint CPU/latency reduction is claimed. The actual-writer dry run is not
presented as HTTP, authority-I/O, commit or recovery equivalence. Likewise no
candidate concurrency/uncertainty/authority matrix is certified: a future viable
candidate still needs all Pro gates, including errors with nonnil requester,
post-lookup authority/MFA changes, DPoP reload, wrong-verifier and later-failure
retry, winning attempt/consumption state and legacy/ephemeral behavior. Baseline
regression runs below preserve relevant evidence but do not substitute for that
future candidate validation.

Exact-byte reuse would preserve both durable JSON values and provide **no
payload-size benefit**. There is no measured or inferred reduction in database,
qlog, replicated wire, archive or backup bytes. Production formats/schema remain
unchanged. Actual wire replication and isolated recovery-phase CPU/allocation
remain the explicitly open #112 baseline gaps. Actual old-binary upgrade and
format-migration tests remain future gates only if representation changes.

## Reproduce and evidence

```sh
GOMAXPROCS=4 go test -c -o /tmp/oauth112-reuse.test ./internal/oauth
# Three fresh paired invocations per case; reverse order in the second pair.
GOMAXPROCS=4 SNAPSHOT112_REUSE_CASE=small-static SNAPSHOT112_REUSE_MODE=baseline \
 /usr/bin/time -l /tmp/oauth112-reuse.test -test.run '^$' \
 -test.bench '^BenchmarkSnapshotReusePair$' -test.benchmem \
 -test.benchtime=10000x -test.count=1 -test.timeout=30s
# Repeat with MODE=candidate; cases: small-static, medium-static, large-static,
# medium-managed, medium-ephemeral. Preserve stdout and time stderr separately.
```

`raw-evidence.tar.gz` retains all 30 logs and process resource outputs, source/base
provenance, oracle/negative-control/race logs and the temporary negative overlays.
`SHA256SUMS` covers the archive and derived tables. The final additive sensitive
inventory test was added after timing; candidate/benchmark bodies are unchanged.
Both measured and final source hashes are retained. No production edits or
external deployments; local commit only, pending independent review and Pro.

## Validation results

- Final candidate byte/error/ownership, actual-writer and explicit sensitive-set
  oracles: **race, count=3 PASS, 2.268s** (45 tests/subtests per repetition).
- Candidate oracles plus baseline filtering, legacy-shaped decode, DPoP
  destination hydration, wrong-verifier retry/refresh, concurrent code use,
  managed revision/generation fences and post-claim Device MFA change:
  **race PASS, 14.412s**. This run preceded the additive sensitive-set test.
- Both negative controls failed on stale bytes as intended; neither was counted
  as a pass. All 30 benchmark processes completed successfully.
- `go vet ./internal/oauth` and `git diff --check` passed. No full repository
  suite, CI run, deployment or push; production and dependencies are unchanged.
