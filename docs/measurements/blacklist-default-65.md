# #65 default blacklist capacity correctness

Base: `c6c6de0a2a7545bc4a2ce50caf6358f5c1ba8004`.
Test-only tranche, Go 1.27.0 darwin/arm64, GOMAXPROCS=4. No production,
dependency, admission-policy or storage-limit changes. No performance campaign.
**This is partial #65 evidence; it does not close the aggregate issue.**

## Scope and oracles

`internal/ipblacklist/default_capacity_test.go` uses the existing fully migrated
benchmark fixture (only its parameter widened to `testing.TB`). It retains normal
Rhiza limits and constructs two `NewStore(db, 0)` instances over one DB, with an
independent literal assertion of the documented 10,000 default.

Exactly 9,999 canonical, unique rows are fixture-seeded, including disjoint
43-byte IPv6 host prefixes and special match prefixes. Notes are 256 non-NUL
ASCII bytes (`0x01`), each JSON-escaped; the production byte limit and SQLite
character boundary are both respected. Twenty setup batches bind shared note
and timestamps once; each asserts <=999 arguments, <=256 KiB SQL and <=64 KiB
serialized ExecuteRequest, leaving headroom below the 128 KiB replicated-value
limit. These unconditional inserts are setup, not admission evidence. Setup is
atomic per batch, not across all batches; any setup failure aborts the test.

A start barrier releases two distinct production Add calls for the last slot.
Both complete their classification reads before any mutation or clock advance.
Exactly one succeeds and one returns ErrTooMany. The test checks exact winning
fields, absent loser, overflow, fresh-ID duplicate, full-capacity Update, all
10,000 List rows, fixed Check probes (including IPv6 and mapped IPv4), exact
expiry-equality fallback, continued capacity occupation by an expired row,
production Delete and fresh-ID slot reuse. No Check-per-row loop or sleep.

`internal/loginpolicy/default_blacklist_capacity_test.go` uses its existing
migrated fixture and default blacklist store. At 10,000 unexpired rows, a new
IP's seventh production Failure succeeds with counter seven and a one-minute
block deadline, retains seven InvalidLogins events, but inserts no blacklist row
and no IpBlacklisted event. An existing permanent prefix at a later explicit
clock advances updated_at while preserving creation time, note and NULL expiry;
this is a non-vacuous assertion of the full-capacity existing-prefix exception.

A fresh six-failure IP crosses the threshold when one victim expires exactly.
An IpBlacklisted-specific late abort trigger proves rollback of the complete
failure row, exact victim row, cardinality, target absence, event counts and
order high-water. Removing the trigger and repeating the seventh transition
admits the new prefix and removes the victim, retains 10,000 rows, and records
exactly the target's next InvalidLogins and one IpBlacklisted event with the
expected timestamp/IP/expiry-seconds data. This does not duplicate the separate
existing event-order abort matrix.

## Verification

Normal and race runs used this bounded selection on both packages:

```sh
GOMAXPROCS=4 go test ./internal/ipblacklist ./internal/loginpolicy \
  -run '^Test(DefaultCapacityWideRows|AddCeilingDeterministic|AddReplaySameRequestID|UpdateReplaySameRequestID|CheckExpiryEqualIsExpired|CheckExpiredEntrySkippedForLongerPrefix|RejectsLongNote|AutomaticBlacklist.*)$' \
  -count=1 -v -timeout=180s
# Repeat the same command with -race.
GOMAXPROCS=4 go vet ./internal/ipblacklist ./internal/loginpolicy
```

Normal: PASS, package times 6.237s / 7.497s. Race: PASS, 24.352s / 25.507s.
The final IPv6-probe/deleted-row assertions were subsequently checked by focused
normal/race runs of TestDefaultCapacityWideRows, with 90-second timeouts.
Full-width List/Check passed without reducing fixture widths or raising limits.
Test runtime is correctness execution evidence, not benchmark latency.

Three separate temporary Go overlays changed only production predicates;
working-tree production source was never changed. Each preserved placeholders
and valid SQL, and each failed an outcome assertion (not a SQL/binding error):

| Mutant | Exact substitution | Observed failure |
| --- | --- | --- |
| Manual capacity | `COUNT(*) … < ?` to `COUNT(*) … >= ? * 0` | Both last-slot Add calls returned nil errors. |
| Automatic capacity | Same substitution in automatic admission only | Blacklist cardinality became 10,001, query error nil. |
| Existing-prefix exception | `OR EXISTS (…)` to `OR (EXISTS (…) AND 0)` | Permanent row kept updated_at `1799999999000` instead of advancing to `1800000000001`, Get error nil. |

Each overlay command used `go test -overlay <mapping.json>` with only its new
boundary test selected, `-count=1 -v -timeout=90s`; each exited 1 as expected.
No benchmark timing body or data shape was changed. Existing expiry/threshold,
replay and rollback regressions were reused rather than replaced.

## Acceptance limit

This verifies the default Store boundary for the tested wide-row shape, manual
last-slot contention/full-table reads/updates and automatic prune/admit/event
rollback. It does not establish throughput, HTTP response-size acceptance,
backlog cleanup cost, production/HA SLOs, or a new policy decision. The broader
#65 audit and later expiry-backlog measurement remain outstanding.
