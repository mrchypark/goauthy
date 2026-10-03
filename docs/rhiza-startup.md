# Rhiza startup close guard

The greenfield candidate uses `github.com/mrchypark/rhiza v0.18.0` and
LatticeDB v0.10.0 with a fresh `DataDir`, unused cluster ID, and unused
object-store namespace. Existing-data migration is out of scope and unsupported.
During startup, `cmd/goauthy` waits up to 30 seconds for `DB.Ready()` before
running GoAuthy's application migrations or starting the HTTP server.

The startup defer intentionally does not call `DB.Close()` until all startup
initialization has succeeded and the server lifecycle is about to begin. This
is an application-side workaround for a confirmed Rhiza v0.10.0
checkpoint-corruption hazard when a database is closed during startup, even if
`DB.Ready()` became true transiently before a later migration, quorum, or
configuration failure. Once startup is complete, the normal close path remains
active for graceful shutdown, so this guard does not alter ordinary lifecycle
cleanup.

The GoAuthy startup-close regression test verifies this guard. One fresh local
diagnostic with three logical GoAuthy members on one Kind node and a Versity
fixture completed its scheduled IAM/API and drain checks on first startup
without GoAuthy restarts. See the [Run 25 evidence](measurements/saas-isolation-113-local/README.md).
This does not test data integrity after an early close and cold reopen, physical
host failure tolerance, production qualification, or existing-data migration.
See [the no-PVC recovery and upgrade contract](no-pvc-dr.md).
