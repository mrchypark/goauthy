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

The greenfield candidate retains this guard. The existing GoAuthy test verifies
the guard, not data integrity after an early close and cold reopen. No
end-to-end greenfield qualification is claimed yet. See [the no-PVC recovery
and upgrade contract](no-pvc-dr.md).
