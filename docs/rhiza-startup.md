# Rhiza startup close guard

GoAuthy uses `github.com/mrchypark/rhiza v0.12.3` for its embedded replicated
database. During startup, `cmd/goauthy` waits up to 30 seconds for
`DB.Ready()` before running migrations or starting the HTTP server.

The startup defer intentionally does not call `DB.Close()` until all startup
initialization has succeeded and the server lifecycle is about to begin. This
is an application-side workaround for a confirmed Rhiza v0.10.0
checkpoint-corruption hazard when a database is closed during startup, even if
`DB.Ready()` became true transiently before a later migration, quorum, or
configuration failure. Once startup is complete, the normal close path remains
active for graceful shutdown, so this guard does not alter ordinary lifecycle
cleanup.

The v0.12.3 upgrade retains this guard: Rhiza's public close implementation and
node shutdown ordering are unchanged from v0.12.0. The LatticeDB v0.6.0 upgrade
does not establish that the early-startup-close hazard is fixed. The existing
GoAuthy test verifies the guard, not data integrity after an early close and
cold reopen. The guard is deliberately narrow; it does
not claim to repair an already damaged checkpoint or replace Rhiza upgrades and
recovery testing.
