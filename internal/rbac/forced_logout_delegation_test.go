package rbac

import (
	"context"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// seedDelegatedExchange writes the rows the exchange path persists: an
// oauth_token_requests/oauth_access_tokens pair for the exchanged target plus
// its oauth_refresh_tokens row, all keyed on the SOURCE subject. The request
// record carries the actor only in extra.act, exactly as
// internal/oauth/token_exchange.go sets the target session and
// internal/oauth/grant_storage.go encodeRequest persists it. The rbac package
// cannot drive the OAuth exchange handlers, so the rows are seeded here with
// those same column shapes.
func seedDelegatedExchange(t *testing.T, db *rhiza.DB) {
	t.Helper()
	const record = `{"id":"oauth-token-exchange/hash","client_id":"client","requested_at_unix_ms":1700000000000,"requested_scopes":["goauthy.read"],"granted_scopes":["goauthy.read"],"requested_audience":[],"granted_audience":[],"subject":"delegation-source","extra":{"act":{"sub":"delegation-actor"}},"expires_at_unix_ms":{"access":4102444800000}}`
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "delegation-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES('exchange-target','` + record + `')`},
		{SQL: `INSERT INTO oauth_access_tokens(signature,request_id,client_id,requested_at_unix_ms,expires_at_unix_ms,requested_scopes,granted_scopes,requested_audience,granted_audience) VALUES('exchange-target','oauth-token-exchange/hash','client',1700000000000,4102444800000,'["goauthy.read"]','["goauthy.read"]','[]','[]')`},
		{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES('exchange-refresh','exchange-target','oauth-token-exchange/hash','` + record + `',4102444800000)`},
		{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES('delegation-actor-sid','delegation-actor','pwd',1700000000000,4102444800000,1700000000000)`},
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestForceLogoutDelegationActorRevocationKeepsExchangedCredential(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "delegation-source")
	insertActive(t, db, "delegation-actor")
	seedDelegatedExchange(t, db)
	if err := store.ForceLogout(ctx, "delegation-actor-op", "delegation-actor", "1=1"); err != nil {
		t.Fatal(err)
	}
	// The actor's own session family is revoked; the delegated credential that
	// names the source subject as its session subject survives.
	count(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE subject=? AND revoked_at_unix_ms IS NOT NULL`, "delegation-actor", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "exchange-target", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "exchange-target", 1)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=1`, "exchange-refresh", 1)
}

func TestForceLogoutDelegationSourceRevocationRevokesExchangedCredential(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "delegation-source")
	insertActive(t, db, "delegation-actor")
	seedDelegatedExchange(t, db)
	if err := store.ForceLogout(ctx, "delegation-source-op", "delegation-source", "1=1"); err != nil {
		t.Fatal(err)
	}
	count(t, db, `SELECT COUNT(*) FROM oauth_token_requests WHERE signature=?`, "exchange-target", 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_access_tokens WHERE signature=?`, "exchange-target", 0)
	count(t, db, `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE signature=? AND active=0`, "exchange-refresh", 1)
}
