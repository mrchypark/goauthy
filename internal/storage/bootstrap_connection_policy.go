package storage

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// The pin is immutable. A different node configuration cannot overwrite cluster
// authority or make old consent valid again. Scope policy keeps its existing CAS.
func migrateBootstrapConnectionPolicy(ctx context.Context, db *rhiza.DB) error {
	_, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v113", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS bootstrap_connection_policy (
		 singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL UNIQUE,
		 config_digest TEXT NOT NULL CHECK(length(config_digest)=64), generation TEXT NOT NULL,
		 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json))) STRICT`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS bootstrap_connection_policy_no_update BEFORE UPDATE ON bootstrap_connection_policy BEGIN SELECT RAISE(ABORT,'bootstrap connections policy is immutable'); END`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS bootstrap_connection_policy_no_delete BEFORE DELETE ON bootstrap_connection_policy BEGIN SELECT RAISE(ABORT,'bootstrap connections policy is immutable'); END`},
		{SQL: `CREATE VIEW IF NOT EXISTS connection_client_policies AS
		 SELECT id,generation,revision,enabled,deleted,metadata_json FROM managed_oauth_clients m
		 WHERE NOT EXISTS(SELECT 1 FROM bootstrap_connection_policy b WHERE b.id=m.id)
		 UNION ALL
		 SELECT b.id,b.generation || ':scopes:' || CAST(COALESCE(s.revision,0) AS TEXT),1,1,0,
		 json_set(b.metadata_json,'$.scopes',json((SELECT json_group_array(value) FROM (
		   SELECT value FROM json_each(b.metadata_json,'$.scopes')
		   UNION SELECT value FROM json_each(s.allowed_scopes_json)))))
		 FROM bootstrap_connection_policy b LEFT JOIN bootstrap_client_claim_scopes s ON s.client_id=b.id
		 WHERE EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap r WHERE r.id=b.id)
		 AND NOT EXISTS(SELECT 1 FROM managed_oauth_clients m WHERE m.id=b.id)
		 AND NOT EXISTS(SELECT 1 FROM dynamic_oauth_clients d WHERE d.client_id=b.id)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations(version) VALUES(113)`},
	}})
	return err
}
