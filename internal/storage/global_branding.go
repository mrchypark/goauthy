package storage

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// Common branding gets its own namespace; ambiguous legacy rows stay untouched.
func migrateGlobalBranding(ctx context.Context, db *rhiza.DB) error {
	_, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v114", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS global_brand_themes (client_id TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL, document_json TEXT NOT NULL) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS global_brand_logos (client_id TEXT NOT NULL, res TEXT NOT NULL, content_type TEXT NOT NULL, data BLOB NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(client_id,res)) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS branding_legacy_resolution (singleton INTEGER PRIMARY KEY CHECK(singleton=1)) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations(version) VALUES(114)`},
	}})
	return err
}
