package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/mrchypark/rhiza"
)

const schemaVersion = 102

// migrateThroughV97 applies schema versions v1 through v97. It is the
// unchanged prefix of Migrate, extracted so tests can reach a clean v97
// state without cached RequestID receipts from v98-v102.
func migrateThroughV97(ctx context.Context, db *rhiza.DB) error {
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "goauthy-schema-v1",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS goauthy_schema_migrations (
				version INTEGER PRIMARY KEY
			) STRICT`},
			{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(1)}},
		},
	}); err != nil {
		return fmt.Errorf("migrate schema v1: %w", err)
	}
	if _, err := Execute(ctx, db, schemaV2Request("goauthy-schema-v2")); err != nil {
		return fmt.Errorf("migrate schema v2: %w", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "goauthy-schema-v3",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS oauth_access_tokens (
				signature TEXT PRIMARY KEY NOT NULL,
				request_id TEXT NOT NULL,
				client_id TEXT NOT NULL,
				requested_at_unix_ms INTEGER NOT NULL,
				expires_at_unix_ms INTEGER NOT NULL,
				requested_scopes TEXT NOT NULL,
				granted_scopes TEXT NOT NULL,
				requested_audience TEXT NOT NULL,
				granted_audience TEXT NOT NULL
			) STRICT`},
			{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(3)}},
		},
	}); err != nil {
		return fmt.Errorf("migrate schema v3: %w", err)
	}
	if _, err := Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "goauthy-schema-v4",
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS oauth_authorize_codes (
				signature TEXT PRIMARY KEY NOT NULL,
				request_json TEXT NOT NULL,
				expires_at_unix_ms INTEGER NOT NULL,
				invalidated INTEGER NOT NULL DEFAULT 0 CHECK (invalidated IN (0, 1)),
				used_attempt TEXT
			) STRICT`},
			{SQL: `CREATE TABLE IF NOT EXISTS oauth_pkce_requests (
				signature TEXT PRIMARY KEY NOT NULL,
				request_json TEXT NOT NULL,
				expires_at_unix_ms INTEGER NOT NULL
			) STRICT`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_authorize_codes_expiry
				ON oauth_authorize_codes(expires_at_unix_ms)`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_pkce_requests_expiry
				ON oauth_pkce_requests(expires_at_unix_ms)`},
			{SQL: `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
				signature TEXT PRIMARY KEY NOT NULL,
				access_signature TEXT NOT NULL,
				request_id TEXT NOT NULL,
				request_json TEXT NOT NULL,
				expires_at_unix_ms INTEGER NOT NULL,
				active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
				rotated_attempt TEXT
			) STRICT`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_request_id
				ON oauth_refresh_tokens(request_id)`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expiry
				ON oauth_refresh_tokens(expires_at_unix_ms)`},
			{SQL: `CREATE TABLE IF NOT EXISTS oauth_token_requests (
				signature TEXT PRIMARY KEY NOT NULL,
				request_json TEXT NOT NULL
			) STRICT`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_access_tokens_request_id
				ON oauth_access_tokens(request_id)`},
			{SQL: `CREATE INDEX IF NOT EXISTS oauth_access_tokens_expiry
				ON oauth_access_tokens(expires_at_unix_ms)`},
			{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(4)}},
		},
	}); err != nil {
		return fmt.Errorf("migrate schema v4: %w", err)
	}
	if err := migrateSchemaV5(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v5: %w", err)
	}
	if _, err := Execute(ctx, db, schemaV6Request("goauthy-schema-v6")); err != nil {
		return fmt.Errorf("migrate schema v6: %w", err)
	}
	if err := migrateSchemaV7(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v7: %w", err)
	}
	if err := migrateSchemaV8(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v8: %w", err)
	}
	if err := migrateSchemaV9(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v9: %w", err)
	}
	if err := migrateSchemaV10(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v10: %w", err)
	}
	if err := migrateSchemaV11(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v11: %w", err)
	}
	if err := migrateSchemaV12(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v12: %w", err)
	}
	if err := migrateSchemaV13(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v13: %w", err)
	}
	if err := migrateSchemaV14(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v14: %w", err)
	}
	if err := migrateSchemaV15(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v15: %w", err)
	}
	if err := migrateSchemaV16(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v16: %w", err)
	}
	if err := migrateSchemaV17(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v17: %w", err)
	}
	if err := migrateSchemaV18(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v18: %w", err)
	}
	if err := migrateSchemaV19(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v19: %w", err)
	}
	if err := migrateSchemaV20(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v20: %w", err)
	}
	if err := migrateSchemaV21(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v21: %w", err)
	}
	if err := migrateSchemaV22(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v22: %w", err)
	}
	if err := migrateSchemaV23(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v23: %w", err)
	}
	if err := migrateSchemaV24(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v24: %w", err)
	}
	if err := migrateSchemaV25(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v25: %w", err)
	}
	if err := migrateSchemaV26(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v26: %w", err)
	}
	if err := migrateSchemaV27(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v27: %w", err)
	}
	if err := migrateSchemaV28(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v28: %w", err)
	}
	if err := migrateSchemaV29(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v29: %w", err)
	}
	if err := migrateSchemaV30(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v30: %w", err)
	}
	if err := migrateSchemaV31(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v31: %w", err)
	}
	if err := migrateSchemaV32(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v32: %w", err)
	}
	if err := migrateSchemaV33(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v33: %w", err)
	}
	if err := migrateSchemaV34(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v34: %w", err)
	}
	if err := migrateSchemaV35(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v35: %w", err)
	}
	if err := migrateSchemaV36(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v36: %w", err)
	}
	if err := migrateSchemaV37(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v37: %w", err)
	}
	if err := migrateSchemaV38(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v38: %w", err)
	}
	if err := migrateSchemaV39(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v39: %w", err)
	}
	if err := migrateSchemaV40(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v40: %w", err)
	}
	if err := migrateSchemaV41(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v41: %w", err)
	}
	if err := migrateSchemaV42(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v42: %w", err)
	}
	if err := migrateSchemaV43(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v43: %w", err)
	}
	if err := migrateSchemaV44(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v44: %w", err)
	}
	if err := migrateSchemaV45(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v45: %w", err)
	}
	if err := migrateSchemaV46(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v46: %w", err)
	}
	if err := migrateSchemaV47(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v47: %w", err)
	}
	if err := migrateSchemaV48(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v48: %w", err)
	}
	if err := migrateSchemaV49(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v49: %w", err)
	}
	if err := migrateSchemaV50(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v50: %w", err)
	}
	if err := migrateSchemaV51(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v51: %w", err)
	}
	if err := migrateSchemaV52(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v52: %w", err)
	}
	if err := migrateSchemaV53(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v53: %w", err)
	}
	if err := migrateSchemaV54(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v54: %w", err)
	}
	if err := migrateSchemaV55(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v55: %w", err)
	}
	if err := migrateSchemaV56(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v56: %w", err)
	}
	if err := migrateSchemaV57(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v57: %w", err)
	}
	if err := migrateSchemaV58(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v58: %w", err)
	}
	if err := migrateSchemaV59(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v59: %w", err)
	}
	if err := migrateSchemaV60(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v60: %w", err)
	}
	if err := migrateSchemaV61(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v61: %w", err)
	}
	if err := migrateSchemaV62(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v62: %w", err)
	}
	if err := migrateSchemaV63(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v63: %w", err)
	}
	if err := migrateSchemaV64(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v64: %w", err)
	}
	if err := migrateSchemaV65(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v65: %w", err)
	}
	if err := migrateSchemaV66(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v66: %w", err)
	}
	if err := migrateSchemaV67(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v67: %w", err)
	}
	if err := migrateSchemaV68(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v68: %w", err)
	}
	if err := migrateSchemaV69(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v69: %w", err)
	}
	if err := migrateSchemaV70(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v70: %w", err)
	}
	if err := migrateSchemaV71(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v71: %w", err)
	}
	if err := migrateSchemaV72(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v72: %w", err)
	}
	if err := migrateSchemaV73(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v73: %w", err)
	}
	if err := migrateSchemaV74(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v74: %w", err)
	}
	if err := migrateSchemaV75(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v75: %w", err)
	}
	if err := migrateSchemaV76(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v76: %w", err)
	}
	if err := migrateSchemaV77(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v77: %w", err)
	}
	if err := migrateSchemaV78(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v78: %w", err)
	}
	if err := migrateSchemaV79(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v79: %w", err)
	}
	if err := migrateSchemaV80(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v80: %w", err)
	}
	if err := migrateSchemaV81(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v81: %w", err)
	}
	if err := migrateSchemaV82(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v82: %w", err)
	}
	if err := migrateSchemaV83(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v83: %w", err)
	}
	if err := migrateSchemaV84(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v84: %w", err)
	}
	if err := migrateSchemaV85(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v85: %w", err)
	}
	if err := migrateSchemaV86(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v86: %w", err)
	}
	if err := migrateSchemaV87(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v87: %w", err)
	}
	if err := migrateSchemaV88(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v88: %w", err)
	}
	if err := migrateSchemaV89(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v89: %w", err)
	}
	if err := migrateSchemaV90(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v90: %w", err)
	}
	if err := migrateSchemaV91(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v91: %w", err)
	}
	if err := migrateSchemaV92(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v92: %w", err)
	}
	if err := migrateSchemaV93(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v93: %w", err)
	}
	if err := migrateSchemaV94(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v94: %w", err)
	}
	if err := migrateSchemaV95(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v95: %w", err)
	}
	if err := migrateSchemaV96(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v96: %w", err)
	}
	if err := migrateSchemaV97(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v97: %w", err)
	}
	return nil
}

// Migrate applies deterministic, idempotent schema changes through Rhiza's
// replicated transaction API. A migration's request ID must never be reused
// for different statements.
func Migrate(ctx context.Context, db *rhiza.DB) error {
	if err := migrateThroughV97(ctx, db); err != nil {
		return err
	}
	if err := migrateSchemaV98(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v98: %w", err)
	}
	if err := migrateSchemaV99(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v99: %w", err)
	}
	if err := migrateSchemaV100(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v100: %w", err)
	}
	if err := migrateSchemaV101(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v101: %w", err)
	}
	if err := migrateSchemaV102(ctx, db); err != nil {
		return fmt.Errorf("migrate schema v102: %w", err)
	}
	return nil
}

// migrateSchemaV85 stores the cluster-wide Generate API-key artifact. A NULL
// envelope is an irreversible expiry tombstone: its immutable metadata keeps
// a later starter from minting a different bootstrap secret.
func migrateSchemaV85(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=85)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 85 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v85", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE generated_api_key_bootstrap (
			singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
			config_digest TEXT NOT NULL CHECK(length(config_digest) > 0),
			payload_envelope BLOB CHECK(payload_envelope IS NULL OR length(payload_envelope) > 0),
			deadline_unix_s INTEGER NOT NULL CHECK(deadline_unix_s >= 0),
			created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE TRIGGER generated_api_key_bootstrap_tombstone_immutable
			BEFORE UPDATE ON generated_api_key_bootstrap
			WHEN OLD.payload_envelope IS NULL AND NEW.payload_envelope IS NOT NULL
			BEGIN SELECT RAISE(ABORT,'generated API-key bootstrap tombstone cannot be resurrected'); END`},
		{SQL: `CREATE TRIGGER generated_api_key_bootstrap_tombstone_metadata
			BEFORE UPDATE ON generated_api_key_bootstrap
			WHEN NEW.payload_envelope IS NULL AND (NEW.config_digest <> OLD.config_digest OR NEW.deadline_unix_s <> OLD.deadline_unix_s OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms)
			BEGIN SELECT RAISE(ABORT,'generated API-key bootstrap tombstone metadata is immutable'); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(85)`},
	}})
	return err
}

// migrateSchemaV84 records a verified upstream logout token's replay receipt.
// It stores only bounded claims and the token digest, never the bearer token.
func migrateSchemaV84(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=84)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 84 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v84", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE upstream_logout_receipts (
			issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 2048),
			client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 256),
			jti TEXT NOT NULL CHECK(length(jti) BETWEEN 1 AND 512),
			token_digest TEXT NOT NULL CHECK(length(token_digest) = 43 AND token_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(token_digest, -1) GLOB '[AEIMQUYcgkosw048]'),
			operation_id TEXT NOT NULL CHECK(length(operation_id) = 22 AND operation_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(operation_id, -1) GLOB '[AQgw]'),
			upstream_subject TEXT NOT NULL CHECK(length(upstream_subject) <= 512),
			upstream_sid TEXT NOT NULL CHECK(length(upstream_sid) <= 512),
			expires_at_unix_ms INTEGER NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (issuer, client_id, jti)
		) STRICT`},
		{SQL: `CREATE INDEX upstream_logout_receipts_expiry ON upstream_logout_receipts(expires_at_unix_ms)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(84)`},
	}})
	return err
}

// migrateSchemaV83 adds the verified upstream OIDC identity that created an
// external browser session. Rhiza does not enforce SQLite foreign keys; the
// browser store removes bindings when it deletes expired sessions.
func migrateSchemaV83(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=83)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 83 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v83", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE browser_upstream_session_bindings (
			session_digest TEXT PRIMARY KEY NOT NULL,
			issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 2048),
			client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 1 AND 256),
			upstream_subject TEXT NOT NULL CHECK(length(upstream_subject) BETWEEN 1 AND 512),
			upstream_sid TEXT CHECK(upstream_sid IS NULL OR length(upstream_sid) BETWEEN 1 AND 512),
			created_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX browser_upstream_session_bindings_subject ON browser_upstream_session_bindings(issuer, client_id, upstream_subject)`},
		{SQL: `CREATE INDEX browser_upstream_session_bindings_sid ON browser_upstream_session_bindings(issuer, client_id, upstream_sid) WHERE upstream_sid IS NOT NULL`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(83)`},
	}})
	return err
}

func migrateSchemaV82(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=82)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 82 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v82", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE saas_use_grants ADD COLUMN allow_refresh INTEGER NOT NULL DEFAULT 0 CHECK (allow_refresh IN (0,1))`},
		{SQL: `ALTER TABLE saas_use_handoffs ADD COLUMN allow_refresh INTEGER NOT NULL DEFAULT 0 CHECK (allow_refresh IN (0,1))`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(82)`},
	}})
	return err
}

func migrateSchemaV81(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=81)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 81 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v81", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE saas_use_handoffs ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0 CHECK (credential_version >= 0)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(81)`},
	}})
	return err
}

func migrateSchemaV80(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=80)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 80 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v80", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN dpop_bound_access_tokens INTEGER NOT NULL DEFAULT 0 CHECK (dpop_bound_access_tokens IN (0,1))`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(80)`},
	}})
	return err
}

func migrateSchemaV78(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=78)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 78 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v78", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_use_handoffs (
			id_hash TEXT PRIMARY KEY NOT NULL,
			owner_subject TEXT NOT NULL,
			request_client_id TEXT NOT NULL,
			request_client_generation TEXT NOT NULL,
			collection_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			generation TEXT NOT NULL,
			consumer_client_id TEXT NOT NULL,
			consumer_generation TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			connector_digest TEXT NOT NULL,
			resource TEXT NOT NULL,
			mode TEXT NOT NULL CHECK (mode='proxy'),
			purpose TEXT NOT NULL,
			return_uri TEXT NOT NULL,
			return_state TEXT NOT NULL,
			provider_revision INTEGER NOT NULL CHECK (provider_revision > 0),
			grant_expires_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('pending','approved','denied')),
			grant_id TEXT,
			CHECK ((state='approved' AND grant_id IS NOT NULL) OR (state IN ('pending','denied') AND grant_id IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX saas_use_handoffs_expiry ON saas_use_handoffs(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX saas_use_handoffs_owner_expiry ON saas_use_handoffs(owner_subject,expires_at_unix_ms)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(78)`},
	}})
	return err
}

func migrateSchemaV79(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=79)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 79 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v79", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_use_handoffs_v79 (
			id_hash TEXT PRIMARY KEY NOT NULL,
			owner_subject TEXT NOT NULL,
			request_client_id TEXT NOT NULL,
			request_client_generation TEXT NOT NULL,
			collection_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			generation TEXT NOT NULL,
			consumer_client_id TEXT NOT NULL,
			consumer_generation TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			connector_digest TEXT NOT NULL,
			resource TEXT NOT NULL,
			mode TEXT NOT NULL CHECK (mode IN ('proxy','credential_delivery')),
			purpose TEXT NOT NULL,
			return_uri TEXT NOT NULL,
			return_state TEXT NOT NULL,
			provider_revision INTEGER NOT NULL CHECK (provider_revision > 0),
			grant_expires_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('pending','approved','denied')),
			grant_id TEXT,
			CHECK ((state='approved' AND grant_id IS NOT NULL) OR (state IN ('pending','denied') AND grant_id IS NULL))
		) STRICT`},
		{SQL: `INSERT INTO saas_use_handoffs_v79 SELECT id_hash,owner_subject,request_client_id,request_client_generation,collection_id,connection_id,generation,consumer_client_id,consumer_generation,provider_id,connector_digest,resource,mode,purpose,return_uri,return_state,provider_revision,grant_expires_at_unix_ms,expires_at_unix_ms,state,grant_id FROM saas_use_handoffs`},
		{SQL: `DROP INDEX IF EXISTS saas_use_handoffs_expiry`},
		{SQL: `DROP INDEX IF EXISTS saas_use_handoffs_owner_expiry`},
		{SQL: `DROP TABLE saas_use_handoffs`},
		{SQL: `ALTER TABLE saas_use_handoffs_v79 RENAME TO saas_use_handoffs`},
		{SQL: `CREATE INDEX saas_use_handoffs_expiry ON saas_use_handoffs(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX saas_use_handoffs_owner_expiry ON saas_use_handoffs(owner_subject,expires_at_unix_ms)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(79)`},
	}})
	return err
}

func migrateSchemaV77(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=77)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 77 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v77", Statements: []rhiza.SQLStatement{
		{SQL: `DROP TRIGGER auth_collection_provider_revoke`},
		{SQL: `CREATE TRIGGER auth_collection_provider_revoke AFTER UPDATE OF providers_json ON auth_collection_definitions WHEN NEW.auth_method='oauth2' OR (NEW.auth_method='api_key' AND (json_array_length(OLD.providers_json)>0 OR json_array_length(NEW.providers_json)>0)) BEGIN UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE collection_id=NEW.id AND NOT EXISTS(SELECT 1 FROM json_each(NEW.providers_json) p WHERE p.type='text' AND p.value=saas_connection_credentials.provider_id); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(77)`},
	}})
	return err
}

func migrateSchemaV76(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=76)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 76 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v76", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_use_grants (
			id TEXT PRIMARY KEY NOT NULL,
			owner_subject TEXT NOT NULL,
			collection_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			consumer_client_id TEXT NOT NULL,
			mode TEXT NOT NULL CHECK(mode IN ('proxy','credential_delivery')),
			purpose TEXT NOT NULL,
			resource TEXT NOT NULL,
			generation TEXT NOT NULL,
			consumer_generation TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			connector_digest TEXT NOT NULL,
			revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
			provider_revision INTEGER NOT NULL CHECK(provider_revision >= 0),
			expires_at_unix_ms INTEGER NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
		) STRICT`},
		{SQL: `CREATE INDEX saas_use_grants_owner_resource ON saas_use_grants(owner_subject,collection_id,connection_id)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(76)`},
	}})
	return err
}

func migrateSchemaV75(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=75)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 75 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v75", Statements: []rhiza.SQLStatement{{SQL: `ALTER TABLE oauth_device_grants ADD COLUMN resource TEXT`}, {SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(75)`}}})
	return err
}

func migrateSchemaV74(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=74)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 74 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v74", Statements: []rhiza.SQLStatement{{SQL: `ALTER TABLE saas_authorization_requests ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1 CHECK(token_version>=1)`}, {SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(74)`}}})
	return err
}

func migrateSchemaV73(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=73)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 73 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v73", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE saas_authorization_requests ADD COLUMN verifier_envelope BLOB`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(73)`},
	}})
	return err
}

func migrateSchemaV72(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=72)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 72 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v72", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE saas_providers ADD COLUMN identity_endpoint TEXT NOT NULL DEFAULT ''`},
		{SQL: `ALTER TABLE saas_providers ADD COLUMN subject_field TEXT NOT NULL DEFAULT ''`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(72)`},
	}})
	return err
}

func migrateSchemaV71(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=71)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 71 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v71", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_providers (
			id TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL CHECK(kind IN ('oauth2','api_key')),
			enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
			revision INTEGER NOT NULL CHECK(revision >= 1),
			deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
			callback_uri TEXT NOT NULL,
			client_id TEXT NOT NULL,
			auth_endpoint TEXT NOT NULL,
			token_endpoint TEXT NOT NULL,
			scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json) AND json_type(scopes_json)='array'),
			auth_style TEXT NOT NULL,
			connector_json TEXT NOT NULL DEFAULT '',
			generation TEXT NOT NULL,
			secret_envelope BLOB
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(71)`},
	}})
	return err
}

func migrateSchemaV70(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=70)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 70 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v70", Statements: []rhiza.SQLStatement{
		{SQL: `DROP TRIGGER auth_collection_provider_revoke`},
		{SQL: `CREATE TRIGGER auth_collection_provider_revoke AFTER UPDATE OF providers_json ON auth_collection_definitions WHEN NEW.auth_method='oauth2' BEGIN UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE collection_id=NEW.id AND NOT EXISTS(SELECT 1 FROM json_each(NEW.providers_json) p WHERE p.type='text' AND p.value=saas_connection_credentials.provider_id); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(70)`},
	}})
	return err
}

func migrateSchemaV69(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=69)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 69 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v69", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_authorization_requests (
			state_digest TEXT PRIMARY KEY NOT NULL,
			verifier_digest TEXT NOT NULL,
			session_digest TEXT NOT NULL,
			provider_digest TEXT NOT NULL,
			owner_subject TEXT NOT NULL,
			collection_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			generation TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms > created_at_unix_ms),
			consumed_at_unix_ms INTEGER,
			invalidated INTEGER NOT NULL DEFAULT 0 CHECK(invalidated IN (0,1))
		) STRICT`},
		{SQL: `CREATE INDEX saas_authorization_requests_expires ON saas_authorization_requests(expires_at_unix_ms)`},
		{SQL: `CREATE TRIGGER auth_collection_authorization_request_invalidate AFTER UPDATE OF providers_json ON auth_collection_definitions BEGIN UPDATE saas_authorization_requests SET invalidated=1 WHERE collection_id=NEW.id AND NOT EXISTS(SELECT 1 FROM json_each(NEW.providers_json) p WHERE p.type='text' AND p.value=saas_authorization_requests.provider_id); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(69)`},
	}})
	return err
}

func migrateSchemaV68(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=68)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 68 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v68", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE auth_collection_definitions ADD COLUMN providers_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(providers_json) AND json_type(providers_json)='array')`},
		{SQL: `CREATE TRIGGER auth_collection_provider_revoke AFTER UPDATE OF providers_json ON auth_collection_definitions BEGIN UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE collection_id=NEW.id AND NOT EXISTS(SELECT 1 FROM json_each(NEW.providers_json) p WHERE p.type='text' AND p.value=saas_connection_credentials.provider_id); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(68)`},
	}})
	return err
}

func migrateSchemaV67(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=67)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 67 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v67", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE saas_connection_credentials (
			connection_id TEXT PRIMARY KEY NOT NULL,
			owner_subject TEXT NOT NULL,
			collection_id TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			generation TEXT NOT NULL,
			token_version INTEGER NOT NULL CHECK(token_version >= 1),
			state TEXT NOT NULL CHECK(state IN ('ready','refreshing','uncertain','revoked')),
			credential BLOB NOT NULL,
			refresh_claim TEXT,
			CHECK((state = 'refreshing' AND refresh_claim IS NOT NULL) OR (state <> 'refreshing' AND refresh_claim IS NULL))
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(67)`},
	}})
	return err
}

func migrateSchemaV66(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=66)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 66 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v66", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE oauth_device_grants ADD COLUMN token_request_id TEXT`},
		{SQL: `ALTER TABLE oauth_device_grants ADD COLUMN revoked_at_unix_ms INTEGER`},
		{SQL: `CREATE UNIQUE INDEX oauth_device_grants_token_request_idx ON oauth_device_grants(token_request_id) WHERE token_request_id IS NOT NULL`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(66)`},
	}})
	return err
}

func migrateSchemaV65(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=65)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 65 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v65", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE oauth_device_grants ADD COLUMN managed_client_generation TEXT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(65)`},
	}})
	return err
}

func migrateSchemaV64(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=64)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 64 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v64", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE auth_collection_definitions (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, auth_method TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), revision INTEGER NOT NULL CHECK(revision > 0), generation TEXT NOT NULL, fields_json TEXT NOT NULL CHECK(json_valid(fields_json) AND json_type(fields_json)='array'), deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1))) STRICT`},
		{SQL: `CREATE TABLE auth_collection_connections (id TEXT PRIMARY KEY NOT NULL, collection_id TEXT NOT NULL, owner_subject TEXT NOT NULL, state TEXT NOT NULL CHECK(state='draft'), revision INTEGER NOT NULL CHECK(revision > 0), definition_revision INTEGER NOT NULL CHECK(definition_revision > 0), metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json) AND json_type(metadata_json)='object' AND length(metadata_json) <= 8192), generation TEXT NOT NULL)`},
		{SQL: `CREATE INDEX auth_collection_connections_owner ON auth_collection_connections(owner_subject,collection_id,id)`},
		{SQL: `CREATE INDEX auth_collection_connections_collection ON auth_collection_connections(collection_id)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(64)`},
	}})
	return err
}

func migrateSchemaV63(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=63)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 63 inspection")
	}
	dynamic, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='dynamic_oauth_clients')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(dynamic.Rows) != 1 {
		return errors.New("invalid dynamic client inspection")
	}
	statements := []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS managed_oauth_client_bootstrap (singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL UNIQUE) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS managed_oauth_clients (id TEXT PRIMARY KEY NOT NULL, generation TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)), metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json) AND json_type(metadata_json)='object'), secret_hash BLOB, secret_envelope BLOB) STRICT`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS managed_oauth_clients_no_bootstrap_shadow BEFORE INSERT ON managed_oauth_clients WHEN EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'managed client id is bootstrap reserved'); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations(version) VALUES(63)`},
	}
	if dynamic.Rows[0][0] == int64(1) {
		statements = append(statements[:len(statements)-1], rhiza.SQLStatement{SQL: `CREATE TRIGGER IF NOT EXISTS managed_oauth_clients_no_dynamic_shadow BEFORE INSERT ON managed_oauth_clients WHEN EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=NEW.id) BEGIN SELECT RAISE(ABORT,'managed client id already used by dynamic client'); END`}, rhiza.SQLStatement{SQL: `CREATE TRIGGER IF NOT EXISTS dynamic_oauth_clients_no_managed_shadow BEFORE INSERT ON dynamic_oauth_clients WHEN EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=NEW.client_id) BEGIN SELECT RAISE(ABORT,'dynamic client id already used by managed client'); END`}, rhiza.SQLStatement{SQL: `CREATE TRIGGER IF NOT EXISTS dynamic_oauth_clients_no_bootstrap_shadow BEFORE INSERT ON dynamic_oauth_clients WHEN EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=NEW.client_id) BEGIN SELECT RAISE(ABORT,'dynamic client id is bootstrap reserved'); END`}, statements[len(statements)-1])
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v63", Statements: statements})
	return err
}

func migrateSchemaV62(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=62)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 62 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v62", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE event_notification_targets (target TEXT PRIMARY KEY NOT NULL, level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3), enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))) STRICT`},
		{SQL: `CREATE TABLE event_notification_deliveries (target TEXT NOT NULL, event_id TEXT NOT NULL, timestamp INTEGER NOT NULL, level INTEGER NOT NULL, typ TEXT NOT NULL, ip TEXT, data INTEGER, text TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at_unix_ms INTEGER NOT NULL, lease_token TEXT, lease_until_unix_ms INTEGER, delivered_at_unix_ms INTEGER, last_error TEXT, PRIMARY KEY(target,event_id)) STRICT`},
		{SQL: `CREATE INDEX event_notification_due ON event_notification_deliveries(target,next_attempt_at_unix_ms,delivered_at_unix_ms)`},
		{SQL: `CREATE TRIGGER event_notification_enqueue AFTER INSERT ON event_log BEGIN INSERT OR IGNORE INTO event_notification_deliveries(target,event_id,timestamp,level,typ,ip,data,text,next_attempt_at_unix_ms) SELECT target,NEW.id,NEW.timestamp,NEW.level,NEW.typ,NEW.ip,NEW.data,NEW.text,NEW.timestamp FROM event_notification_targets WHERE enabled=1; END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(62)`},
	}})
	return err
}

func migrateSchemaV61(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='oidc_backchannel_deliveries'),
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='oidc_user_clients'),
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='oidc_backchannel_deliveries_due'),
		EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=61),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_backchannel_deliveries') WHERE name='sid'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_backchannel_deliveries') WHERE name='subject'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='subject'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='client_id'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='logout_uri'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='allow_private'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='allow_http'),
		EXISTS(SELECT 1 FROM pragma_table_info('oidc_user_clients') WHERE name='created_at_unix_ms')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 12 {
		return errors.New("invalid schema 61 inspection")
	}
	counts, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		(SELECT COUNT(*) FROM pragma_table_info('oidc_backchannel_deliveries')),
		(SELECT COUNT(*) FROM pragma_table_info('oidc_user_clients'))`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(counts.Rows) != 1 || len(counts.Rows[0]) != 2 {
		return errors.New("invalid schema 61 column inspection")
	}
	deliveryColumns, deliveryOK := counts.Rows[0][0].(int64)
	userColumns, userOK := counts.Rows[0][1].(int64)
	if !deliveryOK || !userOK {
		return errors.New("invalid schema 61 column count")
	}
	flags := make([]bool, 12)
	for i, raw := range state.Rows[0] {
		n, ok := raw.(int64)
		if !ok || (n != 0 && n != 1) {
			return fmt.Errorf("schema 61 inspection flag has type/value %T/%v", raw, raw)
		}
		flags[i] = n == 1
	}
	if flags[3] {
		if deliveryColumns != 15 || userColumns != 6 {
			return errors.New("schema 61 marker exists but table columns are incomplete")
		}
		for _, i := range []int{0, 1, 2, 4, 5} {
			present := flags[i]
			if !present {
				return fmt.Errorf("schema 61 marker exists but schema object %d is missing", i)
			}
		}
		if slices.Contains(flags[6:], false) {
			return errors.New("schema 61 user-client columns are incomplete")
		}
		shape, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
			EXISTS(SELECT 1 FROM pragma_table_info('oidc_backchannel_deliveries') WHERE name='sid' AND type='TEXT' AND "notnull"=0),
			EXISTS(SELECT 1 FROM pragma_table_info('oidc_backchannel_deliveries') WHERE name='subject' AND type='TEXT' AND "notnull"=1 AND dflt_value='''''')`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		if len(shape.Rows) != 1 || len(shape.Rows[0]) != 2 || shape.Rows[0][0] != int64(1) || shape.Rows[0][1] != int64(1) {
			return errors.New("schema 61 subject/session nullability or default mismatch")
		}
		return nil
	}
	if !flags[0] || flags[1] || !flags[2] || flags[5] || slices.Contains(flags[6:], true) || deliveryColumns != 14 {
		return errors.New("schema 61 marker and schema objects disagree")
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v61", Statements: []rhiza.SQLStatement{
		{SQL: `DROP INDEX oidc_backchannel_deliveries_due`},
		{SQL: `CREATE TABLE oidc_backchannel_deliveries_v61 (
			event_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			sid TEXT,
			subject TEXT NOT NULL DEFAULT '',
			logout_uri TEXT NOT NULL,
			allow_private INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			allow_http INTEGER NOT NULL CHECK (allow_http IN (0, 1)),
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at_unix_ms INTEGER NOT NULL,
			lease_token TEXT,
			lease_until_unix_ms INTEGER,
			delivered_at_unix_ms INTEGER,
			failed_at_unix_ms INTEGER,
			last_error TEXT,
			created_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (event_id, client_id),
			UNIQUE (sid, client_id),
			CHECK ((sid IS NOT NULL AND sid <> '') OR subject <> '')
		) STRICT`},
		{SQL: `INSERT INTO oidc_backchannel_deliveries_v61
			(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,lease_token,lease_until_unix_ms,delivered_at_unix_ms,failed_at_unix_ms,last_error,created_at_unix_ms)
			SELECT event_id,client_id,sid,'',logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,lease_token,lease_until_unix_ms,delivered_at_unix_ms,failed_at_unix_ms,last_error,created_at_unix_ms
			FROM oidc_backchannel_deliveries`},
		{SQL: `DROP TABLE oidc_backchannel_deliveries`},
		{SQL: `ALTER TABLE oidc_backchannel_deliveries_v61 RENAME TO oidc_backchannel_deliveries`},
		{SQL: `CREATE INDEX oidc_backchannel_deliveries_due ON oidc_backchannel_deliveries(next_attempt_at_unix_ms) WHERE delivered_at_unix_ms IS NULL AND failed_at_unix_ms IS NULL`},
		{SQL: `CREATE TABLE oidc_user_clients (
			subject TEXT NOT NULL CHECK (subject <> ''),
			client_id TEXT NOT NULL,
			logout_uri TEXT NOT NULL,
			allow_private INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			allow_http INTEGER NOT NULL CHECK (allow_http IN (0, 1)),
			created_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (subject, client_id)
		) STRICT`},
		{SQL: `INSERT INTO oidc_user_clients (subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms)
			SELECT b.subject, sc.client_id, sc.logout_uri, sc.allow_private, sc.allow_http, sc.created_at_unix_ms
			FROM oidc_session_clients sc JOIN browser_sessions b ON b.token_digest=sc.sid
			WHERE b.subject <> '' AND NOT EXISTS (
				SELECT 1 FROM oidc_session_clients sc2 JOIN browser_sessions b2 ON b2.token_digest=sc2.sid
				WHERE b2.subject=b.subject AND sc2.client_id=sc.client_id AND
					(sc2.created_at_unix_ms < sc.created_at_unix_ms OR
					 (sc2.created_at_unix_ms = sc.created_at_unix_ms AND b2.token_digest < b.token_digest)))`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(61)`},
	}})
	return err
}

func migrateSchemaV60(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_log'),
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_log_order'),
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='event_log_order_insert'),
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='event_log_order_delete'),
		EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=60)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 5 {
		return errors.New("invalid schema 60 inspection")
	}
	flags := make([]int64, 5)
	for i, raw := range state.Rows[0] {
		n, ok := raw.(int64)
		if !ok || (n != 0 && n != 1) {
			return errors.New("invalid schema 60 inspection flag")
		}
		flags[i] = n
	}
	if flags[4] == 1 && flags[0] == 1 && flags[1] == 1 && flags[2] == 1 && flags[3] == 1 {
		return nil
	}
	if flags[4] == 1 || flags[0] != 1 || flags[1] != 0 || flags[2] != 0 || flags[3] != 0 {
		return errors.New("event order and schema 60 marker disagree")
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v60", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE event_log_order (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL) STRICT`},
		{SQL: `INSERT INTO event_log_order(event_id) SELECT id FROM event_log ORDER BY timestamp ASC,id ASC`},
		{SQL: `CREATE TRIGGER event_log_order_insert AFTER INSERT ON event_log BEGIN INSERT INTO event_log_order(event_id) VALUES(NEW.id); END`},
		{SQL: `CREATE TRIGGER event_log_order_delete AFTER DELETE ON event_log BEGIN DELETE FROM event_log_order WHERE event_id=OLD.id; END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(60)`},
	}})
	return err
}

func migrateSchemaV59(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_log'),
		EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=59)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 2 {
		return errors.New("invalid schema 59 inspection")
	}
	if state.Rows[0][0] == int64(1) && state.Rows[0][1] == int64(1) {
		return nil
	}
	if state.Rows[0][0] != int64(0) || state.Rows[0][1] != int64(0) {
		return errors.New("event log and schema 59 marker disagree")
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v59", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE event_log (
			id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=43),
			timestamp INTEGER NOT NULL CHECK(timestamp>=0),
			level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3),
			typ TEXT NOT NULL CHECK(typ IN ('InvalidLogins','IpBlacklisted','IpBlacklistRemoved','JwksRotated','NewUserRegistered','NewRauthyAdmin','NewRauthyVersion','PossibleBruteForce','RauthyStarted','RauthyHealthy','RauthyUnhealthy','SecretsMigrated','UserEmailChange','UserPasswordReset','Test','BackchannelLogoutFailed','ScimTaskFailed','ForcedLogout','UserLoginRevoke','SuspiciousApiScan','LoginNewLocation','TokenIssued','CredentialStuffing','EmailSendError')),
			ip TEXT CHECK(ip IS NULL OR length(ip) BETWEEN 2 AND 45),
			data INTEGER,
			text TEXT CHECK(text IS NULL OR length(text)<=4096)
		) STRICT`},
		{SQL: `CREATE INDEX event_log_time ON event_log(timestamp DESC,id DESC)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(59)`},
	}})
	return err
}

func migrateSchemaV58(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity_users'),
		EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=58),
		EXISTS(SELECT 1 FROM pragma_table_info('identity_users') WHERE name='user_expires_at_unix_ms')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 3 {
		return fmt.Errorf("unexpected schema 58 inspection result")
	}
	flags := make([]bool, 3)
	for i, raw := range state.Rows[0] {
		n, ok := raw.(int64)
		if !ok || (n != 0 && n != 1) {
			return fmt.Errorf("schema 58 inspection flag has type/value %T/%v", raw, raw)
		}
		flags[i] = n == 1
	}
	if !flags[0] {
		return fmt.Errorf("identity_users table is missing")
	}
	if flags[1] {
		if !flags[2] {
			return fmt.Errorf("schema 58 marker exists but expiry column is missing")
		}
		return nil
	}
	if flags[2] {
		return fmt.Errorf("identity expiry column exists without schema 58 marker")
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v58", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_users ADD COLUMN user_expires_at_unix_ms INTEGER CHECK (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms >= 0)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(58)}},
	}})
	return err
}

func migrateSchemaV57(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity_users'),
		EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=57),
		EXISTS(SELECT 1 FROM pragma_table_info('identity_users') WHERE name='language')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 3 {
		return fmt.Errorf("unexpected schema 57 inspection result")
	}
	flags := make([]bool, 3)
	for i, raw := range state.Rows[0] {
		n, ok := raw.(int64)
		if !ok || (n != 0 && n != 1) {
			return fmt.Errorf("schema 57 inspection flag has type/value %T/%v", raw, raw)
		}
		flags[i] = n == 1
	}
	if !flags[0] {
		return fmt.Errorf("identity_users table is missing")
	}
	if flags[1] {
		if !flags[2] {
			return fmt.Errorf("schema 57 marker exists but language column is missing")
		}
		return nil
	}
	if flags[2] {
		return fmt.Errorf("identity language column exists without schema 57 marker")
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v57", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_users ADD COLUMN language TEXT CHECK (language IS NULL OR language IN ('de','en','fr','ko','nb','nl','ru','uk','zhhans'))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(57)}},
	}})
	return err
}

// migrateSchemaV56 adds the identity timestamps used by user management.
// A zero created_at value is deliberately retained for legacy rows: it means
// that the creation time is unknown, rather than being inferred here.
func migrateSchemaV56(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT
			EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'identity_users'),
			EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version = 56),
			EXISTS(SELECT 1 FROM pragma_table_info('identity_users') WHERE name = 'created_at_unix_ms'),
			EXISTS(SELECT 1 FROM pragma_table_info('identity_users') WHERE name = 'last_login_at_unix_ms')`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 4 {
		return fmt.Errorf("unexpected schema 56 inspection result")
	}
	flag := func(v any) (bool, error) {
		n, ok := v.(int64)
		if !ok || (n != 0 && n != 1) {
			return false, fmt.Errorf("schema 56 inspection flag has type/value %T/%v", v, v)
		}
		return n == 1, nil
	}
	hasTable, marked, hasCreated, hasLastLogin := false, false, false, false
	for i, target := range []*bool{&hasTable, &marked, &hasCreated, &hasLastLogin} {
		value, flagErr := flag(state.Rows[0][i])
		if flagErr != nil {
			return flagErr
		}
		*target = value
	}
	if !hasTable {
		return fmt.Errorf("identity_users table is missing")
	}
	if marked {
		if !hasCreated || !hasLastLogin {
			return fmt.Errorf("schema 56 marker exists but identity metadata columns are incomplete")
		}
		return nil
	}
	if hasCreated || hasLastLogin {
		return fmt.Errorf("identity metadata columns exist without schema 56 marker")
	}

	statements := []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_users ADD COLUMN created_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (created_at_unix_ms >= 0)`},
		{SQL: `ALTER TABLE identity_users ADD COLUMN last_login_at_unix_ms INTEGER CHECK (last_login_at_unix_ms IS NULL OR last_login_at_unix_ms >= 0)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(56)}},
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v56", Statements: statements})
	return err
}

func migrateSchemaV55(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(55)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v55", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS kv_namespaces (name TEXT PRIMARY KEY NOT NULL, identity TEXT NOT NULL UNIQUE, public INTEGER NOT NULL DEFAULT 0 CHECK (public IN (0,1))) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS kv_values (namespace TEXT NOT NULL REFERENCES kv_namespaces(name) ON UPDATE CASCADE ON DELETE CASCADE, key TEXT NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0 CHECK (encrypted IN (0,1)), value BLOB NOT NULL, PRIMARY KEY(namespace,key)) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS kv_access (id TEXT PRIMARY KEY NOT NULL, namespace TEXT NOT NULL REFERENCES kv_namespaces(name) ON UPDATE CASCADE ON DELETE CASCADE, secret BLOB NOT NULL, secret_digest TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)), name TEXT) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS kv_access_namespace ON kv_access(namespace)`},
		{SQL: `INSERT OR IGNORE INTO kv_namespaces(name,identity,public) VALUES ('default','default',0)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(55)}},
	}})
	return err
}

func migrateSchemaV54(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(54)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v54", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS dcr_software_statement_trust (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			config_digest TEXT NOT NULL CHECK (length(config_digest) = 43 AND config_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			topology_digest TEXT NOT NULL CHECK (length(topology_digest) = 43 AND topology_digest NOT GLOB '*[^A-Za-z0-9_-]*')
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(54)}},
	}})
	return err
}

func migrateSchemaV53(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(53)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	table, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'dynamic_oauth_clients'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	// Some migration fixtures intentionally contain only the tables needed by
	// the migration under test. The dynamic-client table is created by v9 in a
	// complete database; preserve those fixtures by recording v53 when it is
	// absent rather than attempting an ALTER TABLE against a missing object.
	if len(table.Rows) == 0 {
		_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v53", SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(53)}})
		return err
	}
	column, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM pragma_table_info('dynamic_oauth_clients') WHERE name = 'software_statement'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	statements := make([]rhiza.SQLStatement, 0, 2)
	if len(column.Rows) == 0 {
		statements = append(statements, rhiza.SQLStatement{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN software_statement TEXT CHECK (software_statement IS NULL OR (length(software_statement) BETWEEN 1 AND 12288))`})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(53)}})
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v53", Statements: statements})
	return err
}

func migrateSchemaV52(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(52)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	shape, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_events' AND sql LIKE '%master_key_retirement.prepared%'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(shape.Rows) != 0 {
		_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v52-marker", SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(52)}})
		return err
	}
	table, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(table.Rows) == 0 {
		_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v52-marker", SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(52)}})
		return err
	}
	return executeSchemaV52Safely(ctx, db, schemaV52Request("goauthy-schema-v52"))
}

func executeSchemaV52Safely(ctx context.Context, db *rhiza.DB, request rhiza.ExecuteRequest) error {
	response, err := db.Execute(ctx, request)
	if err == nil {
		_, err = validateReceipt(request.RequestID, response)
		return err
	}
	if !errors.Is(err, rhiza.ErrCommitUnknown) {
		return err
	}
	status, statusErr := db.RequestStatus(ctx, rhiza.RequestStatusRequest{Kind: "sql", RequestID: request.RequestID})
	if statusErr != nil {
		return errors.Join(err, statusErr)
	}
	if status.State == "committed" || status.State == "rejected" {
		if status.Receipt == nil {
			return errors.Join(err, fmt.Errorf("rhiza mutation %q: %s status without receipt", request.RequestID, status.State))
		}
		response.MutationReceipt = *status.Receipt
		_, receiptErr := validateReceipt(request.RequestID, response)
		return receiptErr
	}
	marker, current, stateErr := schemaV52State(ctx, db)
	if stateErr != nil {
		return errors.Join(err, stateErr)
	}
	if marker && current {
		return nil
	}
	return errors.Join(err, fmt.Errorf("schema v52 commit unknown: marker=%t current_schema=%t", marker, current))
}

func schemaV52State(ctx context.Context, db *rhiza.DB) (marker, current bool, err error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS (SELECT 1 FROM goauthy_schema_migrations WHERE version = 52),
		EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_events' AND sql LIKE '%master_key_retirement.prepared%')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, false, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return false, false, fmt.Errorf("schema v52 reconciliation returned %d rows", len(result.Rows))
	}
	markerValue, markerOK := result.Rows[0][0].(int64)
	currentValue, currentOK := result.Rows[0][1].(int64)
	return markerOK && currentOK && markerValue == 1, markerOK && currentOK && currentValue == 1, nil
}

func schemaV52Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE audit_events_v52 (
			event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id)=43 AND event_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
			occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
			event_type TEXT NOT NULL CHECK (event_type IN ('api_key.created','api_key.updated','api_key.deleted','api_key.rotated','master_key_retirement.prepared','master_key_retirement.fenced','master_key_retirement.ready','master_key_retirement.aborted')),
			action TEXT NOT NULL CHECK (action IN ('create','update','delete','rotate','prepare','fence','ready','abort')),
			outcome TEXT NOT NULL CHECK (outcome='success'),
			actor_kind TEXT NOT NULL CHECK (actor_kind IN ('browser_admin','api_key')),
			actor_hash TEXT CHECK (actor_hash IS NULL OR (length(actor_hash)=43 AND actor_hash NOT GLOB '*[^A-Za-z0-9_-]*')),
			target_hash TEXT NOT NULL CHECK (length(target_hash)=43 AND target_hash NOT GLOB '*[^A-Za-z0-9_-]*'),
			CHECK ((event_type = 'api_key.created' AND action = 'create') OR
			       (event_type = 'api_key.updated' AND action = 'update') OR
			       (event_type = 'api_key.deleted' AND action = 'delete') OR
			       (event_type = 'api_key.rotated' AND action = 'rotate') OR
			       (event_type = 'master_key_retirement.prepared' AND action = 'prepare') OR
			       (event_type = 'master_key_retirement.fenced' AND action = 'fence') OR
			       (event_type = 'master_key_retirement.ready' AND action = 'ready') OR
			       (event_type = 'master_key_retirement.aborted' AND action = 'abort')),
			CHECK ((actor_kind = 'browser_admin' AND actor_hash IS NULL) OR
			       (actor_kind = 'api_key' AND actor_hash IS NOT NULL)),
			CHECK (event_type NOT LIKE 'master_key_retirement.%' OR actor_kind = 'api_key')
		) STRICT`},
		{SQL: `INSERT INTO audit_events_v52(sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash)
			SELECT sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash FROM audit_events ORDER BY sequence`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_append_only_update`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_append_only_delete`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_insert_existing_guard`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_insert_type_action_guard`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_insert_actor_guard`},
		{SQL: `DROP INDEX IF EXISTS audit_events_order`},
		{SQL: `DROP TABLE audit_events`},
		{SQL: `ALTER TABLE audit_events_v52 RENAME TO audit_events`},
		{SQL: `CREATE INDEX audit_events_order ON audit_events(sequence DESC)`},
		{SQL: `CREATE TRIGGER audit_events_append_only_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER audit_events_append_only_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER audit_events_insert_existing_guard BEFORE INSERT ON audit_events
			WHEN EXISTS (SELECT 1 FROM audit_events WHERE event_id = NEW.event_id OR sequence = NEW.sequence)
			BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER audit_events_insert_type_action_guard BEFORE INSERT ON audit_events
			WHEN NOT ((NEW.event_type = 'api_key.created' AND NEW.action = 'create') OR
			          (NEW.event_type = 'api_key.updated' AND NEW.action = 'update') OR
			          (NEW.event_type = 'api_key.deleted' AND NEW.action = 'delete') OR
			          (NEW.event_type = 'api_key.rotated' AND NEW.action = 'rotate') OR
			          (NEW.event_type = 'master_key_retirement.prepared' AND NEW.action = 'prepare') OR
			          (NEW.event_type = 'master_key_retirement.fenced' AND NEW.action = 'fence') OR
			          (NEW.event_type = 'master_key_retirement.ready' AND NEW.action = 'ready') OR
			          (NEW.event_type = 'master_key_retirement.aborted' AND NEW.action = 'abort'))
			BEGIN SELECT RAISE(ABORT, 'audit event type/action mismatch'); END`},
		{SQL: `CREATE TRIGGER audit_events_insert_actor_guard BEFORE INSERT ON audit_events
			WHEN (NEW.actor_kind = 'browser_admin' AND NEW.actor_hash IS NOT NULL) OR
			     (NEW.actor_kind = 'api_key' AND NEW.actor_hash IS NULL) OR
			     (NEW.event_type LIKE 'master_key_retirement.%' AND NEW.actor_kind <> 'api_key')
			BEGIN SELECT RAISE(ABORT, 'audit event actor mismatch'); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(52)}},
	}}
}

func migrateSchemaV51(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(51)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	table, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(table.Rows) == 0 {
		_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v51", Statements: []rhiza.SQLStatement{{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(51)}}}})
		return err
	}
	invalid, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM audit_events WHERE NOT (
		(event_type = 'api_key.created' AND action = 'create') OR
		(event_type = 'api_key.updated' AND action = 'update') OR
		(event_type = 'api_key.deleted' AND action = 'delete') OR
		(event_type = 'api_key.rotated' AND action = 'rotate')) OR
		(actor_kind = 'browser_admin' AND actor_hash IS NOT NULL) OR
		(actor_kind = 'api_key' AND actor_hash IS NULL) LIMIT 1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(invalid.Rows) != 0 {
		return errors.New("audit_events contains invalid cross-field data")
	}
	_, err = Execute(ctx, db, schemaV51Request("goauthy-schema-v51"))
	return err
}

func schemaV51Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TRIGGER IF NOT EXISTS audit_events_insert_existing_guard BEFORE INSERT ON audit_events
			WHEN EXISTS (SELECT 1 FROM audit_events WHERE event_id = NEW.event_id OR sequence = NEW.sequence)
			BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS audit_events_insert_type_action_guard BEFORE INSERT ON audit_events
			WHEN NOT ((NEW.event_type = 'api_key.created' AND NEW.action = 'create') OR
			          (NEW.event_type = 'api_key.updated' AND NEW.action = 'update') OR
			          (NEW.event_type = 'api_key.deleted' AND NEW.action = 'delete') OR
			          (NEW.event_type = 'api_key.rotated' AND NEW.action = 'rotate'))
			BEGIN SELECT RAISE(ABORT, 'audit event type/action mismatch'); END`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS audit_events_insert_actor_guard BEFORE INSERT ON audit_events
			WHEN (NEW.actor_kind = 'browser_admin' AND NEW.actor_hash IS NOT NULL) OR
			     (NEW.actor_kind = 'api_key' AND NEW.actor_hash IS NULL)
			BEGIN SELECT RAISE(ABORT, 'audit event actor mismatch'); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(51)}},
	}}
}

func migrateSchemaV50(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(50)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	column, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM pragma_table_info('master_key_retirement_members') WHERE name = 'attestation_sequence'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	statements := make([]rhiza.SQLStatement, 0, 4)
	if len(column.Rows) == 0 {
		statements = append(statements, rhiza.SQLStatement{SQL: `ALTER TABLE master_key_retirement_members ADD COLUMN attestation_sequence INTEGER NOT NULL DEFAULT 0 CHECK (attestation_sequence >= 0)`})
	}
	// v48 did not persist a sequence. One is the only safe deterministic
	// value for an existing attestation; pending rows remain at zero.
	statements = append(statements,
		rhiza.SQLStatement{SQL: `UPDATE master_key_retirement_members SET attestation_sequence = 1 WHERE attestation_state = 'attested' AND attestation_sequence = 0`},
		rhiza.SQLStatement{SQL: `CREATE UNIQUE INDEX IF NOT EXISTS master_key_retirement_attested_boot ON master_key_retirement_members(epoch, boot_id) WHERE attestation_state = 'attested'`},
		rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(50)}},
	)
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v50", Statements: statements})
	return err
}

func migrateSchemaV49(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(49)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	return executeSchemaV49Safely(ctx, db, schemaV49Request("goauthy-schema-v49"))
}

func executeSchemaV49Safely(ctx context.Context, db *rhiza.DB, request rhiza.ExecuteRequest) error {
	response, err := db.Execute(ctx, request)
	if err == nil {
		_, err = validateReceipt(request.RequestID, response)
		return err
	}
	if !errors.Is(err, rhiza.ErrCommitUnknown) {
		return err
	}
	status, statusErr := db.RequestStatus(ctx, rhiza.RequestStatusRequest{Kind: "sql", RequestID: request.RequestID})
	if statusErr != nil {
		return errors.Join(err, statusErr)
	}
	if status.State == "committed" || status.State == "rejected" {
		if status.Receipt == nil {
			return errors.Join(err, fmt.Errorf("rhiza mutation %q: %s status without receipt", request.RequestID, status.State))
		}
		response.MutationReceipt = *status.Receipt
		_, receiptErr := validateReceipt(request.RequestID, response)
		return receiptErr
	}
	// A destructive migration is never retried from an unknown/expired
	// receipt. Reconcile the marker and current table shape first; a later
	// startup may retry only after this invocation has safely stopped.
	marker, current, reconcileErr := schemaV49State(ctx, db)
	if reconcileErr != nil {
		return errors.Join(err, reconcileErr)
	}
	if marker && current {
		return nil
	}
	return errors.Join(err, fmt.Errorf("schema v49 commit unknown: marker=%t current_schema=%t", marker, current))
}

func schemaV49State(ctx context.Context, db *rhiza.DB) (marker, current bool, err error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
		EXISTS (SELECT 1 FROM goauthy_schema_migrations WHERE version = 49),
		EXISTS (SELECT 1 FROM pragma_table_info('audit_events') WHERE name = 'sequence')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, false, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return false, false, fmt.Errorf("schema v49 reconciliation returned %d rows", len(result.Rows))
	}
	markerValue, markerOK := result.Rows[0][0].(int64)
	currentValue, currentOK := result.Rows[0][1].(int64)
	return markerOK && currentOK && markerValue == 1, markerOK && currentOK && currentValue == 1, nil
}

func schemaV49Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE audit_events_v49 (
			event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id)=43 AND event_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
			occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
			event_type TEXT NOT NULL CHECK (event_type IN ('api_key.created','api_key.updated','api_key.deleted','api_key.rotated')),
			action TEXT NOT NULL CHECK (action IN ('create','update','delete','rotate')),
			outcome TEXT NOT NULL CHECK (outcome='success'),
			actor_kind TEXT NOT NULL CHECK (actor_kind IN ('browser_admin','api_key')),
			actor_hash TEXT CHECK (actor_hash IS NULL OR (length(actor_hash)=43 AND actor_hash NOT GLOB '*[^A-Za-z0-9_-]*')),
			target_hash TEXT NOT NULL CHECK (length(target_hash)=43 AND target_hash NOT GLOB '*[^A-Za-z0-9_-]*')
			, CHECK ((event_type = 'api_key.created' AND action = 'create') OR
			         (event_type = 'api_key.updated' AND action = 'update') OR
			         (event_type = 'api_key.deleted' AND action = 'delete') OR
			         (event_type = 'api_key.rotated' AND action = 'rotate'))
			, CHECK ((actor_kind = 'browser_admin' AND actor_hash IS NULL) OR
			         (actor_kind = 'api_key' AND actor_hash IS NOT NULL))
		) STRICT`},
		{SQL: `INSERT INTO audit_events_v49(sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash)
			SELECT ROW_NUMBER() OVER (ORDER BY occurred_at_unix_ms,event_id),event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash FROM audit_events`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_append_only_update`},
		{SQL: `DROP TRIGGER IF EXISTS audit_events_append_only_delete`},
		{SQL: `DROP INDEX IF EXISTS audit_events_order`},
		{SQL: `DROP TABLE audit_events`},
		{SQL: `ALTER TABLE audit_events_v49 RENAME TO audit_events`},
		{SQL: `CREATE INDEX audit_events_order ON audit_events(sequence DESC)`},
		{SQL: `CREATE TRIGGER audit_events_append_only_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER audit_events_append_only_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(49)}},
	}}
}

func migrateSchemaV48(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(48)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV48Request("goauthy-schema-v48"))
	return err
}

func schemaV48Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS master_key_retirement_barrier (
			barrier_id INTEGER PRIMARY KEY CHECK (barrier_id = 1),
			epoch INTEGER NOT NULL UNIQUE CHECK (epoch > 0),
			old_key_id TEXT NOT NULL CHECK (length(old_key_id) BETWEEN 1 AND 64 AND old_key_id NOT GLOB '*[^A-Za-z0-9._-]*'),
			replacement_key_id TEXT NOT NULL CHECK (length(replacement_key_id) BETWEEN 1 AND 64 AND replacement_key_id NOT GLOB '*[^A-Za-z0-9._-]*' AND replacement_key_id <> old_key_id),
			membership_digest TEXT NOT NULL CHECK (length(membership_digest) = 43 AND membership_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			state TEXT NOT NULL CHECK (state IN ('prepared', 'fenced', 'ready', 'aborted')),
			prepared_at_unix_ms INTEGER NOT NULL CHECK (prepared_at_unix_ms >= 0),
			fenced_at_unix_ms INTEGER CHECK (fenced_at_unix_ms IS NULL OR fenced_at_unix_ms >= prepared_at_unix_ms),
			ready_at_unix_ms INTEGER CHECK (ready_at_unix_ms IS NULL OR (fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms >= fenced_at_unix_ms)),
			aborted_at_unix_ms INTEGER CHECK (aborted_at_unix_ms IS NULL OR aborted_at_unix_ms >= prepared_at_unix_ms),
			CHECK ((state = 'prepared' AND fenced_at_unix_ms IS NULL AND ready_at_unix_ms IS NULL AND aborted_at_unix_ms IS NULL) OR
			       (state = 'fenced' AND fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NULL AND aborted_at_unix_ms IS NULL) OR
			       (state = 'ready' AND fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NOT NULL AND aborted_at_unix_ms IS NULL) OR
			       (state = 'aborted' AND aborted_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS master_key_retirement_members (
			epoch INTEGER NOT NULL,
			node_id TEXT NOT NULL CHECK (length(node_id) BETWEEN 1 AND 128 AND node_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
			attestation_state TEXT NOT NULL DEFAULT 'pending' CHECK (attestation_state IN ('pending', 'attested')),
			attestation_sequence INTEGER NOT NULL DEFAULT 0 CHECK (attestation_sequence >= 0),
			boot_id TEXT NOT NULL DEFAULT '' CHECK (length(boot_id) <= 128 AND boot_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
			active_key_id TEXT NOT NULL DEFAULT '' CHECK (length(active_key_id) <= 64 AND active_key_id NOT GLOB '*[^A-Za-z0-9._-]*'),
			attested_at_unix_ms INTEGER CHECK (attested_at_unix_ms IS NULL OR attested_at_unix_ms >= 0),
			old_references INTEGER NOT NULL DEFAULT 0 CHECK (old_references >= 0),
			non_active_references INTEGER NOT NULL DEFAULT 0 CHECK (non_active_references >= 0),
			legacy_references INTEGER NOT NULL DEFAULT 0 CHECK (legacy_references >= 0),
			tamper_references INTEGER NOT NULL DEFAULT 0 CHECK (tamper_references >= 0),
			oidc_references INTEGER NOT NULL DEFAULT 0 CHECK (oidc_references >= 0),
			dcr_references INTEGER NOT NULL DEFAULT 0 CHECK (dcr_references >= 0),
			upstream_references INTEGER NOT NULL DEFAULT 0 CHECK (upstream_references >= 0),
			passkey_enabled INTEGER NOT NULL DEFAULT 0 CHECK (passkey_enabled IN (0, 1)),
			passkey_references INTEGER NOT NULL DEFAULT 0 CHECK (passkey_references >= 0),
			PRIMARY KEY (epoch, node_id),
			FOREIGN KEY (epoch) REFERENCES master_key_retirement_barrier(epoch),
			CHECK ((attestation_state = 'pending' AND attestation_sequence = 0 AND boot_id = '' AND active_key_id = '' AND attested_at_unix_ms IS NULL) OR
			       (attestation_state = 'attested' AND attestation_sequence > 0 AND length(boot_id) BETWEEN 1 AND 128 AND length(active_key_id) BETWEEN 1 AND 64 AND attested_at_unix_ms IS NOT NULL))
		) STRICT`},
		{SQL: `CREATE UNIQUE INDEX IF NOT EXISTS master_key_retirement_attested_boot
			ON master_key_retirement_members(epoch, boot_id) WHERE attestation_state = 'attested'`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(48)}},
	}}
}

func migrateSchemaV47(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(47)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV47Request("goauthy-schema-v47"))
	return err
}

func schemaV47Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN logo_uri TEXT CHECK (logo_uri IS NULL OR (length(logo_uri) BETWEEN 1 AND 2048))`},
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN tos_uri TEXT CHECK (tos_uri IS NULL OR (length(tos_uri) BETWEEN 1 AND 2048))`},
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN policy_uri TEXT CHECK (policy_uri IS NULL OR (length(policy_uri) BETWEEN 1 AND 2048))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(47)}},
	}}
}

func migrateSchemaV46(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(46)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV46Request("goauthy-schema-v46"))
	return err
}

func schemaV46Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN contacts_json TEXT CHECK (contacts_json IS NULL OR (json_valid(contacts_json) AND json_type(contacts_json) = 'array'))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(46)}},
	}}
}

func migrateSchemaV45(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(45)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV45Request("goauthy-schema-v45"))
	return err
}

func schemaV45Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS audit_events (
			event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id)=43 AND event_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
			event_type TEXT NOT NULL CHECK (event_type IN ('api_key.created','api_key.updated','api_key.deleted','api_key.rotated')),
			action TEXT NOT NULL CHECK (action IN ('create','update','delete','rotate')),
			outcome TEXT NOT NULL CHECK (outcome='success'),
			actor_kind TEXT NOT NULL CHECK (actor_kind IN ('browser_admin','api_key')),
			actor_hash TEXT CHECK (actor_hash IS NULL OR (length(actor_hash)=43 AND actor_hash NOT GLOB '*[^A-Za-z0-9_-]*')),
			target_hash TEXT NOT NULL CHECK (length(target_hash)=43 AND target_hash NOT GLOB '*[^A-Za-z0-9_-]*')
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS audit_events_order ON audit_events(occurred_at_unix_ms DESC,event_id DESC)`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS audit_events_append_only_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS audit_events_append_only_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(45)}},
	}}
}

func migrateSchemaV44(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(44)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV44Request("goauthy-schema-v44"))
	return err
}

func schemaV44Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN client_uri TEXT CHECK (client_uri IS NULL OR (length(client_uri) BETWEEN 1 AND 2048))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(44)}},
	}}
}

func migrateSchemaV43(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(43)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV43Request("goauthy-schema-v43"))
	return err
}

func schemaV43Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS client_favicons (
			client_id TEXT PRIMARY KEY NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64 AND client_id NOT GLOB '*[^A-Za-z0-9._-]*'),
			content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/x-icon')),
			data BLOB NOT NULL CHECK (length(data) BETWEEN 1 AND 262144),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(43)}},
	}}
}

func migrateSchemaV42(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(42)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV42Request("goauthy-schema-v42"))
	return err
}

func schemaV42Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE scim_user_tombstones ADD COLUMN generation TEXT NOT NULL DEFAULT '' CHECK (length(generation) = 0 OR (length(generation) = 22 AND generation NOT GLOB '*[^A-Za-z0-9_-]*'))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(42)}},
	}}
}

func migrateSchemaV41(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(41)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV41Request("goauthy-schema-v41"))
	return err
}

func schemaV41Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE scim_user_tombstones ADD COLUMN provider_snapshot_complete INTEGER NOT NULL DEFAULT 0 CHECK (provider_snapshot_complete IN (0, 1))`},
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_tombstone_providers (
			local_external_id TEXT NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			delete_policy INTEGER NOT NULL CHECK (delete_policy IN (1, 2)),
			PRIMARY KEY (local_external_id, client_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_tombstone_providers_client
			ON scim_user_tombstone_providers(client_id, local_external_id)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(41)}},
	}}
}

func migrateSchemaV40(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(40)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV40Request("goauthy-schema-v40"))
	return err
}

func schemaV40Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN anonymous INTEGER NOT NULL DEFAULT 0 CHECK (anonymous IN (0, 1))`},
		{SQL: `CREATE INDEX IF NOT EXISTS dynamic_oauth_clients_anonymous_cleanup ON dynamic_oauth_clients(anonymous, created_at_unix_ms, client_id)`},
		{SQL: `CREATE INDEX IF NOT EXISTS dynamic_oauth_clients_anonymous_last_used_cleanup ON dynamic_oauth_clients(anonymous, last_used_at_unix_ms, client_id)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(40)}},
	}}
}

func migrateSchemaV39(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(39)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV39Request("goauthy-schema-v39"))
	return err
}

func schemaV39Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_tombstones (
			local_external_id TEXT PRIMARY KEY NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			user_name TEXT NOT NULL CHECK (length(user_name) BETWEEN 1 AND 254),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			hard_delete INTEGER NOT NULL DEFAULT 0 CHECK (hard_delete IN (0, 1)),
			deleted_at_unix_ms INTEGER NOT NULL CHECK (deleted_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_tombstones_deleted
			ON scim_user_tombstones(deleted_at_unix_ms, local_external_id)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(39)}},
	}}
}

func migrateSchemaV38(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(38)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV38Request("goauthy-schema-v38"))
	return err
}

func schemaV38Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_mappings (
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			local_external_id TEXT NOT NULL CHECK (length(local_external_id) BETWEEN 1 AND 512),
			remote_user_id TEXT NOT NULL CHECK (length(remote_user_id) BETWEEN 1 AND 512),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0),
			PRIMARY KEY (client_id, local_external_id),
			UNIQUE (client_id, remote_user_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_mappings_remote ON scim_user_mappings(client_id, remote_user_id)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(38)}},
	}}
}

func migrateSchemaV37(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(37)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV37Request("goauthy-schema-v37"))
	return err
}

func schemaV37Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS scim_user_outbox (
			job_id TEXT PRIMARY KEY NOT NULL CHECK (length(job_id) = 43 AND job_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(job_id, -1) GLOB '[AEIMQUYcgkosw048]'),
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			external_id TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
			request_json TEXT NOT NULL CHECK (length(request_json) BETWEEN 2 AND 16384 AND json_valid(request_json) AND json(request_json) = request_json),
			request_digest TEXT NOT NULL CHECK (length(request_digest) = 43 AND request_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(request_digest, -1) GLOB '[AEIMQUYcgkosw048]'),
			status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'succeeded', 'dead')),
			attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
			next_attempt_at_unix_ms INTEGER NOT NULL CHECK (next_attempt_at_unix_ms >= 0),
			revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
			lease_token TEXT,
			lease_until_unix_ms INTEGER,
			last_error TEXT,
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms),
			completed_at_unix_ms INTEGER,
			UNIQUE (client_id, external_id),
			CHECK ((status = 'processing') = (lease_token IS NOT NULL AND lease_until_unix_ms IS NOT NULL)),
			CHECK ((status IN ('succeeded', 'dead')) = (completed_at_unix_ms IS NOT NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_outbox_due
			ON scim_user_outbox(next_attempt_at_unix_ms, job_id)
			WHERE status IN ('pending', 'processing')`},
		{SQL: `CREATE INDEX IF NOT EXISTS scim_user_outbox_cleanup
			ON scim_user_outbox(completed_at_unix_ms, job_id)
			WHERE status IN ('succeeded', 'dead')`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(37)}},
	}}
}

func migrateSchemaV36(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(36)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV36Request("goauthy-schema-v36"))
	return err
}

func schemaV36Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `DROP INDEX IF EXISTS browser_sessions_expiry`},
		{SQL: `DROP INDEX IF EXISTS browser_sessions_last_seen`},
		{SQL: `CREATE TABLE browser_sessions_v36 (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			auth_method TEXT NOT NULL DEFAULT '' CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa', 'external')),
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			last_seen_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER,
			peer_ip TEXT NOT NULL DEFAULT ''
		) STRICT`},
		{SQL: `INSERT INTO browser_sessions_v36 (token_digest, subject, auth_method, created_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms, revoked_at_unix_ms, peer_ip)
			SELECT token_digest, subject, auth_method, created_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms, revoked_at_unix_ms, peer_ip FROM browser_sessions`},
		{SQL: `DROP TABLE browser_sessions`},
		{SQL: `ALTER TABLE browser_sessions_v36 RENAME TO browser_sessions`},
		{SQL: `CREATE INDEX browser_sessions_expiry ON browser_sessions(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX browser_sessions_last_seen ON browser_sessions(last_seen_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(36)}},
	}}
}

func migrateSchemaV35(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(35)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV35Request("goauthy-schema-v35"))
	return err
}

func schemaV35Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS upstream_provider_transactions (
			state_digest TEXT PRIMARY KEY NOT NULL CHECK (length(state_digest) = 43 AND state_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(state_digest, -1) GLOB '[AEIMQUYcgkosw048]'),
			browser_binding_digest TEXT NOT NULL CHECK (length(browser_binding_digest) = 43 AND browser_binding_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(browser_binding_digest, -1) GLOB '[AEIMQUYcgkosw048]'),
			provider_id TEXT NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 64),
			secret_envelope TEXT NOT NULL CHECK (length(secret_envelope) BETWEEN 1 AND 4096),
			issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
			audience TEXT NOT NULL CHECK (length(audience) <= 1024),
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			scopes_json TEXT NOT NULL CHECK (length(scopes_json) BETWEEN 2 AND 4096 AND json_valid(scopes_json) AND json_type(scopes_json) = 'array' AND json(scopes_json) = scopes_json),
			callback_uri TEXT NOT NULL CHECK (length(callback_uri) BETWEEN 1 AND 2048),
			purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link')),
			link_subject TEXT CHECK (link_subject IS NULL OR length(link_subject) BETWEEN 1 AND 512),
			link_session_digest TEXT CHECK (link_session_digest IS NULL OR (length(link_session_digest) = 43 AND link_session_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(link_session_digest, -1) GLOB '[AEIMQUYcgkosw048]')),
			session_digest TEXT CHECK (session_digest IS NULL OR (length(session_digest) = 43 AND session_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(session_digest, -1) GLOB '[AEIMQUYcgkosw048]')),
			interaction_digest TEXT CHECK (interaction_digest IS NULL OR (length(interaction_digest) = 43 AND interaction_digest NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(interaction_digest, -1) GLOB '[AEIMQUYcgkosw048]')),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > created_at_unix_ms),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR (length(consumed_attempt) = 22 AND consumed_attempt NOT GLOB '*[^A-Za-z0-9_-]*')),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= created_at_unix_ms),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL)),
			CHECK ((purpose = 'login' AND link_subject IS NULL AND link_session_digest IS NULL) OR (purpose = 'link' AND link_subject IS NOT NULL AND link_session_digest IS NOT NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS upstream_provider_transactions_expiry ON upstream_provider_transactions(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS upstream_provider_transactions_provider_expiry ON upstream_provider_transactions(provider_id, expires_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_external_links (
			provider_id TEXT NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 64),
			external_key TEXT NOT NULL CHECK (length(external_key) = 43 AND external_key NOT GLOB '*[^A-Za-z0-9_-]*'),
			local_subject TEXT NOT NULL CHECK (length(local_subject) BETWEEN 1 AND 512),
			linked_at_unix_ms INTEGER NOT NULL CHECK (linked_at_unix_ms >= 0),
			PRIMARY KEY (provider_id, external_key),
			UNIQUE (local_subject, provider_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_external_links_subject ON identity_external_links(local_subject)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(35)}},
	}}
}

func migrateSchemaV34(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(34)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV34Request("goauthy-schema-v34"))
	return err
}

func schemaV34Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS dcr_registration_idempotency (
			principal_digest TEXT NOT NULL CHECK (length(principal_digest) = 43 AND principal_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			key_digest TEXT NOT NULL CHECK (length(key_digest) = 43 AND key_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			request_digest TEXT NOT NULL CHECK (length(request_digest) = 43 AND request_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
			response_envelope TEXT NOT NULL CHECK (length(response_envelope) > 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > 0),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			PRIMARY KEY (principal_digest, key_digest)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS dcr_registration_idempotency_expiry ON dcr_registration_idempotency(expires_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(34)}},
	}}
}

func migrateSchemaV30(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(30)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV30Request("goauthy-schema-v30"))
	return err
}

func schemaV30Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_password_reset_pow_issuance_limits (
			peer_digest TEXT PRIMARY KEY NOT NULL CHECK (length(peer_digest) = 43 AND peer_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
			window_start_unix_seconds INTEGER NOT NULL CHECK (window_start_unix_seconds >= 0),
			count INTEGER NOT NULL CHECK (count BETWEEN 1 AND 5)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(30)}},
	}}
}

func migrateSchemaV31(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(31)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV31Request("goauthy-schema-v31"))
	return err
}

func schemaV31Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE browser_sessions ADD COLUMN peer_ip TEXT NOT NULL DEFAULT ''`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(31)}},
	}}
}

func migrateSchemaV32(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(32)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV32Request("goauthy-schema-v32"))
	return err
}

func schemaV32Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS ip_blacklist_entries (
			prefix TEXT PRIMARY KEY NOT NULL CHECK (length(prefix) > 0),
			note TEXT NOT NULL DEFAULT '' CHECK (length(note) BETWEEN 0 AND 256),
			expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms > 0),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(32)}},
	}}
}

func migrateSchemaV33(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(33)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV33Request("goauthy-schema-v33"))
	return err
}

func schemaV33Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE oauth_rate_limits_new (
			key_digest TEXT PRIMARY KEY NOT NULL,
			window_start_unix_ms INTEGER NOT NULL CHECK (window_start_unix_ms >= 0),
			count INTEGER NOT NULL CHECK (count >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > 0),
			last_window_at_unix_ms INTEGER NOT NULL CHECK (last_window_at_unix_ms >= 0),
			CHECK (expires_at_unix_ms > last_window_at_unix_ms)
		) STRICT`},
		{SQL: `INSERT INTO oauth_rate_limits_new (key_digest,window_start_unix_ms,count,expires_at_unix_ms,last_window_at_unix_ms) SELECT key_digest,window_start_unix_ms,count,window_start_unix_ms + 86400000,window_start_unix_ms FROM oauth_rate_limits`},
		{SQL: `DROP TABLE oauth_rate_limits`},
		{SQL: `ALTER TABLE oauth_rate_limits_new RENAME TO oauth_rate_limits`},
		{SQL: `CREATE INDEX IF NOT EXISTS oauth_rate_limits_expiry ON oauth_rate_limits(expires_at_unix_ms)`},
		{SQL: `CREATE TRIGGER oauth_rate_limits_cleanup BEFORE INSERT ON oauth_rate_limits BEGIN DELETE FROM oauth_rate_limits WHERE key_digest IN (SELECT key_digest FROM oauth_rate_limits WHERE expires_at_unix_ms <= NEW.last_window_at_unix_ms AND key_digest != NEW.key_digest ORDER BY expires_at_unix_ms,key_digest LIMIT 64); END`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(33)}},
	}}
}

func migrateSchemaV29(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(29)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV29Request("goauthy-schema-v29"))
	return err
}

func schemaV29Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS bootstrap_client_credentials_claims (
			client_id TEXT PRIMARY KEY NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
			claims_json TEXT CHECK (claims_json IS NULL OR (length(claims_json) BETWEEN 1 AND 1024 AND json_valid(claims_json) AND json_type(claims_json) = 'object' AND json(claims_json) = claims_json)),
			claims_at_root INTEGER NOT NULL DEFAULT 0 CHECK (claims_at_root IN (0, 1)),
			revision INTEGER NOT NULL CHECK (revision >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(29)}},
	}}
}

func migrateSchemaV28(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(28)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 0 {
		return err
	}
	_, err = Execute(ctx, db, schemaV28Request("goauthy-schema-v28"))
	return err
}

func schemaV28Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS api_keys (name TEXT PRIMARY KEY NOT NULL CHECK (length(name) BETWEEN 2 AND 24 AND name NOT GLOB '*[^A-Za-z0-9_/-]*'), secret_digest TEXT NOT NULL CHECK (length(secret_digest)=43 AND secret_digest NOT GLOB '*[^A-Za-z0-9_-]*'), created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0), expires_at_unix_ms INTEGER CHECK (expires_at_unix_ms IS NULL OR expires_at_unix_ms >= 0)) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS api_key_access (key_name TEXT NOT NULL, group_name TEXT NOT NULL CHECK (group_name IN ('Blacklist','Clients','Events','Generic','Groups','Roles','Secrets','Sessions','Scopes','UserAttributes','Users','Pam','AuthProviders','ApiKeys')), right_name TEXT NOT NULL CHECK (right_name IN ('read','create','update','delete')), PRIMARY KEY (key_name, group_name, right_name)) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS api_key_mutation_guards (request_id TEXT PRIMARY KEY NOT NULL CHECK (length(request_id) BETWEEN 1 AND 64)) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS api_keys_expiry ON api_keys(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS api_key_access_lookup ON api_key_access(key_name, group_name, right_name)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(28)}},
	}}
}

func migrateSchemaV27(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(27)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV27Request("goauthy-schema-v27"))
	return err
}

func schemaV27Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN default_scopes_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(default_scopes_json) AND json_type(default_scopes_json) = 'array')`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(27)}},
	}}
}

func migrateSchemaV26(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(26)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV26Request("goauthy-schema-v26"))
	return err
}

func schemaV26Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS claims_catalog (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			revision INTEGER NOT NULL CHECK (revision >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO claims_catalog (id, revision) VALUES (1, 0)`},
		{SQL: `CREATE TABLE IF NOT EXISTS user_attribute_configs (
			name TEXT PRIMARY KEY NOT NULL CHECK (length(name) BETWEEN 2 AND 32),
			desc TEXT CHECK (desc IS NULL OR length(desc) BETWEEN 1 AND 128),
			default_value_json TEXT CHECK (default_value_json IS NULL OR (length(default_value_json) BETWEEN 1 AND 8192 AND json_valid(default_value_json) AND json(default_value_json) = default_value_json)),
			typ TEXT CHECK (typ IS NULL OR typ IN ('email')),
			user_editable INTEGER NOT NULL DEFAULT 0 CHECK (user_editable IN (0, 1)),
			revision INTEGER NOT NULL CHECK (revision >= 1),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS user_attribute_values (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			key TEXT NOT NULL CHECK (length(key) BETWEEN 2 AND 32),
			value_json TEXT NOT NULL CHECK (length(value_json) BETWEEN 1 AND 8192 AND json_valid(value_json) AND json(value_json) = value_json),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0),
			PRIMARY KEY (subject, key)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS user_attribute_values_key_subject ON user_attribute_values(key, subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS custom_scopes (
			name TEXT PRIMARY KEY NOT NULL CHECK (length(name) BETWEEN 2 AND 64),
			attr_include_access_json TEXT NOT NULL CHECK (json_valid(attr_include_access_json) AND json_type(attr_include_access_json) = 'array'),
			attr_include_id_json TEXT NOT NULL CHECK (json_valid(attr_include_id_json) AND json_type(attr_include_id_json) = 'array'),
			claims_at_root INTEGER NOT NULL DEFAULT 0 CHECK (claims_at_root IN (0, 1)),
			revision INTEGER NOT NULL CHECK (revision >= 1)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS bootstrap_client_claim_scopes (
			client_id TEXT PRIMARY KEY NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
			allowed_scopes_json TEXT NOT NULL CHECK (json_valid(allowed_scopes_json) AND json_type(allowed_scopes_json) = 'array'),
			default_scopes_json TEXT NOT NULL CHECK (json_valid(default_scopes_json) AND json_type(default_scopes_json) = 'array'),
			revision INTEGER NOT NULL CHECK (revision >= 1)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(26)}},
	}}
}

func migrateSchemaV25(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(25)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV25Request("goauthy-schema-v25"))
	return err
}

func schemaV25Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS bootstrap_client_login_restrictions (
			client_id TEXT PRIMARY KEY NOT NULL CHECK (length(client_id) BETWEEN 1 AND 64),
			restrict_group_prefix TEXT CHECK (restrict_group_prefix IS NULL OR length(restrict_group_prefix) BETWEEN 2 AND 64),
			revision INTEGER NOT NULL CHECK (revision >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(25)}},
	}}
}

// migrateSchemaV24 adds locally-enforced RBAC state. Rhiza does not enforce
// SQLite foreign keys, so stores must validate referenced IDs transactionally.
func migrateSchemaV24(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(24)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV24Request("goauthy-schema-v24"))
	return err
}

func schemaV24Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_roles (
			id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 64),
			name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 64),
			meta_json TEXT CHECK (meta_json IS NULL OR (length(meta_json) BETWEEN 2 AND 8192 AND json_valid(meta_json) AND json(meta_json) = meta_json)),
			revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_groups (
			id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 64),
			name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 64),
			meta_json TEXT CHECK (meta_json IS NULL OR (length(meta_json) BETWEEN 2 AND 8192 AND json_valid(meta_json) AND json(meta_json) = meta_json)),
			revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_user_roles (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			role_id TEXT NOT NULL CHECK (length(role_id) BETWEEN 1 AND 64),
			granted_at_unix_ms INTEGER NOT NULL CHECK (granted_at_unix_ms >= 0),
			PRIMARY KEY (subject, role_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS rbac_user_roles_role_id_subject ON rbac_user_roles(role_id, subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_user_groups (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			group_id TEXT NOT NULL CHECK (length(group_id) BETWEEN 1 AND 64),
			granted_at_unix_ms INTEGER NOT NULL CHECK (granted_at_unix_ms >= 0),
			PRIMARY KEY (subject, group_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS rbac_user_groups_group_id_subject ON rbac_user_groups(group_id, subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS rbac_principal_versions (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			revision INTEGER NOT NULL CHECK (revision >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(24)}},
	}}
}

// migrateSchemaV23 separates initial-password links from reset links and
// retains the open-registration profile until the first password is chosen.
func migrateSchemaV23(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(23)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV23Request("goauthy-schema-v23"))
	return err
}

func schemaV23Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_password_reset_tokens ADD COLUMN usage TEXT NOT NULL DEFAULT 'password_reset' CHECK (usage IN ('password_reset', 'password_new'))`},
		{SQL: `ALTER TABLE identity_password_reset_tokens ADD COLUMN redirect_uri TEXT CHECK (redirect_uri IS NULL OR (length(redirect_uri) BETWEEN 1 AND 2048 AND instr(redirect_uri, char(13)) = 0 AND instr(redirect_uri, char(10)) = 0))`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_user_profiles (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254 AND email = lower(email)),
			email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
			preferred_username TEXT CHECK (preferred_username IS NULL OR length(preferred_username) BETWEEN 1 AND 128),
			given_name TEXT CHECK (given_name IS NULL OR length(given_name) BETWEEN 1 AND 32),
			family_name TEXT CHECK (family_name IS NULL OR length(family_name) BETWEEN 1 AND 32),
			user_values_json TEXT CHECK (user_values_json IS NULL OR (length(user_values_json) BETWEEN 2 AND 8192 AND json_valid(user_values_json)))
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(23)}},
	}}
}

// migrateSchemaV22 records an authenticated browser session's authentication
// method. Existing authenticated sessions are revoked rather than guessed.
func migrateSchemaV22(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(22)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV22Request("goauthy-schema-v22"))
	return err
}

func schemaV22Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE browser_sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT '' CHECK (auth_method IN ('', 'pwd', 'webauthn', 'mfa'))`},
		{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms = COALESCE(revoked_at_unix_ms, created_at_unix_ms) WHERE subject <> ''`},
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN force_mfa INTEGER NOT NULL DEFAULT 0 CHECK (force_mfa IN (0, 1))`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(22)}},
	}}
}

// migrateSchemaV21 gives service WebAuthn ceremonies and proofs an explicit
// purpose. Legacy v20 rows intentionally remain unmarked and fail closed.
func migrateSchemaV21(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(21)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV21Request("goauthy-schema-v21"))
	return err
}

func schemaV21Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_service_ceremony_purposes (
			code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 43),
			purpose TEXT NOT NULL CHECK (purpose IN ('MfaModToken', 'PasswordNew'))
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_service_proof_purposes (
			code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 43),
			purpose TEXT NOT NULL CHECK (purpose IN ('MfaModToken', 'PasswordNew'))
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(21)}},
	}}
}

// migrateSchemaV20 separates a WebAuthn step-up ceremony from the short-lived
// proof it produces. Keeping both purpose-specific avoids overloading login
// ceremonies or making a pre-assertion challenge redeemable as MFA proof.
func migrateSchemaV20(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(20)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV20Request("goauthy-schema-v20"))
	return err
}

func schemaV20Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_mfa_ceremonies (
			code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			session_digest TEXT NOT NULL CHECK (length(session_digest) = 43),
			session_json TEXT NOT NULL CHECK (length(session_json) > 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
			proof_expires_at_unix_ms INTEGER NOT NULL CHECK (proof_expires_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_mfa_ceremonies_expiry
			ON identity_webauthn_mfa_ceremonies(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_mfa_ceremonies_subject
			ON identity_webauthn_mfa_ceremonies(subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_mfa_proofs (
			code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			session_digest TEXT NOT NULL CHECK (length(session_digest) = 43),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_mfa_proofs_expiry
			ON identity_webauthn_mfa_proofs(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_mfa_proofs_subject
			ON identity_webauthn_mfa_proofs(subject)`},
		// Existing tokens deliberately have no row and therefore fail closed;
		// new tokens must record the factor that authorized their issuance.
		{SQL: `CREATE TABLE IF NOT EXISTS identity_mfa_mod_token_factors (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			proof_kind TEXT NOT NULL CHECK (proof_kind IN ('password', 'webauthn'))
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(20)}},
	}}
}

// migrateSchemaV19 records the credential admission mode separately from the
// password hash. The hash remains non-null in the legacy identity table, while
// every password entry point must admit it only when mode is password.
func migrateSchemaV19(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(19)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV19Request("goauthy-schema-v19"))
	return err
}

func schemaV19Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_authentication_modes (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			mode TEXT NOT NULL CHECK (mode IN ('password', 'passkey')),
			generation INTEGER NOT NULL CHECK (generation >= 1),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		// Existing local accounts retain password admission until an explicit,
		// generation-guarded conversion changes this row.
		{SQL: `INSERT OR IGNORE INTO identity_authentication_modes (subject, mode, generation, updated_at_unix_ms)
			SELECT subject, 'password', 1, 0 FROM identity_users`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(19)}},
	}}
}

func migrateSchemaV18(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(18)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV18Request("goauthy-schema-v18"))
	return err
}

func schemaV18Request(requestID string) rhiza.ExecuteRequest {
	// credential_version gives credential updates a deterministic CAS guard.
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_users (
			subject TEXT PRIMARY KEY NOT NULL,
			user_handle TEXT NOT NULL UNIQUE CHECK (length(user_handle) = 43),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_credentials (
			credential_id TEXT PRIMARY KEY NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 2048),
			subject TEXT NOT NULL,
			name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 32),
			credential_json TEXT NOT NULL CHECK (length(credential_json) > 0),
			sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
			credential_version INTEGER NOT NULL DEFAULT 0 CHECK (credential_version >= 0),
			user_verified INTEGER NOT NULL CHECK (user_verified IN (0, 1)),
			registered_at_unix_ms INTEGER NOT NULL CHECK (registered_at_unix_ms >= 0),
			last_used_at_unix_ms INTEGER NOT NULL CHECK (last_used_at_unix_ms >= 0),
			UNIQUE (subject, name)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_credentials_subject
			ON identity_webauthn_credentials(subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_webauthn_ceremonies (
			code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 43),
			purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
			subject TEXT NOT NULL,
			session_digest TEXT NOT NULL CHECK (length(session_digest) = 43),
			interaction_digest TEXT CHECK (interaction_digest IS NULL OR length(interaction_digest) = 43),
			passkey_name TEXT CHECK (passkey_name IS NULL OR length(passkey_name) BETWEEN 1 AND 32),
			session_json TEXT NOT NULL CHECK (length(session_json) > 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL)),
			CHECK ((purpose = 'register' AND interaction_digest IS NULL AND passkey_name IS NOT NULL) OR
				(purpose = 'login' AND interaction_digest IS NOT NULL AND passkey_name IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_ceremonies_expiry
			ON identity_webauthn_ceremonies(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_webauthn_ceremonies_subject
			ON identity_webauthn_ceremonies(subject)`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_mfa_mod_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) > 0),
			session_digest TEXT NOT NULL CHECK (length(session_digest) = 43),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_mfa_mod_tokens_expiry
			ON identity_mfa_mod_tokens(expires_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(18)}},
	}}
}

func migrateSchemaV17(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(17)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV17Request("goauthy-schema-v17"))
	return err
}

func schemaV17Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_password_reset_pow_challenges (
			challenge TEXT PRIMARY KEY NOT NULL CHECK (length(challenge) = 43),
			expires_at_unix_seconds INTEGER NOT NULL CHECK (expires_at_unix_seconds >= 0),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_seconds INTEGER CHECK (consumed_at_unix_seconds IS NULL OR consumed_at_unix_seconds >= 0),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_seconds IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_password_reset_pow_challenges_expiry
			ON identity_password_reset_pow_challenges(expires_at_unix_seconds)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(17)}},
	}}
}

func migrateSchemaV16(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(16)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV16Request("goauthy-schema-v16"))
	return err
}

func schemaV16Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_recovery_emails (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254),
			CHECK (email = lower(email))
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(16)}},
	}}
}

func migrateSchemaV15(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(15)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV15Request("goauthy-schema-v15"))
	return err
}

func schemaV15Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_password_reset_tokens (
			token_digest TEXT PRIMARY KEY NOT NULL CHECK (length(token_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			password_generation INTEGER NOT NULL CHECK (password_generation >= 1),
			issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
			binding_digest TEXT CHECK (binding_digest IS NULL OR length(binding_digest) = 43),
			bound_at_unix_ms INTEGER CHECK (bound_at_unix_ms IS NULL OR bound_at_unix_ms >= issued_at_unix_ms),
			consumed_attempt TEXT CHECK (consumed_attempt IS NULL OR length(consumed_attempt) = 22),
			consumed_at_unix_ms INTEGER CHECK (consumed_at_unix_ms IS NULL OR consumed_at_unix_ms >= issued_at_unix_ms),
			CHECK ((binding_digest IS NULL) = (bound_at_unix_ms IS NULL)),
			CHECK ((consumed_attempt IS NULL) = (consumed_at_unix_ms IS NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_password_reset_tokens_expiry
			ON identity_password_reset_tokens(expires_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(15)}},
	}}
}

func migrateSchemaV14(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(14)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV14Request("goauthy-schema-v14"))
	return err
}

func schemaV14Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_users ADD COLUMN password_changed_at_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (password_changed_at_unix_ms >= 0)`},
		{SQL: `ALTER TABLE identity_users ADD COLUMN password_generation INTEGER NOT NULL DEFAULT 1 CHECK (password_generation >= 1)`},
		{SQL: `CREATE TABLE identity_password_history (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			generation INTEGER NOT NULL CHECK (generation >= 1),
			password_phc TEXT NOT NULL CHECK (length(password_phc) BETWEEN 1 AND 512),
			changed_at_unix_ms INTEGER NOT NULL CHECK (changed_at_unix_ms >= 0),
			PRIMARY KEY (subject, generation)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(14)}},
	}}
}

func migrateSchemaV13(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(13)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV13Request("goauthy-schema-v13"))
	return err
}

func schemaV13Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS cimd_client_documents (
			client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 2048),
			policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 43),
			metadata_json TEXT NOT NULL CHECK (length(metadata_json) BETWEEN 2 AND 8192 AND json_valid(metadata_json)),
			metadata_digest TEXT NOT NULL CHECK (length(metadata_digest) = 43),
			fetched_at_unix_ms INTEGER NOT NULL CHECK (fetched_at_unix_ms >= 0),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > fetched_at_unix_ms),
			PRIMARY KEY (client_id, policy_digest)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS cimd_client_documents_expiry ON cimd_client_documents(expires_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(13)}},
	}}
}

func migrateSchemaV12(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(12)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV12Request("goauthy-schema-v12"))
	return err
}

func schemaV12Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS login_ip_failures (
			key_digest TEXT PRIMARY KEY NOT NULL,
			failures INTEGER NOT NULL CHECK (failures >= 0),
			blocked_until_unix_ms INTEGER NOT NULL CHECK (blocked_until_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS login_ip_failures_updated ON login_ip_failures(updated_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS login_timing (
			id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
			success_mean_unix_ms INTEGER NOT NULL CHECK (success_mean_unix_ms > 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(12)}},
	}}
}

func migrateSchemaV11(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(11)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV11Request("goauthy-schema-v11"))
	return err
}

func schemaV11Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS dpop_nonces (
			nonce_digest TEXT PRIMARY KEY NOT NULL,
			client_id TEXT NOT NULL,
			jkt TEXT NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			consumed_attempt TEXT,
			created_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS dpop_nonces_expiry ON dpop_nonces(expires_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS dpop_replays (
			replay_digest TEXT PRIMARY KEY NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			created_attempt TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS dpop_replays_expiry ON dpop_replays(expires_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(11)}},
	}}
}

func migrateSchemaV10(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(10)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV10Request("goauthy-schema-v10"))
	return err
}

func schemaV10Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_device_grants (
			device_code_digest TEXT PRIMARY KEY NOT NULL,
			user_code_digest TEXT NOT NULL UNIQUE,
			client_id TEXT NOT NULL,
			scopes_json TEXT NOT NULL,
			subject TEXT,
			state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'consumed')),
			decision_attempt TEXT,
			expires_at_unix_ms INTEGER NOT NULL,
			interval_seconds INTEGER NOT NULL CHECK (interval_seconds >= 5 AND interval_seconds <= 60),
			next_poll_at_unix_ms INTEGER NOT NULL,
			claim_token_digest TEXT,
			claim_until_unix_ms INTEGER,
			created_at_unix_ms INTEGER NOT NULL,
			CHECK ((state = 'approved' AND subject IS NOT NULL) OR (state != 'approved')),
			CHECK ((claim_token_digest IS NULL AND claim_until_unix_ms IS NULL) OR (claim_token_digest IS NOT NULL AND claim_until_unix_ms IS NOT NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS oauth_device_grants_expiry ON oauth_device_grants(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS oauth_device_grants_user_code ON oauth_device_grants(user_code_digest)`},
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_rate_limits (
			key_digest TEXT PRIMARY KEY NOT NULL,
			window_start_unix_ms INTEGER NOT NULL,
			count INTEGER NOT NULL CHECK (count >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(10)}},
	}}
}

func migrateSchemaV9(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(9)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV9Request("goauthy-schema-v9"))
	return err
}

func schemaV9Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS dynamic_oauth_clients (
			client_id TEXT PRIMARY KEY NOT NULL,
			secret_hash TEXT,
			registration_token_digest TEXT NOT NULL UNIQUE,
			redirect_uris_json TEXT NOT NULL,
			scopes_json TEXT NOT NULL,
			grant_types_json TEXT NOT NULL,
			response_types_json TEXT NOT NULL,
			audiences_json TEXT NOT NULL,
			token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post')),
			name TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			last_used_at_unix_ms INTEGER,
			CHECK ((token_endpoint_auth_method = 'none' AND secret_hash IS NULL) OR
			       (token_endpoint_auth_method != 'none' AND secret_hash IS NOT NULL))
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS dynamic_oauth_clients_last_used
			ON dynamic_oauth_clients(last_used_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(9)}},
	}}
}

func migrateSchemaV8(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(8)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV8Request("goauthy-schema-v8"))
	return err
}

func schemaV8Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS oidc_session_clients (
			sid TEXT NOT NULL,
			client_id TEXT NOT NULL,
			logout_uri TEXT NOT NULL,
			allow_private INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			allow_http INTEGER NOT NULL CHECK (allow_http IN (0, 1)),
			created_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (sid, client_id)
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS oidc_backchannel_deliveries (
			event_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			sid TEXT NOT NULL,
			logout_uri TEXT NOT NULL,
			allow_private INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			allow_http INTEGER NOT NULL CHECK (allow_http IN (0, 1)),
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at_unix_ms INTEGER NOT NULL,
			lease_token TEXT,
			lease_until_unix_ms INTEGER,
			delivered_at_unix_ms INTEGER,
			failed_at_unix_ms INTEGER,
			last_error TEXT,
			created_at_unix_ms INTEGER NOT NULL,
			PRIMARY KEY (event_id, client_id),
			UNIQUE (sid, client_id)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS oidc_backchannel_deliveries_due
			ON oidc_backchannel_deliveries(next_attempt_at_unix_ms)
			WHERE delivered_at_unix_ms IS NULL AND failed_at_unix_ms IS NULL`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(8)}},
	}}
}

func migrateSchemaV7(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(7)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, schemaV7Request("goauthy-schema-v7"))
	return err
}

func schemaV7Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE browser_sessions ADD COLUMN last_seen_at_unix_ms INTEGER NOT NULL DEFAULT 0`},
		{SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = created_at_unix_ms WHERE last_seen_at_unix_ms = 0`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_sessions_last_seen ON browser_sessions(last_seen_at_unix_ms)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(7)}},
	}}
}

func schemaV6Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_users (
			subject TEXT PRIMARY KEY NOT NULL,
			username TEXT NOT NULL UNIQUE,
			password_phc TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS browser_sessions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			revoked_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_sessions_expiry ON browser_sessions(expires_at_unix_ms)`},
		{SQL: `CREATE TABLE IF NOT EXISTS browser_authorization_interactions (
			token_digest TEXT PRIMARY KEY NOT NULL,
			request_id TEXT NOT NULL UNIQUE,
			session_digest TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL,
			consumed_attempt TEXT,
			consumed_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_authorization_interactions_expiry ON browser_authorization_interactions(expires_at_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS browser_authorization_interactions_session ON browser_authorization_interactions(session_digest)`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(6)}},
	}}
}

func migrateSchemaV5(ctx context.Context, db *rhiza.DB) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM goauthy_schema_migrations WHERE version = ?`, Args: []any{int64(5)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 0 {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v5", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE oidc_signing_keys_v5 (
			kid TEXT PRIMARY KEY NOT NULL,
			public_jwk TEXT NOT NULL,
			private_envelope TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('active', 'pending', 'retiring')),
			created_at_unix_ms INTEGER NOT NULL,
			activates_after_unix_ms INTEGER,
			retire_after_unix_ms INTEGER,
			CHECK ((state = 'active' AND activates_after_unix_ms IS NULL AND retire_after_unix_ms IS NULL) OR
			       (state = 'pending' AND activates_after_unix_ms IS NOT NULL AND retire_after_unix_ms IS NULL) OR
			       (state = 'retiring' AND activates_after_unix_ms IS NULL AND retire_after_unix_ms IS NOT NULL))
		) STRICT`},
		{SQL: `INSERT INTO oidc_signing_keys_v5
			(kid, public_jwk, private_envelope, state, created_at_unix_ms, activates_after_unix_ms, retire_after_unix_ms)
			SELECT kid, public_jwk, private_envelope, state, created_at_unix_ms, NULL, retire_after_unix_ms FROM oidc_signing_keys`},
		{SQL: `DROP INDEX IF EXISTS oidc_signing_keys_one_active`},
		{SQL: `DROP TABLE oidc_signing_keys`},
		{SQL: `ALTER TABLE oidc_signing_keys_v5 RENAME TO oidc_signing_keys`},
		{SQL: `CREATE UNIQUE INDEX oidc_signing_keys_one_active ON oidc_signing_keys(state) WHERE state = 'active'`},
		{SQL: `CREATE UNIQUE INDEX oidc_signing_keys_one_pending ON oidc_signing_keys(state) WHERE state = 'pending'`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(5)}},
	}})
	return err
}

func schemaV2Request(requestID string) rhiza.ExecuteRequest {
	return rhiza.ExecuteRequest{
		RequestID: requestID,
		Statements: []rhiza.SQLStatement{
			{SQL: `CREATE TABLE IF NOT EXISTS oidc_signing_keys (
				kid TEXT PRIMARY KEY NOT NULL,
				public_jwk TEXT NOT NULL,
				private_envelope TEXT NOT NULL,
				state TEXT NOT NULL CHECK (state IN ('active', 'retiring')),
				created_at_unix_ms INTEGER NOT NULL,
				retire_after_unix_ms INTEGER,
				CHECK ((state = 'active' AND retire_after_unix_ms IS NULL) OR
				       (state = 'retiring' AND retire_after_unix_ms IS NOT NULL))
			) STRICT`},
			{SQL: `CREATE UNIQUE INDEX IF NOT EXISTS oidc_signing_keys_one_active
				ON oidc_signing_keys(state) WHERE state = 'active'`},
			{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations (version) VALUES (?)`, Args: []any{int64(2)}},
		},
	}
}

// Execute accepts a Rhiza SQL mutation only when it committed. Rhiza reports
// deterministic SQL rejection in the receipt rather than as a Go error.
func Execute(ctx context.Context, db *rhiza.DB, request rhiza.ExecuteRequest) (rhiza.ExecuteResponse, error) {
	if err := rhiza.ValidateExecuteRequest(request); err != nil {
		return rhiza.ExecuteResponse{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		response, err := db.Execute(ctx, request)
		if err == nil {
			return validateReceipt(request.RequestID, response)
		}
		if !errors.Is(err, rhiza.ErrCommitUnknown) {
			return response, err
		}
		status, statusErr := db.RequestStatus(ctx, rhiza.RequestStatusRequest{Kind: "sql", RequestID: request.RequestID})
		if statusErr != nil {
			return response, errors.Join(err, statusErr)
		}
		switch status.State {
		case "committed":
			if status.Receipt == nil {
				return response, fmt.Errorf("rhiza mutation %q: %s status without receipt", request.RequestID, status.State)
			}
			response.MutationReceipt = *status.Receipt
			recovered, retryErr := db.Execute(ctx, request)
			if retryErr != nil {
				return response, errors.Join(err, retryErr)
			}
			return validateReceipt(request.RequestID, recovered)
		case "rejected":
			if status.Receipt == nil {
				return response, fmt.Errorf("rhiza mutation %q: %s status without receipt", request.RequestID, status.State)
			}
			response.MutationReceipt = *status.Receipt
			return validateReceipt(request.RequestID, response)
		case "unknown_or_expired":
			if attempt == 1 {
				return response, err
			}
		default:
			return response, fmt.Errorf("rhiza mutation %q: unknown request state %q", request.RequestID, status.State)
		}
	}
	panic("unreachable")
}

func validateReceipt(requestID string, response rhiza.ExecuteResponse) (rhiza.ExecuteResponse, error) {
	if response.Status != "committed" {
		return response, fmt.Errorf("rhiza mutation %q: status=%s error_code=%s", requestID, response.Status, response.ErrorCode)
	}
	return response, nil
}

func Ready(ctx context.Context, db *rhiza.DB) error {
	if !db.Ready() {
		return fmt.Errorf("rhiza recovery is not ready")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 WHERE (SELECT MAX(version) FROM goauthy_schema_migrations) = ?`,
		Args:        []any{schemaVersion},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 {
		return fmt.Errorf("schema version is unavailable")
	}
	return nil
}

// migrateSchemaV86 adds nullable authentication failure metadata without
// rewriting existing users or credential generations.
func migrateSchemaV86(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=86)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 86 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v86", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE identity_users ADD COLUMN last_failed_login_at_unix_ms INTEGER CHECK(last_failed_login_at_unix_ms IS NULL OR last_failed_login_at_unix_ms>=0)`},
		{SQL: `ALTER TABLE identity_users ADD COLUMN failed_login_attempts INTEGER CHECK(failed_login_attempts IS NULL OR failed_login_attempts>=0)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(86)`},
	}})
	return err
}

// migrateSchemaV87 adds backchannel_logout_uri to dynamic OAuth clients.
func migrateSchemaV87(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=87)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 87 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v87", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE dynamic_oauth_clients ADD COLUMN backchannel_logout_uri TEXT CHECK(backchannel_logout_uri IS NULL OR length(backchannel_logout_uri) > 0)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(87)`},
	}})
	return err
}

// migrateSchemaV88 adds login location tracking for suspicious login detection.
func migrateSchemaV88(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=88)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 88 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v88", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_login_locations (
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			ip_address TEXT NOT NULL CHECK (length(ip_address) BETWEEN 1 AND 45),
			first_seen_at_unix_ms INTEGER NOT NULL CHECK (first_seen_at_unix_ms >= 0),
			last_seen_at_unix_ms INTEGER NOT NULL CHECK (last_seen_at_unix_ms >= first_seen_at_unix_ms),
			login_count INTEGER NOT NULL DEFAULT 1 CHECK (login_count >= 1),
			PRIMARY KEY (subject, ip_address)
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS identity_login_locations_subject_last_seen
			ON identity_login_locations(subject, last_seen_at_unix_ms)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(88)`},
	}})
	return err
}

// migrateSchemaV89 adds credential stuffing detection tables for distributed
// login attack protection. It tracks per-account failed login attempts from
// multiple IPs and supports automatic account lockout.
func migrateSchemaV89(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=89)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 89 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v89", Statements: []rhiza.SQLStatement{
		// Tracks distinct IP failures per account within a time window.
		// Used to detect credential stuffing attacks where many IPs target one account.
		{SQL: `CREATE TABLE IF NOT EXISTS login_account_ip_failures (
			key_digest TEXT PRIMARY KEY NOT NULL,
			account_hash TEXT NOT NULL,
			ip_hash TEXT NOT NULL,
			window_start_unix_ms INTEGER NOT NULL,
			expires_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `CREATE INDEX IF NOT EXISTS login_account_ip_failures_account_window
			ON login_account_ip_failures(account_hash, window_start_unix_ms)`},
		{SQL: `CREATE INDEX IF NOT EXISTS login_account_ip_failures_expiry
			ON login_account_ip_failures(expires_at_unix_ms)`},
		// Stores account lockout state when credential stuffing is detected.
		{SQL: `CREATE TABLE IF NOT EXISTS login_account_locks (
			account_hash TEXT PRIMARY KEY NOT NULL,
			locked_until_unix_ms INTEGER NOT NULL,
			reason TEXT NOT NULL,
			created_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(89)`},
	}})
	return err
}

// migrateSchemaV90 stores one recoverable, shared login-revoke code per user.
func migrateSchemaV90(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=90)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 90 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v90", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_login_revoke (
			subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			generation TEXT NOT NULL CHECK (length(generation) = 22 AND generation NOT GLOB '*[^A-Za-z0-9_-]*'),
			code_envelope BLOB NOT NULL CHECK (length(code_envelope) > 0),
			FOREIGN KEY (subject) REFERENCES identity_users(subject) ON DELETE CASCADE
		) STRICT`},
		{SQL: `CREATE TRIGGER IF NOT EXISTS identity_login_revoke_user_cleanup
			AFTER DELETE ON identity_users
			BEGIN DELETE FROM identity_login_revoke WHERE subject=OLD.subject; END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(90)`},
	}})
	return err
}

// migrateSchemaV91 preserves IP history while adding browser-aware location identity.
func migrateSchemaV91(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=91)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 91 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v91", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE identity_login_locations_v91 (
 subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 512),
 ip_address TEXT NOT NULL CHECK(length(ip_address) BETWEEN 1 AND 45),
 first_seen_at_unix_ms INTEGER NOT NULL CHECK(first_seen_at_unix_ms>=0),
 last_seen_at_unix_ms INTEGER NOT NULL CHECK(last_seen_at_unix_ms>=first_seen_at_unix_ms),
 login_count INTEGER NOT NULL DEFAULT 1 CHECK(login_count>=1),
 browser_id TEXT NOT NULL DEFAULT '',
 user_agent TEXT NOT NULL DEFAULT '',
 location TEXT,
 PRIMARY KEY(subject,ip_address,browser_id)
 ) STRICT`},
		{SQL: `INSERT INTO identity_login_locations_v91(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count) SELECT subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count FROM identity_login_locations`},
		{SQL: `DROP TABLE identity_login_locations`},
		{SQL: `ALTER TABLE identity_login_locations_v91 RENAME TO identity_login_locations`},
		{SQL: `CREATE INDEX identity_login_locations_subject_last_seen ON identity_login_locations(subject,last_seen_at_unix_ms)`},
		{SQL: `CREATE INDEX identity_login_locations_browser ON identity_login_locations(subject,browser_id)`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(91)`},
	}})
	return err
}

// migrateSchemaV92 persists validated per-client theme documents.
func migrateSchemaV92(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=92)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 92 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v92", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE client_themes (
    client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 2 AND 256),
    version INTEGER NOT NULL CHECK(version>0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms>=0),
    document_json TEXT NOT NULL CHECK(json_valid(document_json) AND json_type(document_json)='object')
  ) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(92)`},
	}})
	return err
}

// migrateSchemaV93 stores independently replaceable logo resolutions.
func migrateSchemaV93(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=93)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 93 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	statements := []rhiza.SQLStatement{}
	for _, table := range []struct{ name, id string }{{"client_logos", "client_id"}, {"auth_provider_logos", "auth_provider_id"}} {
		statements = append(statements, rhiza.SQLStatement{SQL: fmt.Sprintf(`CREATE TABLE %s (
   %s TEXT NOT NULL,
   res TEXT NOT NULL CHECK(res IN ('small','medium','large','custom','svg','favicon')),
   content_type TEXT NOT NULL CHECK(content_type IN ('image/webp','image/svg+xml')),
   data BLOB NOT NULL CHECK(length(data)>0),
   updated INTEGER NOT NULL CHECK(updated>=0),
   PRIMARY KEY(%s,res)
  ) STRICT`, table.name, table.id, table.id)})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(93)`})
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v93", Statements: statements})
	return err
}

// migrateSchemaV94 folds the legacy client_favicons rows into the unified
// client_logos table. The legacy table is intentionally retained so older
// rolling nodes can continue to write it until runtime dual-write/upgrade
// coordination is in place.
func migrateSchemaV94(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=94)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 94 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	// All statements run in one replicated Rhiza mutation. Legacy MIME types
	// are allowed only for the favicon resolution so the copied bytes remain
	// byte-for-byte intact; new runtime writes will use WebP or sanitized SVG.
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v94", Statements: []rhiza.SQLStatement{
		// Keep marker-only historical fixtures and rolling upgrades safe when a
		// node recorded v43 before its legacy table was materialized locally.
		{SQL: `CREATE TABLE IF NOT EXISTS client_favicons (
   client_id TEXT PRIMARY KEY NOT NULL CHECK(length(client_id) BETWEEN 1 AND 64 AND client_id NOT GLOB '*[^A-Za-z0-9._-]*'),
   content_type TEXT NOT NULL CHECK(content_type IN ('image/png','image/x-icon')),
   data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 262144),
   updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0)
  ) STRICT`},
		{SQL: `CREATE TABLE client_logos_v94 (
   client_id TEXT NOT NULL,
   res TEXT NOT NULL CHECK(res IN ('small','medium','large','custom','svg','favicon')),
   content_type TEXT NOT NULL CHECK(
     content_type IN ('image/webp','image/svg+xml') OR
     (res='favicon' AND content_type IN ('image/png','image/x-icon'))
   ),
   data BLOB NOT NULL CHECK(length(data)>0),
   updated INTEGER NOT NULL CHECK(updated>=0),
   PRIMARY KEY(client_id,res)
  ) STRICT`},
		{SQL: `INSERT INTO client_logos_v94(client_id,res,content_type,data,updated)
  SELECT client_id,res,content_type,data,updated FROM client_logos`},
		{SQL: `UPDATE client_logos_v94
  SET content_type=(SELECT f.content_type FROM client_favicons f WHERE f.client_id=client_logos_v94.client_id),
      data=(SELECT f.data FROM client_favicons f WHERE f.client_id=client_logos_v94.client_id),
      updated=(SELECT f.updated_at_unix_ms FROM client_favicons f WHERE f.client_id=client_logos_v94.client_id)
  WHERE client_logos_v94.res='favicon'
    AND EXISTS(SELECT 1 FROM client_favicons f
      WHERE f.client_id=client_logos_v94.client_id
        AND f.updated_at_unix_ms > client_logos_v94.updated)`},
		{SQL: `INSERT INTO client_logos_v94(client_id,res,content_type,data,updated)
  SELECT f.client_id,'favicon',f.content_type,f.data,f.updated_at_unix_ms
  FROM client_favicons f
  WHERE NOT EXISTS(SELECT 1 FROM client_logos_v94 l
    WHERE l.client_id=f.client_id AND l.res='favicon')`},
		{SQL: `DROP TABLE client_logos`},
		{SQL: `ALTER TABLE client_logos_v94 RENAME TO client_logos`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(94)`},
	}})
	return err
}

// migrateSchemaV95 creates the final 21-column auth_providers persistence
// shape. Provider logos remain independent until their explicit cleanup and
// foreign-key lifecycle is wired by the provider store.
func migrateSchemaV95(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=95)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 95 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v95", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE auth_providers (
   id TEXT NOT NULL PRIMARY KEY,
   enabled INTEGER NOT NULL,
   name TEXT NOT NULL,
   typ TEXT NOT NULL,
   issuer TEXT NOT NULL,
   authorization_endpoint TEXT NOT NULL,
   token_endpoint TEXT NOT NULL,
   userinfo_endpoint TEXT NOT NULL,
   client_id TEXT NOT NULL,
   secret BLOB,
   scope TEXT NOT NULL,
   admin_claim_path TEXT,
   admin_claim_value TEXT,
   mfa_claim_path TEXT,
   mfa_claim_value TEXT,
   use_pkce INTEGER NOT NULL,
   client_secret_basic INTEGER NOT NULL DEFAULT 1,
   client_secret_post INTEGER NOT NULL DEFAULT 1,
   jwks_endpoint TEXT,
   auto_onboarding INTEGER NOT NULL DEFAULT 1,
   auto_link INTEGER NOT NULL DEFAULT 0
  ) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(95)`},
	}})
	return err
}

// migrateSchemaV96 creates the per-provider runtime version tracking table
// and backfills existing providers with a deterministic marker.
func migrateSchemaV96(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=96)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 96 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v96", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE auth_provider_runtime_versions (
   provider_id TEXT PRIMARY KEY NOT NULL,
   version TEXT NOT NULL
  ) STRICT`},
		{SQL: `INSERT INTO auth_provider_runtime_versions(provider_id, version) SELECT id, 'migration-v96/'||id FROM auth_providers`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(96)`},
	}})
	return err
}

// migrateSchemaV97 adds a BEFORE UPDATE trigger on auth_providers that
// enforces the oauth_userinfo type mode immutability constraint. Changing
// to or from oauth_userinfo requires a new provider; same-mode and legacy
// type changes are unaffected.
func migrateSchemaV97(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=97)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 97 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v97", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TRIGGER IF NOT EXISTS auth_providers_oauth_userinfo_mode_immutable
			BEFORE UPDATE OF typ ON auth_providers
			WHEN (OLD.typ='oauth_userinfo') != (NEW.typ='oauth_userinfo')
			BEGIN SELECT RAISE(ABORT,'upstream authentication mode change requires new provider'); END`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(97)`},
	}})
	return err
}

func migrateSchemaV98(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=98)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 98 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v98", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE scim_client_config (
			client_id TEXT PRIMARY KEY NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
			endpoint TEXT NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 2048),
			bearer_envelope BLOB CHECK (bearer_envelope IS NULL OR length(bearer_envelope) > 0),
			ca_cert BLOB CHECK (ca_cert IS NULL OR length(ca_cert) > 0),
			enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
			created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(98)`},
	}})
	return err
}

func migrateSchemaV99(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=99)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 99 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v99", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE managed_oauth_clients ADD COLUMN force_mfa INTEGER NOT NULL DEFAULT 0 CHECK(force_mfa IN (0, 1))`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(99)`},
	}})
	return err
}

func migrateSchemaV100(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=100)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 100 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v100", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS system_lockdown (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
			reason TEXT NOT NULL DEFAULT '',
			until_unix_ms INTEGER NOT NULL DEFAULT 0,
			created_at_unix_ms INTEGER NOT NULL,
			updated_at_unix_ms INTEGER NOT NULL
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(100)`},
	}})
	return err
}

func migrateSchemaV101(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=101)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 101 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}

	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v101", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp (
			code_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			expires_at_unix_ms INTEGER NOT NULL,
			consumed_attempt TEXT,
			consumed_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp_rate_limits (
			subject_digest TEXT NOT NULL,
			window_start_unix_seconds INTEGER NOT NULL,
			count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (subject_digest, window_start_unix_seconds)
		) STRICT`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(101)`},
	}})
	return err
}

func migrateSchemaV102(ctx context.Context, db *rhiza.DB) error {
	state, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM goauthy_schema_migrations WHERE version=102)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(state.Rows) != 1 || len(state.Rows[0]) != 1 {
		return errors.New("invalid schema 102 inspection")
	}
	if state.Rows[0][0] == int64(1) {
		return nil
	}
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v102", Statements: []rhiza.SQLStatement{
		{SQL: `ALTER TABLE event_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''`},
		{SQL: `ALTER TABLE event_log ADD COLUMN integrity_hash TEXT NOT NULL DEFAULT ''`},
		{SQL: `INSERT INTO goauthy_schema_migrations(version) VALUES(102)`},
	}})
	return err
}
