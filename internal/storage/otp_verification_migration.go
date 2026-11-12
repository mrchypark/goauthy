package storage

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// migrateOTPVerificationLimits follows v114 so existing OTP rows remain intact.
func migrateOTPVerificationLimits(ctx context.Context, db *rhiza.DB) error {
	_, err := Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "goauthy-schema-v115", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp_verification_limits (
			subject_digest TEXT PRIMARY KEY NOT NULL CHECK (length(subject_digest) = 43),
			failed_attempts INTEGER NOT NULL CHECK (failed_attempts >= 0),
			window_started_at_unix_ms INTEGER NOT NULL CHECK (window_started_at_unix_ms >= 0),
			locked_until_unix_ms INTEGER NOT NULL DEFAULT 0 CHECK (locked_until_unix_ms >= 0),
			updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= 0)
		) STRICT`},
		{SQL: `INSERT OR IGNORE INTO goauthy_schema_migrations(version) VALUES(115)`},
	}})
	return err
}
