package upstreamprovider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	providerSecretRewrapScanLimit   = 128
	providerSecretRewrapUpdateLimit = 32
)

// InspectAuthProviderSecretReferences reads every non-NULL auth_providers.secret
// envelope and returns a cryptographically authenticated key-ID distribution.
// Malformed, tampered, or unknown-key envelopes fail closed.
func InspectAuthProviderSecretReferences(ctx context.Context, db *rhiza.DB, keys EnvelopeKeyring) (oidc.MasterKeyReferenceFamily, error) {
	f := oidc.MasterKeyReferenceFamily{ByKeyID: map[string]int64{}}
	if ctx == nil || db == nil || keys == nil {
		return f, errors.New("invalid auth-provider secret reference scan")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT id,secret FROM auth_providers WHERE secret IS NOT NULL ORDER BY id",
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return f, err
	}
	for _, row := range result.Rows {
		if len(row) != 2 {
			return oidc.MasterKeyReferenceFamily{}, errors.New("invalid auth-provider secret reference row")
		}
		id, idOK := row[0].(string)
		secret, secretOK := row[1].([]byte)
		if !idOK || !secretOK || id == "" {
			return oidc.MasterKeyReferenceFamily{}, errors.New("invalid auth-provider secret reference row")
		}
		purpose := ProviderSecretPurpose(id)
		if !validProviderSecretPurpose(purpose) {
			return oidc.MasterKeyReferenceFamily{}, fmt.Errorf("invalid auth-provider secret purpose %q", purpose)
		}
		kid, err := keys.PurposeEnvelopeKeyID(purpose, secret)
		if err != nil {
			return oidc.MasterKeyReferenceFamily{}, err
		}
		f.ByKeyID[kid]++
		f.Total++
	}
	return f, nil
}

// providerSecretRewrapRow is one candidate for atomic CAS rewrap.
type providerSecretRewrapRow struct {
	id          string
	secret      []byte
	newEnvelope []byte
}

// RewrapAuthProviderSecretBatch re-encrypts at most providerSecretRewrapUpdateLimit
// eligible auth_providers.secret envelopes under the active master key. The cursor
// advances through id-order so old-key rows are never skipped. All rows are
// preflighted before one atomic CAS update; a concurrent row change therefore
// cannot produce a partial batch.
func RewrapAuthProviderSecretBatch(ctx context.Context, db *rhiza.DB, keys EnvelopeKeyring, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
	if db == nil || keys == nil {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid auth-provider secret rewrap")
	}
	activeKeyID, err := keys.ActiveMasterKeyID()
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT id,secret FROM auth_providers WHERE secret IS NOT NULL AND id>? ORDER BY id LIMIT ?",
		Args:        []any{cursor, int64(providerSecretRewrapScanLimit)},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	scannedThrough := cursor
	updateBoundReached := false
	var verifiedWriterKey string
	rows := make([]providerSecretRewrapRow, 0, min(len(result.Rows), providerSecretRewrapUpdateLimit))
	for _, row := range result.Rows {
		if len(row) != 2 {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid auth-provider secret rewrap row")
		}
		id, idOK := row[0].(string)
		secret, secretOK := row[1].([]byte)
		if !idOK || !secretOK || id == "" {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid auth-provider secret rewrap row")
		}
		scannedThrough = id
		purpose := ProviderSecretPurpose(id)
		if !validProviderSecretPurpose(purpose) {
			return oidc.SigningKeyRewrapBatchResult{}, fmt.Errorf("invalid auth-provider secret purpose %q", purpose)
		}
		kid, err := keys.PurposeEnvelopeKeyID(purpose, secret)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		if kid == activeKeyID {
			last = id
			continue
		}
		if len(rows) >= providerSecretRewrapUpdateLimit {
			updateBoundReached = true
			break
		}
		rewrapped, err := keys.RewrapEnvelope(purpose, secret)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		// Verify the rewrapped envelope authenticates under the active key.
		outKeyID, err := keys.PurposeEnvelopeKeyID(purpose, rewrapped)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		if outKeyID != activeKeyID {
			return oidc.SigningKeyRewrapBatchResult{}, fmt.Errorf("rewrapped envelope key %s does not match active key %s", outKeyID, activeKeyID)
		}
		verifiedWriterKey = outKeyID
		rows = append(rows, providerSecretRewrapRow{id: id, secret: secret, newEnvelope: rewrapped})
		last = id
	}
	nextCursor := scannedThrough
	if updateBoundReached {
		nextCursor = last
	}
	done := len(result.Rows) < providerSecretRewrapScanLimit && !updateBoundReached
	if len(rows) == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: nextCursor, Done: done}, nil
	}
	statement := providerSecretRewrapMutation(rows)
	requestID := providerSecretRewrapRequestID(rows)
	response, err := storage.ExecuteEnvelope(ctx, db, verifiedWriterKey, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL:       statement.SQL,
		Args:      statement.Args,
	})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if response.Status != "committed" {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("auth-provider secret rewrap was not committed")
	}
	changed := response.RowsAffected
	if changed == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: cursor, Done: false}, nil
	}
	if changed != 0 && changed != int64(len(rows)) {
		return oidc.SigningKeyRewrapBatchResult{}, fmt.Errorf("auth-provider secret rewrap CAS changed %d rows, want %d", changed, len(rows))
	}
	return oidc.SigningKeyRewrapBatchResult{Cursor: nextCursor, Rewrapped: int(changed), Done: done}, nil
}

func providerSecretRewrapMutation(rows []providerSecretRewrapRow) rhiza.SQLStatement {
	var sql strings.Builder
	sql.WriteString("UPDATE auth_providers SET secret = CASE id ")
	args := make([]any, 0, len(rows)*4+1)
	for _, row := range rows {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.id, row.newEnvelope)
	}
	sql.WriteString("ELSE secret END WHERE id IN (")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.id)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM auth_providers WHERE ")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(id=? AND secret=?)")
		args = append(args, row.id, row.secret)
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(rows)))
	return rhiza.SQLStatement{SQL: sql.String(), Args: args}
}

func providerSecretRewrapRequestID(rows []providerSecretRewrapRow) string {
	h := sha256.New()
	for _, row := range rows {
		h.Write([]byte(row.id))
		h.Write(row.secret)
		h.Write(row.newEnvelope)
	}
	return "upstream-provider-secret-rewrap/" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}
