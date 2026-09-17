package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const credentialEnvelopeBatchSize = 32

func InspectCredentialEnvelopeReferences(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring) (oidc.MasterKeyReferenceFamily, error) {
	family := oidc.MasterKeyReferenceFamily{ByKeyID: make(map[string]int64)}
	if ctx == nil || db == nil || keys == nil {
		return family, errors.New("invalid SaaS credential reference scan")
	}
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT connection_id,owner_subject,collection_id,provider_id,generation,token_version,credential FROM saas_connection_credentials WHERE connection_id > ? ORDER BY connection_id LIMIT ?`, Args: []any{cursor, int64(credentialEnvelopeBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return oidc.MasterKeyReferenceFamily{}, err
		}
		for _, row := range result.Rows {
			binding, envelope, next, err := decodeCredentialRow(row)
			if err != nil {
				return oidc.MasterKeyReferenceFamily{}, err
			}
			purpose, err := credentialPurpose(binding)
			if err != nil {
				return oidc.MasterKeyReferenceFamily{}, err
			}
			keyID, err := keys.PurposeEnvelopeKeyID(purpose, envelope)
			if err != nil {
				return oidc.MasterKeyReferenceFamily{}, err
			}
			family.ByKeyID[keyID]++
			family.Total++
			cursor = next
		}
		if len(result.Rows) < credentialEnvelopeBatchSize {
			return family, nil
		}
	}
}

func RewrapCredentialEnvelopeBatch(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
	if ctx == nil || db == nil || keys == nil {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS credential rewrap")
	}
	if cursor != "" && !validText(cursor) {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS credential cursor")
	}
	active, err := keys.ActiveMasterKeyID()
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim FROM saas_connection_credentials WHERE connection_id > ? ORDER BY connection_id LIMIT ?`, Args: []any{cursor, int64(credentialEnvelopeBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	candidates := make([]credentialRewrapCandidate, 0, len(result.Rows))
	last := cursor
	for _, row := range result.Rows {
		if len(row) != 9 {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS credential row")
		}
		decodeRow := []any{row[0], row[1], row[2], row[3], row[4], row[5], row[7]}
		binding, envelope, connectionID, err := decodeCredentialRow(decodeRow)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		state, ok := row[6].(string)
		if !ok || !validCredentialState(state) {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS credential state")
		}
		claim, ok := nullableString(row[8])
		if !ok || (state == "refreshing") != (claim != "") {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS credential refresh claim")
		}
		purpose, err := credentialPurpose(binding)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		replacement, err := keys.RewrapEnvelope(purpose, envelope)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		candidates = append(candidates, credentialRewrapCandidate{binding: binding, connectionID: connectionID, state: state, claim: claim, oldEnvelope: envelope, newEnvelope: replacement})
		last = connectionID
	}
	requestID := credentialRewrapRequestID(last, candidates)
	sql, args := credentialRewrapSQL(candidates)
	response, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{RequestID: requestID, SQL: sql, Args: args})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if response.Status != "committed" {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("SaaS credential rewrap was not committed")
	}
	changed := response.MutationReceipt.RowsAffected
	if changed != 0 && changed != int64(len(candidates)) {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("SaaS credential rewrap CAS changed a partial batch")
	}
	return oidc.SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(result.Rows) < credentialEnvelopeBatchSize}, nil
}

func decodeCredentialRow(row []any) (credentialBinding, []byte, string, error) {
	if len(row) < 7 {
		return credentialBinding{}, nil, "", errors.New("invalid SaaS credential row")
	}
	connectionID, a := row[0].(string)
	owner, b := row[1].(string)
	collection, c := row[2].(string)
	provider, d := row[3].(string)
	generation, e := row[4].(string)
	version, f := row[5].(int64)
	envelope, g := row[6].([]byte)
	if !a || !b || !c || !d || !e || !f || !g || !validText(connectionID) || len(envelope) == 0 {
		return credentialBinding{}, nil, "", errors.New("invalid SaaS credential row")
	}
	return credentialBinding{Owner: owner, CollectionID: collection, ConnectionID: connectionID, ProviderID: provider, Generation: generation, TokenVersion: version}, envelope, connectionID, nil
}

func validCredentialState(state string) bool {
	return state == "ready" || state == "refreshing" || state == "uncertain" || state == "revoked"
}
func nullableString(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	s, ok := value.(string)
	return s, ok
}

type credentialRewrapCandidate struct {
	binding                    credentialBinding
	connectionID, state, claim string
	oldEnvelope, newEnvelope   []byte
}

func credentialRewrapRequestID(last string, rows []credentialRewrapCandidate) string {
	h := sha256.New()
	for _, row := range rows {
		h.Write([]byte(row.connectionID))
		h.Write(row.oldEnvelope)
		h.Write(row.newEnvelope)
	}
	return "saas-credential-rewrap/" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16]) + "/" + last
}

func credentialRewrapSQL(rows []credentialRewrapCandidate) (string, []any) {
	// One CASE plus a complete old-row predicate gives one atomic all-or-none CAS batch.
	sql := "UPDATE saas_connection_credentials SET credential = CASE connection_id "
	args := make([]any, 0, len(rows)*10)
	for _, row := range rows {
		sql += "WHEN ? THEN ? "
		args = append(args, row.connectionID, row.newEnvelope)
	}
	sql += "ELSE credential END WHERE connection_id IN ("
	for i, row := range rows {
		if i > 0 {
			sql += ","
		}
		sql += "?"
		args = append(args, row.connectionID)
	}
	sql += ") AND (SELECT COUNT(*) FROM saas_connection_credentials WHERE "
	for i, row := range rows {
		if i > 0 {
			sql += " OR "
		}
		sql += "(connection_id=? AND owner_subject=? AND collection_id=? AND provider_id=? AND generation=? AND token_version=? AND state=? AND credential=?"
		args = append(args, row.connectionID, row.binding.Owner, row.binding.CollectionID, row.binding.ProviderID, row.binding.Generation, row.binding.TokenVersion, row.state, row.oldEnvelope)
		if row.claim == "" {
			sql += " AND refresh_claim IS NULL)"
		} else {
			sql += " AND refresh_claim=?)"
			args = append(args, row.claim)
		}
	}
	sql += ") = ?"
	args = append(args, int64(len(rows)))
	return sql, args
}
