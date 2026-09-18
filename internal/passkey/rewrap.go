package passkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	passkeyRewrapBatchSize    = 32
	passkeyPhaseCredentials   = "credentials"
	passkeyPhaseCeremonies    = "ceremonies"
	passkeyPhaseMFACeremonies = "mfa-ceremonies"
)

// RewrapBatchResult reports one bounded passkey database-envelope batch.
// Cursor is opaque and is empty only after every phase is complete.
type RewrapBatchResult struct {
	Cursor    string
	Rewrapped int
	Done      bool
}

type rewrapCredential struct {
	id, subject, oldEnvelope, newEnvelope string
	version                               int64
}

type rewrapCeremony struct {
	digest, purpose, subject, sessionDigest string
	interactionDigest, passkeyName          any
	oldEnvelope, newEnvelope                string
	expiresAt                               int64
	consumedAt                              any
	consumedAttempt                         any
}

type rewrapMFACeremony struct {
	digest, subject, sessionDigest string
	oldEnvelope, newEnvelope       string
	expiresAt, proofExpiresAt      int64
	consumedAttempt, consumedAt    any
}

// RewrapBatch converts legacy passkey DB ciphertext and rewraps old GAOP
// envelopes under the active master key. It scans all retained rows in three
// phases: credentials, normal ceremonies, then MFA ceremonies.
func (s *Service) RewrapBatch(ctx context.Context, cursor string) (RewrapBatchResult, error) {
	if s == nil || s.db == nil || s.keyring == nil || ctx == nil {
		return RewrapBatchResult{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return RewrapBatchResult{}, err
	}
	activeID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return RewrapBatchResult{}, err
	}
	phase, after, err := decodeRewrapCursor(cursor)
	if err != nil {
		return RewrapBatchResult{}, err
	}
	switch phase {
	case passkeyPhaseCredentials:
		return s.rewrapCredentials(ctx, activeID, after)
	case passkeyPhaseCeremonies:
		return s.rewrapCeremonies(ctx, activeID, after)
	case passkeyPhaseMFACeremonies:
		return s.rewrapMFACeremonies(ctx, activeID, after)
	default:
		return RewrapBatchResult{}, errors.New("invalid passkey rewrap phase")
	}
}

func (s *Service) rewrapCredentials(ctx context.Context, activeID, after string) (RewrapBatchResult, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id,subject,credential_json,credential_version
		FROM identity_webauthn_credentials WHERE credential_id > ? ORDER BY credential_id LIMIT ?`, Args: []any{after, int64(passkeyRewrapBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCeremonies, "")}, nil
	}
	candidates := make([]rewrapCredential, 0, len(result.Rows))
	writerKeyID := ""
	last := ""
	for i, row := range result.Rows {
		if len(row) != 4 {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey credential row %d", i)
		}
		id, idOK := row[0].(string)
		subject, subjectOK := row[1].(string)
		encoded, encodedOK := row[2].(string)
		version, versionOK := row[3].(int64)
		if !idOK || id == "" || !subjectOK || !validSubject(subject) || !encodedOK || encoded == "" || !versionOK || version < 0 {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey credential row %d", i)
		}
		last = id
		plain, keyID, legacy, err := s.openStoredEnvelope(encoded, credentialEnvelopePurpose(subject), credentialAAD(subject))
		if err != nil {
			return RewrapBatchResult{}, fmt.Errorf("authenticate passkey credential row %d: %w", i, err)
		}
		var credential wa.Credential
		if decodeCredentialJSON(plain, &credential) != nil || base64.RawURLEncoding.EncodeToString(credential.ID) != id {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey credential row %d", i)
		}
		candidate := rewrapCredential{id: id, subject: subject, oldEnvelope: encoded, version: version}
		if legacy || keyID != activeID {
			sealed, sealedKeyID, err := s.encryptDB(plain, credentialEnvelopePurpose(subject))
			if err != nil {
				return RewrapBatchResult{}, err
			}
			if writerKeyID == "" {
				writerKeyID = sealedKeyID
			} else if writerKeyID != sealedKeyID {
				return RewrapBatchResult{}, errors.New("passkey rewrap batch used multiple envelope writer keys")
			}
			candidate.newEnvelope = base64.RawURLEncoding.EncodeToString(sealed)
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCredentials, last)}, nil
	}
	statement := credentialRewrapMutation(candidates)
	response, err := s.executeRewrap(ctx, writerKeyID, passkeyPhaseCredentials, statement, candidates)
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if response == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCredentials, after)}, nil
	}
	return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCredentials, last), Rewrapped: int(response)}, nil
}

func (s *Service) rewrapCeremonies(ctx context.Context, activeID, after string) (RewrapBatchResult, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_digest,purpose,subject,session_digest,interaction_digest,passkey_name,session_json,expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms
		FROM identity_webauthn_ceremonies WHERE code_digest > ? ORDER BY code_digest LIMIT ?`, Args: []any{after, int64(passkeyRewrapBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseMFACeremonies, "")}, nil
	}
	candidates := make([]rewrapCeremony, 0, len(result.Rows))
	writerKeyID := ""
	last := ""
	for i, row := range result.Rows {
		if len(row) != 10 {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey ceremony row %d", i)
		}
		digest, digestOK := row[0].(string)
		purpose, purposeOK := row[1].(string)
		subject, subjectOK := row[2].(string)
		sessionDigest, sessionOK := row[3].(string)
		encoded, encodedOK := row[6].(string)
		expiresAt, expiresOK := row[7].(int64)
		consumedAt, consumedAtOK := nullableUnixMillis(row[9])
		if !digestOK || !validDigest(digest) || !purposeOK || (purpose != "register" && purpose != "login") || !subjectOK || !validSubject(subject) || !sessionOK || !validDigest(sessionDigest) || !encodedOK || encoded == "" || !expiresOK || expiresAt < 0 || !consumedAtOK || !validCeremonyMetadata(row[4], row[5], row[8]) {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey ceremony row %d", i)
		}
		last = digest
		plain, keyID, legacy, err := s.openStoredEnvelope(encoded, ceremonyEnvelopePurpose(purpose, subject, digest), ceremonyAAD(purpose, subject, digest))
		if err != nil {
			return RewrapBatchResult{}, fmt.Errorf("authenticate passkey ceremony row %d: %w", i, err)
		}
		var sealed sealedState
		if decodeSealedStateJSON(plain, &sealed) != nil || !validCeremonyState(sealed, purpose, row[4]) {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey ceremony row %d", i)
		}
		candidate := rewrapCeremony{digest: digest, purpose: purpose, subject: subject, sessionDigest: sessionDigest, interactionDigest: row[4], passkeyName: row[5], oldEnvelope: encoded, expiresAt: expiresAt, consumedAttempt: row[8], consumedAt: consumedAt}
		if legacy || keyID != activeID {
			sealedEnvelope, sealedKeyID, err := s.encryptDB(plain, ceremonyEnvelopePurpose(purpose, subject, digest))
			if err != nil {
				return RewrapBatchResult{}, err
			}
			if writerKeyID == "" {
				writerKeyID = sealedKeyID
			} else if writerKeyID != sealedKeyID {
				return RewrapBatchResult{}, errors.New("passkey rewrap batch used multiple envelope writer keys")
			}
			candidate.newEnvelope = base64.RawURLEncoding.EncodeToString(sealedEnvelope)
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCeremonies, last)}, nil
	}
	statement := ceremonyRewrapMutation(candidates)
	response, err := s.executeRewrap(ctx, writerKeyID, passkeyPhaseCeremonies, statement, candidates)
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if response == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCeremonies, after)}, nil
	}
	return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseCeremonies, last), Rewrapped: int(response)}, nil
}

func (s *Service) rewrapMFACeremonies(ctx context.Context, activeID, after string) (RewrapBatchResult, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms
		FROM identity_webauthn_mfa_ceremonies WHERE code_digest > ? ORDER BY code_digest LIMIT ?`, Args: []any{after, int64(passkeyRewrapBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return RewrapBatchResult{Done: true}, nil
	}
	candidates := make([]rewrapMFACeremony, 0, len(result.Rows))
	writerKeyID := ""
	last := ""
	for i, row := range result.Rows {
		if len(row) != 8 {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey MFA ceremony row %d", i)
		}
		digest, digestOK := row[0].(string)
		subject, subjectOK := row[1].(string)
		sessionDigest, sessionOK := row[2].(string)
		encoded, encodedOK := row[3].(string)
		expiresAt, expiresOK := row[4].(int64)
		proofExpiresAt, proofExpiresOK := row[5].(int64)
		consumedAt, consumedAtOK := nullableUnixMillis(row[7])
		if !digestOK || !validDigest(digest) || !subjectOK || !validSubject(subject) || !sessionOK || !validDigest(sessionDigest) || !encodedOK || encoded == "" || !expiresOK || expiresAt < 0 || !proofExpiresOK || proofExpiresAt < 0 || !consumedAtOK || !validConsumedAttempt(row[6]) {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey MFA ceremony row %d", i)
		}
		last = digest
		plain, keyID, legacy, err := s.openStoredEnvelope(encoded, mfaCeremonyEnvelopePurpose(subject, digest), mfaCeremonyAAD(subject, digest))
		if err != nil {
			return RewrapBatchResult{}, fmt.Errorf("authenticate passkey MFA ceremony row %d: %w", i, err)
		}
		var sealed modificationSealedState
		if decodeModificationSealedStateJSON(plain, &sealed) != nil || !validCode(sealed.Proof) {
			return RewrapBatchResult{}, fmt.Errorf("invalid passkey MFA ceremony row %d", i)
		}
		candidate := rewrapMFACeremony{digest: digest, subject: subject, sessionDigest: sessionDigest, oldEnvelope: encoded, expiresAt: expiresAt, proofExpiresAt: proofExpiresAt, consumedAttempt: row[6], consumedAt: consumedAt}
		if legacy || keyID != activeID {
			sealedEnvelope, sealedKeyID, err := s.encryptDB(plain, mfaCeremonyEnvelopePurpose(subject, digest))
			if err != nil {
				return RewrapBatchResult{}, err
			}
			if writerKeyID == "" {
				writerKeyID = sealedKeyID
			} else if writerKeyID != sealedKeyID {
				return RewrapBatchResult{}, errors.New("passkey rewrap batch used multiple envelope writer keys")
			}
			candidate.newEnvelope = base64.RawURLEncoding.EncodeToString(sealedEnvelope)
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseMFACeremonies, last)}, nil
	}
	statement := mfaCeremonyRewrapMutation(candidates)
	response, err := s.executeRewrap(ctx, writerKeyID, passkeyPhaseMFACeremonies, statement, candidates)
	if err != nil {
		return RewrapBatchResult{}, err
	}
	if response == 0 {
		return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseMFACeremonies, after)}, nil
	}
	return RewrapBatchResult{Cursor: encodeRewrapCursor(passkeyPhaseMFACeremonies, last), Rewrapped: int(response)}, nil
}

func (s *Service) openStoredEnvelope(encoded, purpose string, legacyAAD []byte) ([]byte, string, bool, error) {
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) == 0 || base64.RawURLEncoding.EncodeToString(value) != encoded {
		return nil, "", false, ErrInvalid
	}
	if isPurposeEnvelope(value) {
		keyID, err := s.keyring.PurposeEnvelopeKeyID(purpose, value)
		if err != nil {
			return nil, "", false, err
		}
		plain, err := s.keyring.OpenEnvelope(purpose, value)
		return plain, keyID, false, err
	}
	plain, err := s.decrypt(value, legacyAAD)
	return plain, "", true, err
}

func (s *Service) executeRewrap(ctx context.Context, writerKeyID, phase string, statement rhiza.SQLStatement, candidates any) (int64, error) {
	requestID := passkeyRewrapRequestID(writerKeyID, phase, statement)
	response, err := storage.ExecuteEnvelope(ctx, s.db, writerKeyID, rhiza.ExecuteRequest{RequestID: requestID, SQL: statement.SQL, Args: statement.Args})
	if err != nil {
		return 0, err
	}
	count := candidateCount(candidates)
	if response.RowsAffected != 0 && response.RowsAffected != int64(count) {
		return 0, fmt.Errorf("passkey rewrap CAS changed %d rows, want %d", response.RowsAffected, count)
	}
	return response.RowsAffected, nil
}

func candidateCount(candidates any) int {
	switch values := candidates.(type) {
	case []rewrapCredential:
		return len(values)
	case []rewrapCeremony:
		return len(values)
	case []rewrapMFACeremony:
		return len(values)
	default:
		return 0
	}
}

func credentialRewrapMutation(rows []rewrapCredential) rhiza.SQLStatement {
	var sql strings.Builder
	sql.WriteString("UPDATE identity_webauthn_credentials SET credential_json = CASE credential_id ")
	args := make([]any, 0, len(rows)*7+1)
	for _, row := range rows {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.id, row.newEnvelope)
	}
	sql.WriteString("ELSE credential_json END WHERE credential_id IN (")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.id)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM identity_webauthn_credentials WHERE ")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(credential_id=? AND subject=? AND credential_json=? AND credential_version=?)")
		args = append(args, row.id, row.subject, row.oldEnvelope, row.version)
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(rows)))
	return rhiza.SQLStatement{SQL: sql.String(), Args: args}
}

func ceremonyRewrapMutation(rows []rewrapCeremony) rhiza.SQLStatement {
	var sql strings.Builder
	sql.WriteString("UPDATE identity_webauthn_ceremonies SET session_json = CASE code_digest ")
	args := make([]any, 0, len(rows)*11+1)
	for _, row := range rows {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.digest, row.newEnvelope)
	}
	sql.WriteString("ELSE session_json END WHERE code_digest IN (")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.digest)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM identity_webauthn_ceremonies WHERE ")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(code_digest=? AND purpose=? AND subject=? AND session_digest=?")
		args = append(args, row.digest, row.purpose, row.subject, row.sessionDigest)
		appendNullableRewrapPredicate(&sql, "interaction_digest", row.interactionDigest, &args)
		appendNullableRewrapPredicate(&sql, "passkey_name", row.passkeyName, &args)
		sql.WriteString(" AND session_json=? AND expires_at_unix_ms=?")
		args = append(args, row.oldEnvelope, row.expiresAt)
		appendNullableRewrapPredicate(&sql, "consumed_attempt", row.consumedAttempt, &args)
		sql.WriteString(" AND consumed_at_unix_ms")
		if row.consumedAt == nil {
			sql.WriteString(" IS NULL")
		} else {
			sql.WriteString("=?")
			args = append(args, row.consumedAt)
		}
		sql.WriteString(")")
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(rows)))
	return rhiza.SQLStatement{SQL: sql.String(), Args: args}
}

func mfaCeremonyRewrapMutation(rows []rewrapMFACeremony) rhiza.SQLStatement {
	var sql strings.Builder
	sql.WriteString("UPDATE identity_webauthn_mfa_ceremonies SET session_json = CASE code_digest ")
	args := make([]any, 0, len(rows)*10+1)
	for _, row := range rows {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.digest, row.newEnvelope)
	}
	sql.WriteString("ELSE session_json END WHERE code_digest IN (")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.digest)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM identity_webauthn_mfa_ceremonies WHERE ")
	for i, row := range rows {
		if i > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(code_digest=? AND subject=? AND session_digest=? AND session_json=? AND expires_at_unix_ms=? AND proof_expires_at_unix_ms=?")
		args = append(args, row.digest, row.subject, row.sessionDigest, row.oldEnvelope, row.expiresAt, row.proofExpiresAt)
		appendNullableRewrapPredicate(&sql, "consumed_attempt", row.consumedAttempt, &args)
		sql.WriteString(" AND consumed_at_unix_ms")
		if row.consumedAt == nil {
			sql.WriteString(" IS NULL")
		} else {
			sql.WriteString("=?")
			args = append(args, row.consumedAt)
		}
		sql.WriteString(")")
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(rows)))
	return rhiza.SQLStatement{SQL: sql.String(), Args: args}
}

func appendNullableRewrapPredicate(sql *strings.Builder, column string, value any, args *[]any) {
	if value == nil {
		sql.WriteString(" AND " + column + " IS NULL")
		return
	}
	sql.WriteString(" AND " + column + "=?")
	*args = append(*args, value)
}

func validCeremonyState(state sealedState, purpose string, interactionDigest any) bool {
	if purpose == "register" {
		return state.Interaction == "" && state.AuthenticationMethod == "" && interactionDigest == nil
	}
	stored, ok := interactionDigest.(string)
	return ok && stored != "" && state.Interaction != "" && challengeDigest(state.Interaction) == stored && (state.AuthenticationMethod == "webauthn" || state.AuthenticationMethod == "mfa")
}

func validCeremonyMetadata(interactionDigest, passkeyName, consumedAttempt any) bool {
	if interactionDigest != nil {
		value, ok := interactionDigest.(string)
		if !ok || !validDigest(value) {
			return false
		}
	}
	if passkeyName != nil {
		value, ok := passkeyName.(string)
		if !ok || !validName(value) {
			return false
		}
	}
	return validConsumedAttempt(consumedAttempt)
}

func validConsumedAttempt(value any) bool {
	if value == nil {
		return true
	}
	attempt, ok := value.(string)
	return ok && len(attempt) == 22
}

func nullableUnixMillis(value any) (any, bool) {
	if value == nil {
		return nil, true
	}
	unixMillis, ok := value.(int64)
	return unixMillis, ok && unixMillis >= 0
}

func encodeRewrapCursor(phase, after string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(phase + "\x00" + after))
}

func decodeRewrapCursor(cursor string) (string, string, error) {
	if cursor == "" {
		return passkeyPhaseCredentials, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != cursor {
		return "", "", errors.New("invalid passkey rewrap cursor")
	}
	parts := bytes.Split(decoded, []byte{'\x00'})
	if len(parts) != 2 || len(parts[1]) > 2048 {
		return "", "", errors.New("invalid passkey rewrap cursor")
	}
	phase, after := string(parts[0]), string(parts[1])
	switch phase {
	case passkeyPhaseCredentials:
		if after != "" && !validCredentialID(after) {
			return "", "", errors.New("invalid passkey rewrap cursor")
		}
	case passkeyPhaseCeremonies, passkeyPhaseMFACeremonies:
		if after != "" && !validDigest(after) {
			return "", "", errors.New("invalid passkey rewrap cursor")
		}
	default:
		return "", "", errors.New("invalid passkey rewrap cursor")
	}
	return phase, after, nil
}

func validCredentialID(value string) bool {
	return len(value) > 0 && len(value) <= 2048 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=") == ""
}

func passkeyRewrapRequestID(activeID, phase string, statement rhiza.SQLStatement) string {
	payload, _ := json.Marshal(struct {
		ActiveID string `json:"active_id"`
		Phase    string `json:"phase"`
		SQL      string `json:"sql"`
		Args     []any  `json:"args"`
	}{activeID, phase, statement.SQL, statement.Args})
	digest := sha256.Sum256(payload)
	return "passkey-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:24])
}
