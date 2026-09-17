package passkey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/rhiza"
)

const passkeyReferenceScanLimit = 32

var ErrUnsafeEnvelopeReferences = errors.New("passkey envelope references are unsafe")

// EnvelopeReferenceFamily contains counts for one retained passkey table.
// ByKeyID contains only authenticated GAOP envelopes; Legacy counts old
// CookieKey ciphertexts. Total is the sum of both.
type EnvelopeReferenceFamily struct {
	ByKeyID map[string]int64
	Legacy  int64
	Total   int64
}

// EnvelopeReferenceStatus is read-only local evidence for master-key
// retirement. Safe is true only when every retained passkey envelope is
// authenticated under the active key and no legacy ciphertext remains.
type EnvelopeReferenceStatus struct {
	ActiveMasterKeyID string
	Credentials       EnvelopeReferenceFamily
	Ceremonies        EnvelopeReferenceFamily
	MFACeremonies     EnvelopeReferenceFamily
	Safe              bool
}

// InspectEnvelopeReferences scans every retained credential, normal ceremony,
// and MFA ceremony in bounded linearizable pages. It authenticates every GAOP
// envelope and semantically validates every plaintext, while legacy rows are
// decrypted with the migration CookieKey and validated before counting. Any
// malformed, tampered, or unknown-key row fails closed without fallback.
// This is local evidence only and is not a cluster-wide write barrier.
func (s *Service) InspectEnvelopeReferences(ctx context.Context) (EnvelopeReferenceStatus, error) {
	status := EnvelopeReferenceStatus{
		Credentials:   emptyEnvelopeReferenceFamily(),
		Ceremonies:    emptyEnvelopeReferenceFamily(),
		MFACeremonies: emptyEnvelopeReferenceFamily(),
	}
	if s == nil || s.db == nil || s.keyring == nil || ctx == nil {
		return status, ErrUnsafeEnvelopeReferences
	}
	if err := ctx.Err(); err != nil {
		return status, err
	}
	activeID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return status, ErrUnsafeEnvelopeReferences
	}
	status.ActiveMasterKeyID = activeID
	if err := s.inspectCredentialReferences(ctx, &status.Credentials); err != nil {
		return status, ErrUnsafeEnvelopeReferences
	}
	if err := s.inspectCeremonyReferences(ctx, &status.Ceremonies); err != nil {
		return status, ErrUnsafeEnvelopeReferences
	}
	if err := s.inspectMFAReferences(ctx, &status.MFACeremonies); err != nil {
		return status, ErrUnsafeEnvelopeReferences
	}
	status.Safe = envelopeFamilyUsesOnly(status.Credentials, activeID) && envelopeFamilyUsesOnly(status.Ceremonies, activeID) && envelopeFamilyUsesOnly(status.MFACeremonies, activeID)
	return status, nil
}

func emptyEnvelopeReferenceFamily() EnvelopeReferenceFamily {
	return EnvelopeReferenceFamily{ByKeyID: make(map[string]int64)}
}

func envelopeFamilyUsesOnly(family EnvelopeReferenceFamily, activeID string) bool {
	if family.Legacy != 0 {
		return false
	}
	for keyID := range family.ByKeyID {
		if keyID != activeID {
			return false
		}
	}
	return true
}

func (s *Service) inspectCredentialReferences(ctx context.Context, family *EnvelopeReferenceFamily) error {
	after := ""
	for {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id,subject,credential_json,credential_version
			FROM identity_webauthn_credentials WHERE credential_id > ? ORDER BY credential_id LIMIT ?`, Args: []any{after, int64(passkeyReferenceScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		if len(result.Rows) == 0 {
			return nil
		}
		last := ""
		for i, row := range result.Rows {
			if len(row) != 4 {
				return fmt.Errorf("credential row %d", i)
			}
			id, idOK := row[0].(string)
			subject, subjectOK := row[1].(string)
			encoded, encodedOK := row[2].(string)
			version, versionOK := row[3].(int64)
			if !idOK || !validCredentialID(id) || !subjectOK || !validSubject(subject) || !encodedOK || encoded == "" || !versionOK || version < 0 {
				return fmt.Errorf("credential row %d", i)
			}
			plain, keyID, legacy, err := s.openStoredEnvelope(encoded, credentialEnvelopePurpose(subject), credentialAAD(subject))
			if err != nil {
				return err
			}
			var credential wa.Credential
			if decodeCredentialJSON(plain, &credential) != nil || base64.RawURLEncoding.EncodeToString(credential.ID) != id {
				return fmt.Errorf("credential row %d", i)
			}
			addEnvelopeReference(family, keyID, legacy)
			last = id
		}
		if len(result.Rows) < passkeyReferenceScanLimit {
			return nil
		}
		after = last
	}
}

func (s *Service) inspectCeremonyReferences(ctx context.Context, family *EnvelopeReferenceFamily) error {
	after := ""
	for {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_digest,purpose,subject,session_digest,interaction_digest,passkey_name,session_json,expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms
			FROM identity_webauthn_ceremonies WHERE code_digest > ? ORDER BY code_digest LIMIT ?`, Args: []any{after, int64(passkeyReferenceScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		if len(result.Rows) == 0 {
			return nil
		}
		last := ""
		for i, row := range result.Rows {
			if len(row) != 10 {
				return fmt.Errorf("ceremony row %d", i)
			}
			digest, digestOK := row[0].(string)
			purpose, purposeOK := row[1].(string)
			subject, subjectOK := row[2].(string)
			sessionDigest, sessionOK := row[3].(string)
			encoded, encodedOK := row[6].(string)
			expiresAt, expiresOK := row[7].(int64)
			_, consumedAtOK := nullableUnixMillis(row[9])
			if !digestOK || !validDigest(digest) || !purposeOK || (purpose != "register" && purpose != "login") || !subjectOK || !validSubject(subject) || !sessionOK || !validDigest(sessionDigest) || !encodedOK || encoded == "" || !expiresOK || expiresAt < 0 || !consumedAtOK || !validCeremonyMetadata(row[4], row[5], row[8]) {
				return fmt.Errorf("ceremony row %d", i)
			}
			plain, keyID, legacy, err := s.openStoredEnvelope(encoded, ceremonyEnvelopePurpose(purpose, subject, digest), ceremonyAAD(purpose, subject, digest))
			if err != nil {
				return err
			}
			var sealed sealedState
			if decodeSealedStateJSON(plain, &sealed) != nil || !validCeremonyState(sealed, purpose, row[4]) {
				return fmt.Errorf("ceremony row %d", i)
			}
			addEnvelopeReference(family, keyID, legacy)
			last = digest
		}
		if len(result.Rows) < passkeyReferenceScanLimit {
			return nil
		}
		after = last
	}
}

func (s *Service) inspectMFAReferences(ctx context.Context, family *EnvelopeReferenceFamily) error {
	after := ""
	for {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms
			FROM identity_webauthn_mfa_ceremonies WHERE code_digest > ? ORDER BY code_digest LIMIT ?`, Args: []any{after, int64(passkeyReferenceScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		if len(result.Rows) == 0 {
			return nil
		}
		last := ""
		for i, row := range result.Rows {
			if len(row) != 8 {
				return fmt.Errorf("MFA ceremony row %d", i)
			}
			digest, digestOK := row[0].(string)
			subject, subjectOK := row[1].(string)
			sessionDigest, sessionOK := row[2].(string)
			encoded, encodedOK := row[3].(string)
			expiresAt, expiresOK := row[4].(int64)
			proofExpiresAt, proofExpiresOK := row[5].(int64)
			_, consumedAtOK := nullableUnixMillis(row[7])
			if !digestOK || !validDigest(digest) || !subjectOK || !validSubject(subject) || !sessionOK || !validDigest(sessionDigest) || !encodedOK || encoded == "" || !expiresOK || expiresAt < 0 || !proofExpiresOK || proofExpiresAt < 0 || !consumedAtOK || !validConsumedAttempt(row[6]) {
				return fmt.Errorf("MFA ceremony row %d", i)
			}
			plain, keyID, legacy, err := s.openStoredEnvelope(encoded, mfaCeremonyEnvelopePurpose(subject, digest), mfaCeremonyAAD(subject, digest))
			if err != nil {
				return err
			}
			var sealed modificationSealedState
			if decodeModificationSealedStateJSON(plain, &sealed) != nil || !validCode(sealed.Proof) {
				return fmt.Errorf("MFA ceremony row %d", i)
			}
			addEnvelopeReference(family, keyID, legacy)
			last = digest
		}
		if len(result.Rows) < passkeyReferenceScanLimit {
			return nil
		}
		after = last
	}
}

func addEnvelopeReference(family *EnvelopeReferenceFamily, keyID string, legacy bool) {
	if legacy {
		family.Legacy++
	} else {
		family.ByKeyID[keyID]++
	}
	family.Total++
}
