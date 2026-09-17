package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	loginRevokeCodeLength = 48
	loginRevokeAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var ErrInvalidLoginRevokeCode = errors.New("invalid login revoke code")

// FindOrCreateLoginRevokeCode returns the user's persistent recoverable code.
func (s *Store) FindOrCreateLoginRevokeCode(ctx context.Context, keyring *oidc.Keyring, subject string) (string, error) {
	if s == nil || s.db == nil || ctx == nil || keyring == nil {
		return "", errors.New("login revoke is not configured")
	}
	if err := validateSubject(subject); err != nil {
		return "", err
	}
	if err := s.ensureLoginRevokeSubject(ctx, subject); err != nil {
		return "", err
	}

	generation, envelope, found, err := s.loginRevokeRecord(ctx, subject)
	if err != nil {
		return "", err
	}
	if found {
		return s.openLoginRevokeCode(keyring, subject, generation, envelope)
	}

	activeKeyID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return "", err
	}
	generation, err = s.randomID(16)
	if err != nil {
		return "", err
	}
	code, err := s.newLoginRevokeCode()
	if err != nil {
		return "", err
	}
	envelope, err = keyring.SealEnvelope(oidc.LoginRevokeCodePurpose(subject, generation), []byte(code))
	if err != nil {
		return "", err
	}
	_, writeErr := storage.ExecuteEnvelope(ctx, s.db, activeKeyID, rhiza.ExecuteRequest{
		RequestID: mutationID("login-revoke-create", subject, generation),
		SQL: `INSERT OR IGNORE INTO identity_login_revoke(subject,generation,code_envelope)
			SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject=?)`,
		Args: []any{subject, generation, envelope, subject},
	})

	winnerGeneration, winnerEnvelope, winnerFound, readErr := s.loginRevokeRecord(ctx, subject)
	if readErr != nil {
		return "", readErr
	}
	if winnerFound {
		return s.openLoginRevokeCode(keyring, subject, winnerGeneration, winnerEnvelope)
	}
	if writeErr != nil {
		return "", writeErr
	}
	return "", ErrInactiveSubject
}

// RevokeLogin atomically consumes the code and revokes all local login state.
func (s *Store) RevokeLogin(ctx context.Context, keyring *oidc.Keyring, subject, code string, ip netip.Addr, location *string) error {
	if s == nil || s.db == nil || ctx == nil || keyring == nil || !ip.IsValid() || ip.Zone() != "" {
		return ErrInvalidLoginRevokeCode
	}
	if err := validateSubject(subject); err != nil {
		return err
	}
	if err := s.ensureLoginRevokeSubject(ctx, subject); err != nil {
		return err
	}
	generation, envelope, found, err := s.loginRevokeRecord(ctx, subject)
	if err != nil {
		return err
	}
	if !found {
		return ErrInvalidLoginRevokeCode
	}
	plain, err := keyring.OpenEnvelope(oidc.LoginRevokeCodePurpose(subject, generation), envelope)
	if err != nil || len(plain) != loginRevokeCodeLength || !validLoginRevokeCode(plain) {
		if err != nil {
			return err
		}
		return ErrInvalidLoginRevokeCode
	}
	if !equalLoginRevokeCode(code, plain) {
		return ErrInvalidLoginRevokeCode
	}

	activeKeyID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	attempt, err := s.randomID(16)
	if err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	if now.UnixMilli() < 0 {
		return errors.New("login revoke time is invalid")
	}
	operationID := mutationID("login-revoke", subject, generation, ip.String(), attempt)
	event, err := eventlog.LoginRevoke(operationID, "", ip, location, now).Statement("1=1")
	if err != nil {
		return err
	}
	one := int64(1)
	first := rhiza.SQLStatement{
		SQL: `DELETE FROM identity_login_revoke
			WHERE subject=? AND generation=? AND code_envelope=?
			AND EXISTS (SELECT 1 FROM identity_users WHERE subject=?)
			RETURNING subject,
			'User ' || char(96) || COALESCE((SELECT NULLIF(email,'') FROM identity_user_profiles WHERE subject=identity_login_revoke.subject),
				(SELECT NULLIF(email,'') FROM identity_recovery_emails WHERE subject=identity_login_revoke.subject),
				(SELECT NULLIF(username,'') FROM identity_users WHERE subject=identity_login_revoke.subject), '') ||
				char(96) || ' revoked illegal login from ' || ? || ' (' || ? || ')' AS event_text`,
		Args: []any{subject, generation, envelope, subject, ip.String(), loginRevokeLocation(location)}, WantRows: true, ExpectedReturnedRows: &one,
	}
	event.Args[6] = nil
	event.OutputRefs = []rhiza.SQLStatementOutputRef{{ArgIndex: 6, StatementIndex: 0, ColumnName: "event_text"}}
	statements := []rhiza.SQLStatement{first,
		{SQL: `INSERT INTO oidc_backchannel_deliveries
			(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
			SELECT ?,client_id,NULL,subject,logout_uri,allow_private,allow_http,0,?,?
			FROM oidc_user_clients WHERE subject=? AND logout_uri <> ''`, Args: []any{operationID, now.UnixMilli(), now.UnixMilli(), subject}},
		{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE subject=?`, Args: []any{now.UnixMilli(), subject}},
		{SQL: `DELETE FROM browser_authorization_interactions WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, Args: []any{subject}},
		{SQL: `UPDATE oauth_authorize_codes SET invalidated=1 WHERE invalidated=0 AND json_extract(request_json,'$.subject')=?`, Args: []any{subject}},
		{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=?)`, Args: []any{subject}},
		{SQL: `UPDATE oauth_refresh_tokens SET active=0 WHERE active=1 AND json_extract(request_json,'$.subject')=?`, Args: []any{subject}},
		{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=?)`, Args: []any{subject}},
		{SQL: `DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=?`, Args: []any{subject}},
		{SQL: `UPDATE oauth_device_grants SET state='denied',claim_token_digest=NULL,claim_until_unix_ms=NULL WHERE subject=? AND state IN ('pending','approved')`, Args: []any{subject}},
		{SQL: `DELETE FROM identity_login_locations WHERE subject=?`, Args: []any{subject}},
		{SQL: `DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE subject=?)`, Args: []any{subject}},
		{SQL: `DELETE FROM oidc_user_clients WHERE subject=?`, Args: []any{subject}},
		event,
	}
	response, err := storage.ExecuteEnvelope(ctx, s.db, activeKeyID, rhiza.ExecuteRequest{RequestID: operationID, Statements: statements})
	if response.Status == "rejected" && response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrInvalidLoginRevokeCode
	}
	return err
}

func (s *Store) loginRevokeRecord(ctx context.Context, subject string) (string, []byte, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT generation,code_envelope FROM identity_login_revoke WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return "", nil, false, err
	}
	if len(result.Rows) == 0 {
		return "", nil, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return "", nil, false, errors.New("invalid login revoke row")
	}
	generation, ok := result.Rows[0][0].(string)
	if !ok || strings.TrimSpace(generation) == "" {
		return "", nil, false, errors.New("invalid login revoke generation")
	}
	envelope, ok := loginRevokeEnvelopeBytes(result.Rows[0][1])
	if !ok || len(envelope) == 0 {
		return "", nil, false, errors.New("invalid login revoke envelope")
	}
	return generation, envelope, true, nil
}

func (s *Store) ensureLoginRevokeSubject(ctx context.Context, subject string) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT 1 FROM identity_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(1) {
		return ErrInactiveSubject
	}
	return nil
}

func (s *Store) openLoginRevokeCode(keyring *oidc.Keyring, subject, generation string, envelope []byte) (string, error) {
	plain, err := keyring.OpenEnvelope(oidc.LoginRevokeCodePurpose(subject, generation), envelope)
	if err != nil {
		return "", err
	}
	if len(plain) != loginRevokeCodeLength || !validLoginRevokeCode(plain) {
		return "", errors.New("invalid login revoke code envelope")
	}
	return string(plain), nil
}

func (s *Store) newLoginRevokeCode() (string, error) {
	code := make([]byte, 0, loginRevokeCodeLength)
	raw := make([]byte, 64)
	for len(code) < loginRevokeCodeLength {
		if err := s.fillRandom(raw); err != nil {
			return "", err
		}
		for _, value := range raw {
			if value >= 248 {
				continue
			}
			code = append(code, loginRevokeAlphabet[int(value)%len(loginRevokeAlphabet)])
			if len(code) == loginRevokeCodeLength {
				return string(code), nil
			}
		}
	}
	return string(code), nil
}

func equalLoginRevokeCode(code string, plain []byte) bool {
	var candidate [loginRevokeCodeLength]byte
	copy(candidate[:], code)
	return len(code) == loginRevokeCodeLength && subtle.ConstantTimeCompare(candidate[:], plain) == 1
}

func validLoginRevokeCode(code []byte) bool {
	for _, value := range code {
		if !strings.ContainsRune(loginRevokeAlphabet, rune(value)) {
			return false
		}
	}
	return true
}

func loginRevokeLocation(location *string) string {
	if location == nil {
		return "Unknown Location"
	}
	return *location
}

func loginRevokeEnvelopeBytes(value any) ([]byte, bool) {
	switch value := value.(type) {
	case []byte:
		return value, true
	case string:
		return []byte(value), true
	default:
		return nil, false
	}
}
