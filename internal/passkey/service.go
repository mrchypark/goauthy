// Package passkey owns the WebAuthn persistence and ceremony boundary.
package passkey

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/tracing"
	"github.com/mrchypark/rhiza"
)

var (
	ErrInvalid  = errors.New("invalid passkey operation")
	ErrConflict = errors.New("passkey conflict")
	ErrNotFound = errors.New("passkey not found")
)

const defaultCeremonyTTL = time.Minute
const defaultRenewTTL = 2160 * time.Hour
const defaultMfaCodeTTL = 90 * time.Second
const modificationTTL = 120 * time.Second
const maxPasswordlessCookieLength = 4096

const (
	modificationPurpose       = "MfaModToken"
	passwordNewPurpose        = "PasswordNew"
	loginPurpose              = "login"
	passwordlessCookiePurpose = "passkey/passwordless-cookie"
)

type Config struct {
	RPID, RPDisplayName string
	Origins             []string
	ForceUV             bool
	CeremonyTTL         time.Duration
	MfaCodeTTL          time.Duration
	RenewTTL            time.Duration
	SessionIdleTimeout  time.Duration
	CookieKey           []byte
	PreviousCookieKey   []byte
	Keyring             EnvelopeKeyring
}

// EnvelopeKeyring supplies the active master-key envelope operations used for
// persisted passkey state and new passwordless cookies. CookieKey remains
// required for decrypting legacy DB rows and legacy passwordless cookies.
type EnvelopeKeyring interface {
	SealEnvelope(purpose string, plaintext []byte) ([]byte, error)
	OpenEnvelope(purpose string, envelope []byte) ([]byte, error)
	PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error)
	ActiveMasterKeyID() (string, error)
}

type Service struct {
	db                                *rhiza.DB
	wa                                *wa.WebAuthn
	forceUV                           bool
	ceremonyTTL, mfaCodeTTL, renewTTL time.Duration
	sessionIdleTimeout                time.Duration
	cookie                            cipher.AEAD
	previousCookie                    cipher.AEAD
	keyring                           EnvelopeKeyring
	now                               func() time.Time
	random                            io.Reader
}

type Credential struct {
	Name                 string
	Registered, LastUsed time.Time
	UserVerified         bool
}
type LoginResult struct{ Subject, InteractionToken, AuthenticationMethod string }
type account struct {
	subject, username string
	handle            []byte
	credentials       []wa.Credential
	credentialJSON    map[string]string
	credentialVersion map[string]int64
}

func (a account) WebAuthnID() []byte                   { return a.handle }
func (a account) WebAuthnName() string                 { return a.username }
func (a account) WebAuthnDisplayName() string          { return a.username }
func (a account) WebAuthnCredentials() []wa.Credential { return a.credentials }

func New(db *rhiza.DB, cfg Config) (*Service, error) {
	if db == nil || cfg.RPID == "" || cfg.RPDisplayName == "" || len(cfg.Origins) == 0 || len(cfg.CookieKey) != 32 || cfg.Keyring == nil {
		return nil, ErrInvalid
	}
	if cfg.CeremonyTTL == 0 {
		cfg.CeremonyTTL = defaultCeremonyTTL
	}
	if cfg.RenewTTL == 0 {
		cfg.RenewTTL = defaultRenewTTL
	}
	if cfg.MfaCodeTTL == 0 {
		cfg.MfaCodeTTL = defaultMfaCodeTTL
	}
	if cfg.SessionIdleTimeout == 0 {
		cfg.SessionIdleTimeout = browser.DefaultIdleTimeout
	}
	if cfg.CeremonyTTL <= 0 || cfg.MfaCodeTTL <= 0 || cfg.RenewTTL <= 0 || cfg.SessionIdleTimeout <= 0 {
		return nil, ErrInvalid
	}
	for _, origin := range cfg.Origins {
		u, err := url.Parse(origin)
		if err != nil || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Hostname() != "localhost") || (u.Hostname() != cfg.RPID && !strings.HasSuffix(u.Hostname(), "."+cfg.RPID)) {
			return nil, ErrInvalid
		}
	}
	block, err := aes.NewCipher(append([]byte(nil), cfg.CookieKey...))
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	var prevAEAD cipher.AEAD
	if len(cfg.PreviousCookieKey) == 32 {
		prevBlock, err := aes.NewCipher(append([]byte(nil), cfg.PreviousCookieKey...))
		if err != nil {
			return nil, ErrInvalid
		}
		prevAEAD, err = cipher.NewGCM(prevBlock)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	uv := protocol.VerificationPreferred
	if cfg.ForceUV {
		uv = protocol.VerificationRequired
	}
	rp, err := wa.New(&wa.Config{RPID: cfg.RPID, RPDisplayName: cfg.RPDisplayName, RPOrigins: append([]string(nil), cfg.Origins...), AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: uv}})
	if err != nil {
		return nil, err
	}
	return &Service{db: db, wa: rp, forceUV: cfg.ForceUV, ceremonyTTL: cfg.CeremonyTTL, mfaCodeTTL: cfg.MfaCodeTTL, renewTTL: cfg.RenewTTL, sessionIdleTimeout: cfg.SessionIdleTimeout, cookie: aead, previousCookie: prevAEAD, keyring: cfg.Keyring, now: time.Now, random: rand.Reader}, nil
}

func (s *Service) BeginRegistration(ctx context.Context, subject, username, name, sessionDigest string) (*protocol.CredentialCreation, string, time.Time, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.register.begin")
	defer span.End()
	if !validSubject(subject) || !validName(name) || !validDigest(sessionDigest) {
		return nil, "", time.Time{}, ErrInvalid
	}
	passkeyOnly, err := s.passkeyOnly(ctx, subject)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	u, err := s.user(ctx, subject, username, true, false)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	challenge, err := s.randomBytes(32)
	if err != nil {
		return nil, "", time.Time{}, ErrInvalid
	}
	registrationOptions := []wa.RegistrationOption{wa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged), wa.WithConveyancePreference(protocol.PreferNoAttestation), func(o *protocol.PublicKeyCredentialCreationOptions) error {
		o.Challenge = protocol.URLEncodedBase64(challenge)
		return nil
	}}
	if passkeyOnly {
		registrationOptions = append(registrationOptions, wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, RequireResidentKey: protocol.ResidentKeyNotRequired(), UserVerification: protocol.VerificationRequired}))
	}
	opts, state, err := s.wa.BeginRegistration(u, registrationOptions...)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	state.Expires = time.Time{}
	code, expires, err := s.saveCeremony(ctx, "register", subject, name, sessionDigest, "", "", state)
	return opts, code, expires, err
}

func (s *Service) BeginLogin(ctx context.Context, subject, username, interactionToken, sessionDigest string) (*protocol.CredentialAssertion, string, time.Time, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.login.begin")
	defer span.End()
	return s.beginLogin(ctx, subject, username, interactionToken, sessionDigest, "webauthn", false)
}

// BeginMFALogin starts the user-verified assertion required by a force_mfa
// authorization. Only credentials whose registration assertion included UV
// are eligible; global ForceUV and account mode cannot weaken this contract.
func (s *Service) BeginMFALogin(ctx context.Context, subject, username, interactionToken, sessionDigest string) (*protocol.CredentialAssertion, string, time.Time, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.mfa.begin")
	defer span.End()
	return s.beginLogin(ctx, subject, username, interactionToken, sessionDigest, "mfa", true)
}

func (s *Service) beginLogin(ctx context.Context, subject, username, interactionToken, sessionDigest, authenticationMethod string, forceUV bool) (*protocol.CredentialAssertion, string, time.Time, error) {
	if !validSubject(subject) || !validDigest(sessionDigest) || interactionToken == "" {
		return nil, "", time.Time{}, ErrInvalid
	}
	passkeyOnly, err := s.passkeyOnly(ctx, subject)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	requireUV := forceUV || passkeyOnly
	u, err := s.user(ctx, subject, username, false, requireUV)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	challenge, err := s.randomBytes(32)
	if err != nil {
		return nil, "", time.Time{}, ErrInvalid
	}
	loginOptions := []wa.LoginOption{wa.WithChallenge(protocol.URLEncodedBase64(challenge))}
	if requireUV {
		loginOptions = append(loginOptions, wa.WithUserVerification(protocol.VerificationRequired))
	}
	opts, state, err := s.wa.BeginLogin(u, loginOptions...)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	state.Expires = time.Time{}
	code, expires, err := s.saveCeremony(ctx, loginPurpose, subject, "", sessionDigest, interactionToken, authenticationMethod, state)
	return opts, code, expires, err
}

// BeginModificationProof starts the service WebAuthn ceremony Rauthy uses to
// authorize MFA-key changes. The proof returned by FinishModificationProof is
// generated here but is kept only inside this encrypted ceremony state.
func (s *Service) BeginModificationProof(ctx context.Context, subject, username, sessionDigest string) (*protocol.CredentialAssertion, string, time.Time, error) {
	return s.beginServiceProof(ctx, modificationPurpose, subject, username, sessionDigest)
}

// BeginPasswordNewProof starts a user-verified WebAuthn proof for a password
// change. Its proof is purpose-bound and cannot authorize MFA modification.
func (s *Service) BeginPasswordNewProof(ctx context.Context, subject, username, sessionDigest string) (*protocol.CredentialAssertion, string, time.Time, error) {
	return s.beginServiceProof(ctx, passwordNewPurpose, subject, username, sessionDigest)
}

func (s *Service) beginServiceProof(ctx context.Context, purpose, subject, username, sessionDigest string) (*protocol.CredentialAssertion, string, time.Time, error) {
	if !validServicePurpose(purpose) {
		return nil, "", time.Time{}, ErrInvalid
	}
	if !validSubject(subject) || !validDigest(sessionDigest) {
		return nil, "", time.Time{}, ErrInvalid
	}
	passkeyOnly, err := s.passkeyOnly(ctx, subject)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	requireUV := purpose == passwordNewPurpose || s.forceUV || passkeyOnly
	u, err := s.user(ctx, subject, username, false, requireUV)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	challenge, err := s.randomBytes(32)
	if err != nil {
		return nil, "", time.Time{}, ErrInvalid
	}
	options := []wa.LoginOption{wa.WithChallenge(protocol.URLEncodedBase64(challenge))}
	if requireUV {
		options = append(options, wa.WithUserVerification(protocol.VerificationRequired))
	}
	opts, state, err := s.wa.BeginLogin(u, options...)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	state.Expires = time.Time{}
	proof, err := s.alnum(48)
	if err != nil {
		return nil, "", time.Time{}, ErrInvalid
	}
	code, exp, err := s.saveModificationCeremony(ctx, purpose, subject, sessionDigest, state, proof)
	return opts, code, exp, err
}

// FinishModificationProof verifies the service assertion and returns a
// short-lived proof that can be exchanged once for an MFA modification token.
func (s *Service) FinishModificationProof(ctx context.Context, subject, sessionDigest, code string, r *http.Request) (string, error) {
	c, err := s.loadModificationCeremony(ctx, subject, sessionDigest, code)
	if err != nil {
		return "", err
	}
	cred, err := s.wa.FinishLogin(c.user, c.state, r)
	if err != nil {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return "", ErrInvalid
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	raw, writerKeyID, err := s.encryptDB(raw, credentialEnvelopePurpose(subject))
	if err != nil {
		return "", ErrInvalid
	}
	old, version := c.oldCount(id), c.oldVersion(id)
	if old < 0 || version < 0 || (old > 0 && int64(cred.Authenticator.SignCount) <= old) {
		return "", ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	attempt, err := s.token(16)
	if err != nil {
		return "", ErrInvalid
	}
	proofDigest := challengeDigest(c.proof)
	credentialJSON := base64.RawURLEncoding.EncodeToString(raw)
	_, err = s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-mfa-finish", c.digest, attempt), Statements: mfaFinishStatements(c.digest, proofDigest, c.purpose, subject, sessionDigest, attempt, id, credentialJSON, int64(cred.Authenticator.SignCount), old, version, now, c.proofExpiry)})
	if err != nil || !s.mfaCeremonyConsumed(ctx, c.digest, attempt) || !s.credentialAtVersion(ctx, subject, id, version+1) || !s.mfaProofReady(ctx, proofDigest, c.purpose, subject, sessionDigest, c.proofExpiry) {
		return "", ErrConflict
	}
	return c.proof, nil
}

func mfaFinishStatements(ceremonyDigest, proofDigest, purpose, subject, sessionDigest, attempt, credentialID, credentialJSON string, signCount, old, version int64, now, proofExpiry time.Time) []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `UPDATE identity_webauthn_mfa_ceremonies SET consumed_attempt=?,consumed_at_unix_ms=? WHERE code_digest=? AND subject=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>? AND EXISTS (SELECT 1 FROM identity_webauthn_service_ceremony_purposes WHERE code_digest=? AND purpose=?) AND EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE credential_id=? AND subject=? AND sign_count=? AND credential_version=?) AND NOT EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE code_digest=?)`, Args: []any{attempt, now.UnixMilli(), ceremonyDigest, subject, sessionDigest, now.UnixMilli(), ceremonyDigest, purpose, credentialID, subject, old, version, proofDigest}},
		{SQL: `UPDATE identity_webauthn_credentials SET credential_json=?,sign_count=?,credential_version=credential_version+1,last_used_at_unix_ms=? WHERE credential_id=? AND subject=? AND sign_count=? AND credential_version=? AND changes()=1 AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_ceremonies WHERE code_digest=? AND consumed_attempt=?)`, Args: []any{credentialJSON, signCount, now.UnixMilli(), credentialID, subject, old, version, ceremonyDigest, attempt}},
		{SQL: `INSERT INTO identity_webauthn_mfa_proofs (code_digest,subject,session_digest,expires_at_unix_ms) SELECT ?,?,?,? WHERE changes()=1 AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_ceremonies WHERE code_digest=? AND consumed_attempt=?)`, Args: []any{proofDigest, subject, sessionDigest, proofExpiry.UnixMilli(), ceremonyDigest, attempt}},
		{SQL: `INSERT INTO identity_webauthn_service_proof_purposes (code_digest,purpose) SELECT ?,? WHERE changes()=1 AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE code_digest=?)`, Args: []any{proofDigest, purpose, proofDigest}},
	}
}

func (s *Service) FinishRegistration(ctx context.Context, subject, name, sessionDigest, code string, r *http.Request) (Credential, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.register.finish")
	defer span.End()
	c, err := s.loadCeremony(ctx, "register", subject, name, sessionDigest, code)
	if err != nil {
		return Credential{}, err
	}
	u, err := s.user(ctx, subject, "", false, false)
	if err != nil {
		return Credential{}, err
	}
	cred, err := s.wa.FinishRegistration(u, c.state, r)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	raw, writerKeyID, err := s.encryptDB(raw, credentialEnvelopePurpose(subject))
	if err != nil {
		return Credential{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	attempt, err := s.token(16)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	res, err := s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-register", c.digest, attempt), Statements: registrationFinishStatements(c.digest, attempt, subject, name, sessionDigest, id, base64.RawURLEncoding.EncodeToString(raw), int64(cred.Authenticator.SignCount), boolInt(cred.Flags.UserVerified), now, s.sessionIdleTimeout)})
	if err != nil || res.RowsAffected < 3 {
		return Credential{}, ErrConflict
	}
	if !s.ceremonyConsumed(ctx, c.digest, attempt) {
		return Credential{}, ErrConflict
	}
	return Credential{Name: name, Registered: now, LastUsed: now, UserVerified: cred.Flags.UserVerified}, nil
}

// FinishPasskeyRegistration completes a passkey registration ceremony for
// passkey-first public registration. Unlike FinishRegistration, it does not
// require an active browser session.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, subject, name, sessionDigest, code string, r *http.Request) (Credential, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.register.finish.passkey")
	defer span.End()
	c, err := s.loadCeremony(ctx, "register", subject, name, sessionDigest, code)
	if err != nil {
		return Credential{}, err
	}
	u, err := s.user(ctx, subject, "", false, false)
	if err != nil {
		return Credential{}, err
	}
	cred, err := s.wa.FinishRegistration(u, c.state, r)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	raw, writerKeyID, err := s.encryptDB(raw, credentialEnvelopePurpose(subject))
	if err != nil {
		return Credential{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	attempt, err := s.token(16)
	if err != nil {
		return Credential{}, ErrInvalid
	}
	res, err := s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-register", c.digest, attempt), Statements: passkeyRegistrationFinishStatements(c.digest, attempt, subject, name, id, base64.RawURLEncoding.EncodeToString(raw), int64(cred.Authenticator.SignCount), boolInt(cred.Flags.UserVerified), now)})
	if err != nil || res.RowsAffected < 2 {
		return Credential{}, ErrConflict
	}
	if !s.ceremonyConsumed(ctx, c.digest, attempt) {
		return Credential{}, ErrConflict
	}
	return Credential{Name: name, Registered: now, LastUsed: now, UserVerified: cred.Flags.UserVerified}, nil
}

// registrationFinishStatements is one Rhiza transaction. The session update
// is deliberately first: the ceremony and credential writes are guarded by
// the resulting MFA/external session state, so an expired, revoked, idle, or
// wrong-subject browser session cannot leave a credential behind. External
// authentication remains truthful; it is a valid enrollment session but is
// never relabeled as MFA.
func registrationFinishStatements(ceremonyDigest, attempt, subject, name, sessionDigest, credentialID, credentialJSON string, signCount, userVerified int64, now time.Time, sessionIdleTimeout time.Duration) []rhiza.SQLStatement {
	nowMS := now.UTC().Truncate(time.Millisecond).UnixMilli()
	idleCutoff := now.UTC().Add(-sessionIdleTimeout).UnixMilli()
	return []rhiza.SQLStatement{
		{SQL: `UPDATE browser_sessions
			SET auth_method = CASE WHEN auth_method = 'external' OR ? = 0 THEN auth_method ELSE 'mfa' END
			WHERE token_digest=? AND subject=? AND auth_method IN ('pwd','webauthn','mfa','external')
			  AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>? AND last_seen_at_unix_ms>?
			  AND EXISTS (SELECT 1 FROM identity_webauthn_ceremonies
				WHERE code_digest=? AND purpose='register' AND subject=? AND passkey_name=?
				  AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>?)
			  AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)
			  AND NOT EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE credential_id=? OR (subject=? AND name=?))`,
			Args: []any{userVerified, sessionDigest, subject, nowMS, idleCutoff, ceremonyDigest, subject, name, sessionDigest, nowMS, subject, credentialID, subject, name}},
		{SQL: `UPDATE identity_webauthn_ceremonies
			SET consumed_attempt=?,consumed_at_unix_ms=?
			WHERE code_digest=? AND purpose='register' AND subject=? AND passkey_name=?
			  AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>?
			  AND changes()=1
			  AND EXISTS (SELECT 1 FROM browser_sessions
				WHERE token_digest=? AND subject=? AND auth_method IN ('pwd','webauthn','mfa','external')
				  AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>? AND last_seen_at_unix_ms>?)
			  AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`,
			Args: []any{attempt, nowMS, ceremonyDigest, subject, name, sessionDigest, nowMS, sessionDigest, subject, nowMS, idleCutoff, subject}},
		{SQL: `INSERT INTO identity_webauthn_credentials
			(credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms)
			SELECT ?,?,?,?,?,?,?,?
			WHERE changes()=1
			  AND EXISTS (SELECT 1 FROM identity_webauthn_ceremonies
				WHERE code_digest=? AND consumed_attempt=? AND subject=? AND session_digest=?)
			  AND EXISTS (SELECT 1 FROM browser_sessions
				WHERE token_digest=? AND subject=? AND auth_method IN ('pwd','webauthn','mfa','external')
				  AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms>? AND last_seen_at_unix_ms>?)
			  AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`,
			Args: []any{credentialID, subject, name, credentialJSON, signCount, userVerified, nowMS, nowMS, ceremonyDigest, attempt, subject, sessionDigest, sessionDigest, subject, nowMS, idleCutoff, subject}},
	}
}

func passkeyRegistrationFinishStatements(ceremonyDigest, attempt, subject, name, credentialID, credentialJSON string, signCount, userVerified int64, now time.Time) []rhiza.SQLStatement {
	nowMS := now.UTC().Truncate(time.Millisecond).UnixMilli()
	return []rhiza.SQLStatement{
		{SQL: `UPDATE identity_webauthn_ceremonies
			SET consumed_attempt=?,consumed_at_unix_ms=?
			WHERE code_digest=? AND purpose='register' AND subject=? AND passkey_name=?
			  AND consumed_attempt IS NULL AND expires_at_unix_ms>?
			  AND changes()=1
			  AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)
			  AND NOT EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE credential_id=? OR (subject=? AND name=?))`,
			Args: []any{attempt, nowMS, ceremonyDigest, subject, name, nowMS, subject, credentialID, subject, name}},
		{SQL: `INSERT INTO identity_webauthn_credentials
			(credential_id,subject,name,credential_json,sign_count,user_verified,registered_at_unix_ms,last_used_at_unix_ms)
			SELECT ?,?,?,?,?,?,?,?
			WHERE changes()=1
			  AND EXISTS (SELECT 1 FROM identity_webauthn_ceremonies
				WHERE code_digest=? AND consumed_attempt=? AND subject=?)
			  AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0)`,
			Args: []any{credentialID, subject, name, credentialJSON, signCount, userVerified, nowMS, nowMS, ceremonyDigest, attempt, subject, subject}},
	}
}

func (s *Service) FinishLogin(ctx context.Context, sessionDigest, code string, r *http.Request) (LoginResult, error) {
	ctx, span := tracing.NewTracer("goauthy/passkey").Start(ctx, "passkey.login.finish")
	defer span.End()
	c, err := s.loadCeremony(ctx, loginPurpose, "", "", sessionDigest, code)
	if err != nil {
		return LoginResult{}, err
	}
	u, err := s.user(ctx, c.subject, "", false, false)
	if err != nil {
		return LoginResult{}, err
	}
	cred, err := s.wa.FinishLogin(u, c.state, r)
	if err != nil {
		return LoginResult{}, ErrInvalid
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return LoginResult{}, ErrInvalid
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	raw, writerKeyID, err := s.encryptDB(raw, credentialEnvelopePurpose(c.subject))
	if err != nil {
		return LoginResult{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	attempt, err := s.token(16)
	if err != nil {
		return LoginResult{}, ErrInvalid
	}
	old := c.oldCount(id)
	version := c.oldVersion(id)
	if old < 0 || version < 0 || (old > 0 && int64(cred.Authenticator.SignCount) <= old) {
		return LoginResult{}, ErrInvalid
	}
	res, err := s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-login", c.digest, attempt), Statements: loginFinishStatements(c.digest, c.purpose, c.subject, sessionDigest, attempt, id, base64.RawURLEncoding.EncodeToString(raw), int64(cred.Authenticator.SignCount), old, version, now)})
	if err != nil || res.RowsAffected < 2 {
		return LoginResult{}, ErrConflict
	}
	if !s.ceremonyConsumed(ctx, c.digest, attempt) {
		return LoginResult{}, ErrConflict
	}
	if !s.credentialAtVersion(ctx, c.subject, id, version+1) {
		return LoginResult{}, ErrConflict
	}
	return LoginResult{Subject: c.subject, InteractionToken: c.interaction, AuthenticationMethod: c.authenticationMethod}, nil
}

func loginFinishStatements(ceremonyDigest, purpose, subject, sessionDigest, attempt, credentialID, credentialJSON string, signCount, old, version int64, now time.Time) []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `UPDATE identity_webauthn_ceremonies SET consumed_attempt=?,consumed_at_unix_ms=? WHERE code_digest=? AND purpose=? AND subject=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>? AND EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE credential_id=? AND subject=? AND sign_count=? AND credential_version=?)`, Args: []any{attempt, now.UnixMilli(), ceremonyDigest, purpose, subject, sessionDigest, now.UnixMilli(), credentialID, subject, old, version}},
		{SQL: `UPDATE identity_webauthn_credentials SET credential_json=?,sign_count=?,credential_version=credential_version+1,last_used_at_unix_ms=? WHERE credential_id=? AND subject=? AND sign_count=? AND credential_version=? AND changes()=1 AND EXISTS (SELECT 1 FROM identity_webauthn_ceremonies WHERE code_digest=? AND consumed_attempt=?)`, Args: []any{credentialJSON, signCount, now.UnixMilli(), credentialID, subject, old, version, ceremonyDigest, attempt}},
	}
}

func (s *Service) List(ctx context.Context, subject string) ([]Credential, error) {
	if !validSubject(subject) {
		return nil, ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,registered_at_unix_ms,last_used_at_unix_ms,user_verified FROM identity_webauthn_credentials WHERE subject=? ORDER BY registered_at_unix_ms,name`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(q.Rows))
	for _, r := range q.Rows {
		if len(r) != 4 {
			return nil, ErrInvalid
		}
		n, ok := r[0].(string)
		a, aok := r[1].(int64)
		b, bok := r[2].(int64)
		uv, uok := r[3].(int64)
		if !ok || !aok || !bok || !uok {
			return nil, ErrInvalid
		}
		out = append(out, Credential{n, time.UnixMilli(a).UTC(), time.UnixMilli(b).UTC(), uv == 1})
	}
	return out, nil
}
func (s *Service) Delete(ctx context.Context, subject, name string) error {
	if !validSubject(subject) || !validName(name) {
		return ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id,credential_version FROM identity_webauthn_credentials WHERE subject=? AND name=?`, Args: []any{subject, name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 2 {
		return ErrNotFound
	}
	id, iok := q.Rows[0][0].(string)
	version, vok := q.Rows[0][1].(int64)
	if !iok || !vok || version < 0 {
		return ErrInvalid
	}
	// The predicate is evaluated by the same replicated mutation as the delete:
	// conversion cannot make the final verified passkey disappear between a read
	// and this write. The receipt is keyed by request ID, so a rejection must
	// carry its own operation identity: reusing the credential CAS version alone
	// would replay the stored zero-row receipt once the final-key protection
	// stops applying, and enrolling another credential need not bump this one's
	// version. The CAS predicate itself stays pinned to the version read here.
	attempt, err := s.token(16)
	if err != nil {
		return ErrInvalid
	}
	res, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-delete", subject, id, strconv.FormatInt(version, 10), attempt), SQL: `DELETE FROM identity_webauthn_credentials WHERE subject=? AND credential_id=? AND credential_version=? AND (NOT EXISTS (SELECT 1 FROM identity_authentication_modes WHERE subject=? AND mode='passkey') OR EXISTS (SELECT 1 FROM identity_webauthn_credentials AS retained WHERE retained.subject=? AND retained.credential_id<>? AND retained.user_verified=1))`, Args: []any{subject, id, version, subject, subject, id}})
	if err != nil {
		return err
	}
	if res.RowsAffected != 1 {
		return ErrConflict
	}
	q, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id FROM identity_webauthn_credentials WHERE subject=? AND credential_id=?`, Args: []any{subject, id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 0 {
		return ErrConflict
	}
	return nil
}

// DeleteForAdministrator is the administrative reset operation. Unlike Delete,
// it intentionally permits removal of the final user-verified passkey, matching
// Rauthy. The replicated DELETE itself checks the active actor's current admin
// membership, so a role revocation between a request check and this mutation
// cannot authorize a reset.
func (s *Service) DeleteForAdministrator(ctx context.Context, actor, subject, name string) error {
	if !validSubject(actor) || !validSubject(subject) || actor == subject || !validName(name) {
		return ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id,credential_version FROM identity_webauthn_credentials WHERE subject=? AND name=?`, Args: []any{subject, name}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 2 {
		return ErrNotFound
	}
	id, iok := q.Rows[0][0].(string)
	version, vok := q.Rows[0][1].(int64)
	if !iok || !vok || version < 0 {
		return ErrInvalid
	}
	res, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-admin-delete", actor, subject, id, strconv.FormatInt(version, 10)), SQL: `DELETE FROM identity_webauthn_credentials WHERE subject=? AND credential_id=? AND credential_version=? AND EXISTS (SELECT 1 FROM identity_users u JOIN rbac_user_roles m ON m.subject=u.subject JOIN rbac_roles r ON r.id=m.role_id WHERE u.subject=? AND u.disabled=0 AND r.name='rauthy_admin')`, Args: []any{subject, id, version, actor}})
	if err != nil || res.RowsAffected != 1 {
		return ErrConflict
	}
	q, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_id FROM identity_webauthn_credentials WHERE subject=? AND credential_id=?`, Args: []any{subject, id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 0 {
		return ErrConflict
	}
	return nil
}

// HasCredentials reports whether the account has any active WebAuthn credential.
func (s *Service) HasCredentials(ctx context.Context, subject string) (bool, error) {
	if !validSubject(subject) {
		return false, ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM identity_webauthn_credentials WHERE subject=? LIMIT 1`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(q.Rows) != 0, nil
}

// IssuePasswordModificationToken is deliberately unavailable once an account
// has a passkey: Rauthy requires a fresh mfa_code in that case.
func (s *Service) IssuePasswordModificationToken(ctx context.Context, subject, sessionDigest string) (string, time.Time, error) {
	if !validSubject(subject) || !validDigest(sessionDigest) {
		return "", time.Time{}, ErrInvalid
	}
	hasCredentials, err := s.HasCredentials(ctx, subject)
	if err != nil || hasCredentials {
		return "", time.Time{}, ErrInvalid
	}
	return s.issueModificationToken(ctx, subject, sessionDigest, true)
}

// IssueModificationToken is retained for source compatibility, but routes
// through the conditional password-only boundary.
func (s *Service) IssueModificationToken(ctx context.Context, subject, sessionDigest string) (string, time.Time, error) {
	return s.IssuePasswordModificationToken(ctx, subject, sessionDigest)
}

func (s *Service) issueModificationToken(ctx context.Context, subject, sessionDigest string, requireNoCredentials bool) (string, time.Time, error) {
	raw, err := s.alnum(32)
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	exp := now.Add(modificationTTL)
	digest := challengeDigest(raw)
	guard := ""
	if requireNoCredentials {
		guard = " WHERE NOT EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE subject=?)"
	}
	args := []any{digest, subject, sessionDigest, exp.UnixMilli()}
	if requireNoCredentials {
		args = append(args, subject)
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-mod-issue", digest), Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) SELECT ?,?,?,?` + guard, Args: args},
		{SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) SELECT ?,'password' WHERE EXISTS (SELECT 1 FROM identity_mfa_mod_tokens WHERE token_digest=?)`, Args: []any{digest, digest}},
	}})
	if err != nil {
		return "", time.Time{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,session_digest,expires_at_unix_ms,consumed_attempt FROM identity_mfa_mod_tokens WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 4 || q.Rows[0][0] != subject || q.Rows[0][1] != sessionDigest || q.Rows[0][2] != exp.UnixMilli() || q.Rows[0][3] != nil || !s.modificationFactor(ctx, digest, "password") {
		return "", time.Time{}, ErrConflict
	}
	return raw, exp, nil
}

// ExchangeModificationProof consumes a successful MFA WebAuthn proof and
// issues the existing session-bound modification token in the same Rhiza
// transaction. A proof cannot be replayed to mint another token.
func (s *Service) ExchangeModificationProof(ctx context.Context, subject, sessionDigest, proof string) (string, time.Time, error) {
	if !validSubject(subject) || !validDigest(sessionDigest) || !validCode(proof) {
		return "", time.Time{}, ErrInvalid
	}
	hasCredentials, err := s.HasCredentials(ctx, subject)
	if err != nil || !hasCredentials {
		return "", time.Time{}, ErrInvalid
	}
	raw, err := s.alnum(32)
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	exp := now.Add(modificationTTL)
	attempt, err := s.token(16)
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	proofDigest, tokenDigest := challengeDigest(proof), challengeDigest(raw)
	res, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-mfa-exchange", proofDigest, attempt), Statements: modificationProofExchangeStatements(proofDigest, tokenDigest, subject, sessionDigest, attempt, now, exp)})
	if err != nil || res.RowsAffected < 2 || !s.mfaProofConsumed(ctx, proofDigest, attempt) || !s.modificationTokenReady(ctx, tokenDigest, subject, sessionDigest, exp) || !s.modificationFactor(ctx, tokenDigest, "webauthn") {
		return "", time.Time{}, ErrConflict
	}
	return raw, exp, nil
}

func modificationProofExchangeStatements(proofDigest, tokenDigest, subject, sessionDigest, attempt string, now, exp time.Time) []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_mfa_mod_token_factors WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_mfa_mod_tokens WHERE token_digest IN (SELECT token_digest FROM identity_mfa_mod_tokens WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `UPDATE identity_webauthn_mfa_proofs SET consumed_attempt=?,consumed_at_unix_ms=? WHERE code_digest=? AND subject=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>? AND EXISTS (SELECT 1 FROM identity_webauthn_service_proof_purposes WHERE code_digest=? AND purpose=?) AND EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE subject=?) AND NOT EXISTS (SELECT 1 FROM identity_mfa_mod_tokens WHERE token_digest=?)`, Args: []any{attempt, now.UnixMilli(), proofDigest, subject, sessionDigest, now.UnixMilli(), proofDigest, modificationPurpose, subject, tokenDigest}},
		{SQL: `INSERT INTO identity_mfa_mod_tokens (token_digest,subject,session_digest,expires_at_unix_ms) SELECT ?,?,?,? WHERE changes()=1 AND EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE code_digest=? AND consumed_attempt=?) AND EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE subject=?)`, Args: []any{tokenDigest, subject, sessionDigest, exp.UnixMilli(), proofDigest, attempt, subject}},
		{SQL: `INSERT INTO identity_mfa_mod_token_factors (token_digest,proof_kind) SELECT ?,'webauthn' WHERE changes()=1 AND EXISTS (SELECT 1 FROM identity_mfa_mod_tokens WHERE token_digest=?)`, Args: []any{tokenDigest, tokenDigest}},
	}
}
func (s *Service) ConsumeModificationToken(ctx context.Context, subject, sessionDigest, raw string) error {
	if !validSubject(subject) || !validDigest(sessionDigest) || len(raw) != 32 {
		return ErrInvalid
	}
	for _, b := range raw {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", b) {
			return ErrInvalid
		}
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	attempt, err := s.token(16)
	if err != nil {
		return ErrInvalid
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-mod-consume", challengeDigest(raw), attempt), SQL: `UPDATE identity_mfa_mod_tokens SET consumed_attempt=?,consumed_at_unix_ms=? WHERE token_digest=? AND subject=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms>? AND EXISTS (SELECT 1 FROM identity_mfa_mod_token_factors WHERE token_digest=? AND (proof_kind='webauthn' OR (proof_kind='password' AND NOT EXISTS (SELECT 1 FROM identity_webauthn_credentials WHERE subject=?))))`, Args: []any{attempt, now.UnixMilli(), challengeDigest(raw), subject, sessionDigest, now.UnixMilli(), challengeDigest(raw), subject}})
	if err != nil {
		return ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_mfa_mod_tokens WHERE token_digest=?`, Args: []any{challengeDigest(raw)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		return ErrInvalid
	}
	v, ok := q.Rows[0][0].(string)
	if !ok || v != attempt {
		return ErrConflict
	}
	return nil
}

func (s *Service) PasswordlessCookie(subject string) (string, error) {
	if !validSubject(subject) {
		return "", ErrInvalid
	}
	exp := s.now().UTC().Add(s.renewTTL).Unix()
	plain := []byte(subject + "\x00" + strconv.FormatInt(exp, 10))
	envelope, err := s.keyring.SealEnvelope(passwordlessCookiePurpose, plain)
	if err != nil {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(envelope), nil
}
func (s *Service) SubjectFromCookie(v string) (string, error) {
	if len(v) == 0 || len(v) > maxPasswordlessCookieLength {
		return "", ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != v {
		return "", ErrInvalid
	}
	var plain []byte
	if isPurposeEnvelope(raw) {
		plain, err = s.keyring.OpenEnvelope(passwordlessCookiePurpose, raw)
	} else {
		if len(raw) < s.cookie.NonceSize() {
			return "", ErrInvalid
		}
		plain, err = s.cookie.Open(nil, raw[:s.cookie.NonceSize()], raw[s.cookie.NonceSize():], nil)
		if err != nil && s.previousCookie != nil && len(raw) >= s.previousCookie.NonceSize() {
			plain, err = s.previousCookie.Open(nil, raw[:s.previousCookie.NonceSize()], raw[s.previousCookie.NonceSize():], nil)
		}
	}
	if err != nil {
		return "", ErrInvalid
	}
	p := strings.SplitN(string(plain), "\x00", 2)
	if len(p) != 2 || !validSubject(p[0]) {
		return "", ErrInvalid
	}
	e, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || e <= s.now().UTC().Unix() {
		return "", ErrInvalid
	}
	return p[0], nil
}

type ceremony struct {
	digest, purpose, subject, interaction, authenticationMethod string
	state                                                       wa.SessionData
	credentials                                                 []wa.Credential
	credentialVersion                                           map[string]int64
}
type sealedState struct {
	Session              wa.SessionData `json:"session"`
	Interaction          string         `json:"interaction,omitempty"`
	AuthenticationMethod string         `json:"authentication_method,omitempty"`
}

type modificationSealedState struct {
	Session wa.SessionData `json:"session"`
	Proof   string         `json:"proof"`
}

type modificationCeremony struct {
	digest, purpose, subject, proof string
	state                           wa.SessionData
	user                            account
	proofExpiry                     time.Time
}

func (c modificationCeremony) oldCount(id string) int64 {
	for _, credential := range c.user.credentials {
		if base64.RawURLEncoding.EncodeToString(credential.ID) == id {
			return int64(credential.Authenticator.SignCount)
		}
	}
	return -1
}

func (c modificationCeremony) oldVersion(id string) int64 { return c.user.credentialVersion[id] }

func (c ceremony) oldCount(id string) int64 {
	for _, x := range c.credentials {
		if base64.RawURLEncoding.EncodeToString(x.ID) == id {
			return int64(x.Authenticator.SignCount)
		}
	}
	return -1
}
func (c ceremony) oldVersion(id string) int64 {
	if c.credentialVersion == nil {
		return -1
	}
	return c.credentialVersion[id]
}
func (s *Service) user(ctx context.Context, subject, username string, create, verifiedOnly bool) (account, error) {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT user_handle FROM identity_webauthn_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return account{}, err
	}
	if len(q.Rows) == 0 && create {
		h, err := s.randomBytes(32)
		if err != nil {
			return account{}, ErrInvalid
		}
		now := s.now().UTC().UnixMilli()
		_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: rid("passkey-user", subject, base64.RawURLEncoding.EncodeToString(h)), SQL: `INSERT OR IGNORE INTO identity_webauthn_users (subject,user_handle,created_at_unix_ms) VALUES (?,?,?)`, Args: []any{subject, base64.RawURLEncoding.EncodeToString(h), now}})
		if err != nil {
			return account{}, err
		}
		q, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT user_handle FROM identity_webauthn_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return account{}, err
		}
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		return account{}, ErrNotFound
	}
	hs, ok := q.Rows[0][0].(string)
	h, err := base64.RawURLEncoding.DecodeString(hs)
	if !ok || err != nil || len(h) != 32 {
		return account{}, ErrInvalid
	}
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_json,credential_version,user_verified FROM identity_webauthn_credentials WHERE subject=? AND (?=0 OR user_verified=1)`, Args: []any{subject, boolInt(verifiedOnly)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return account{}, err
	}
	a := account{subject: subject, username: username, handle: h, credentialJSON: make(map[string]string), credentialVersion: make(map[string]int64)}
	for _, r := range rows.Rows {
		if len(r) != 3 {
			return account{}, ErrInvalid
		}
		v, ok := r[0].(string)
		version, vok := r[1].(int64)
		verified, uok := r[2].(int64)
		if !ok || !vok || !uok || version < 0 || (verified != 0 && verified != 1) {
			return account{}, ErrInvalid
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return account{}, ErrInvalid
		}
		var c wa.Credential
		plain, err := s.decryptDB(ciphertext, credentialEnvelopePurpose(subject), credentialAAD(subject))
		if err != nil || decodeCredentialJSON(plain, &c) != nil {
			return account{}, ErrInvalid
		}
		id := base64.RawURLEncoding.EncodeToString(c.ID)
		a.credentials = append(a.credentials, c)
		a.credentialJSON[id] = v
		a.credentialVersion[id] = version
	}
	return a, nil
}

func (s *Service) saveModificationCeremony(ctx context.Context, purpose, subject, sessionDigest string, state *wa.SessionData, proof string) (string, time.Time, error) {
	if !validServicePurpose(purpose) || !validCode(proof) {
		return "", time.Time{}, ErrInvalid
	}
	code, err := s.alnum(48)
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(s.ceremonyTTL)
	proofExpires := now.Add(s.mfaCodeTTL)
	digest := challengeDigest(code)
	raw, err := json.Marshal(modificationSealedState{Session: *state, Proof: proof})
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	raw, writerKeyID, err := s.encryptDB(raw, mfaCeremonyEnvelopePurpose(subject, digest))
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	_, err = s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-mfa-start", digest), Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE NOT EXISTS (SELECT 1 FROM identity_webauthn_mfa_ceremonies WHERE identity_webauthn_mfa_ceremonies.code_digest=identity_webauthn_service_ceremony_purposes.code_digest)`},
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE NOT EXISTS (SELECT 1 FROM identity_webauthn_mfa_proofs WHERE identity_webauthn_mfa_proofs.code_digest=identity_webauthn_service_proof_purposes.code_digest)`},
		{SQL: `DELETE FROM identity_webauthn_service_ceremony_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_webauthn_service_proof_purposes WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_webauthn_mfa_ceremonies WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_ceremonies WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `DELETE FROM identity_webauthn_mfa_proofs WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_mfa_proofs WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_mfa_ceremonies (code_digest,subject,session_digest,session_json,expires_at_unix_ms,proof_expires_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{digest, subject, sessionDigest, base64.RawURLEncoding.EncodeToString(raw), expires.UnixMilli(), proofExpires.UnixMilli()}},
		{SQL: `INSERT INTO identity_webauthn_service_ceremony_purposes (code_digest,purpose) VALUES (?,?)`, Args: []any{digest, purpose}},
	}})
	if err != nil {
		return "", time.Time{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,session_digest,expires_at_unix_ms,proof_expires_at_unix_ms,consumed_attempt FROM identity_webauthn_mfa_ceremonies WHERE code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 5 || q.Rows[0][0] != subject || q.Rows[0][1] != sessionDigest || q.Rows[0][2] != expires.UnixMilli() || q.Rows[0][3] != proofExpires.UnixMilli() || q.Rows[0][4] != nil {
		return "", time.Time{}, ErrConflict
	}
	return code, expires, nil
}

func (s *Service) loadModificationCeremony(ctx context.Context, subject, sessionDigest, code string) (modificationCeremony, error) {
	if !validSubject(subject) || !validDigest(sessionDigest) || !validCode(code) {
		return modificationCeremony{}, ErrInvalid
	}
	digest := challengeDigest(code)
	now := s.now().UTC().Truncate(time.Millisecond)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT c.session_json,c.expires_at_unix_ms,c.proof_expires_at_unix_ms,c.consumed_attempt,p.purpose FROM identity_webauthn_mfa_ceremonies c JOIN identity_webauthn_service_ceremony_purposes p ON p.code_digest=c.code_digest WHERE c.code_digest=? AND c.subject=? AND c.session_digest=?`, Args: []any{digest, subject, sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return modificationCeremony{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 5 {
		return modificationCeremony{}, ErrNotFound
	}
	enc, ok := q.Rows[0][0].(string)
	expires, eok := q.Rows[0][1].(int64)
	proofExpires, pok := q.Rows[0][2].(int64)
	purpose, purposeOK := q.Rows[0][4].(string)
	if !ok || !eok || !pok || !purposeOK || !validServicePurpose(purpose) || expires <= now.UnixMilli() || proofExpires <= now.UnixMilli() || q.Rows[0][3] != nil {
		return modificationCeremony{}, ErrInvalid
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return modificationCeremony{}, ErrInvalid
	}
	raw, err := s.decryptDB(ciphertext, mfaCeremonyEnvelopePurpose(subject, digest), mfaCeremonyAAD(subject, digest))
	if err != nil {
		return modificationCeremony{}, ErrInvalid
	}
	var sealed modificationSealedState
	if decodeModificationSealedStateJSON(raw, &sealed) != nil || !validCode(sealed.Proof) {
		return modificationCeremony{}, ErrInvalid
	}
	passkeyOnly, err := s.passkeyOnly(ctx, subject)
	if err != nil {
		return modificationCeremony{}, err
	}
	requireUV := s.forceUV || passkeyOnly
	u, err := s.user(ctx, subject, "", false, requireUV)
	if err != nil {
		return modificationCeremony{}, err
	}
	return modificationCeremony{digest: digest, purpose: purpose, subject: subject, proof: sealed.Proof, state: sealed.Session, user: u, proofExpiry: time.UnixMilli(proofExpires).UTC()}, nil
}
func (s *Service) saveCeremony(ctx context.Context, purpose, subject, name, sessionDigest, interaction, authenticationMethod string, state *wa.SessionData) (string, time.Time, error) {
	code, err := s.alnum(48)
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	raw, err := json.Marshal(sealedState{Session: *state, Interaction: interaction, AuthenticationMethod: authenticationMethod})
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(s.ceremonyTTL)
	digest := challengeDigest(code)
	interactionDigest := ""
	if interaction != "" {
		interactionDigest = challengeDigest(interaction)
	}
	raw, writerKeyID, err := s.encryptDB(raw, ceremonyEnvelopePurpose(purpose, subject, digest))
	if err != nil {
		return "", time.Time{}, ErrInvalid
	}
	_, err = s.executeEnvelope(ctx, writerKeyID, rhiza.ExecuteRequest{RequestID: rid("passkey-ceremony", digest), Statements: []rhiza.SQLStatement{{SQL: `DELETE FROM identity_webauthn_ceremonies WHERE code_digest IN (SELECT code_digest FROM identity_webauthn_ceremonies WHERE expires_at_unix_ms <= ? ORDER BY expires_at_unix_ms LIMIT 64)`, Args: []any{now.UnixMilli()}}, {SQL: `INSERT INTO identity_webauthn_ceremonies (code_digest,purpose,subject,session_digest,interaction_digest,passkey_name,session_json,expires_at_unix_ms) VALUES (?,?,?,?,?,?,?,?)`, Args: []any{digest, purpose, subject, sessionDigest, nilIfEmpty(interactionDigest), nilIfEmpty(name), base64.RawURLEncoding.EncodeToString(raw), expires.UnixMilli()}}}})
	if err != nil {
		return "", time.Time{}, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT purpose,subject,session_digest,expires_at_unix_ms,consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 5 || q.Rows[0][0] != purpose || q.Rows[0][1] != subject || q.Rows[0][2] != sessionDigest || q.Rows[0][3] != expires.UnixMilli() || q.Rows[0][4] != nil {
		return "", time.Time{}, ErrConflict
	}
	return code, expires, nil
}
func (s *Service) loadCeremony(ctx context.Context, purpose, subject, name, sessionDigest, code string) (ceremony, error) {
	if !validDigest(sessionDigest) || !validCode(code) {
		return ceremony{}, ErrInvalid
	}
	digest := challengeDigest(code)
	now := s.now().UTC().Truncate(time.Millisecond)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT purpose,subject,interaction_digest,session_json,expires_at_unix_ms,consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=? AND session_digest=?`, Args: []any{digest, sessionDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return ceremony{}, err
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 6 {
		return ceremony{}, ErrNotFound
	}
	r := q.Rows[0]
	actualPurpose, pok := r[0].(string)
	sub, ok := r[1].(string)
	enc, eok := r[3].(string)
	exp, xok := r[4].(int64)
	login := actualPurpose == loginPurpose
	if !pok || actualPurpose != purpose || !ok || !eok || !xok || exp <= now.UnixMilli() || r[5] != nil {
		return ceremony{}, ErrInvalid
	}
	if subject != "" && sub != subject {
		return ceremony{}, ErrInvalid
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return ceremony{}, ErrInvalid
	}
	raw, err := s.decryptDB(ciphertext, ceremonyEnvelopePurpose(actualPurpose, sub, digest), ceremonyAAD(actualPurpose, sub, digest))
	if err != nil {
		return ceremony{}, ErrInvalid
	}
	var sealed sealedState
	if decodeSealedStateJSON(raw, &sealed) != nil {
		return ceremony{}, ErrInvalid
	}
	if login {
		stored, ok := r[2].(string)
		if !ok || challengeDigest(sealed.Interaction) != stored || (sealed.AuthenticationMethod != "webauthn" && sealed.AuthenticationMethod != "mfa") {
			return ceremony{}, ErrInvalid
		}
	} else if sealed.AuthenticationMethod != "" {
		return ceremony{}, ErrInvalid
	}
	u, err := s.user(ctx, sub, "", false, sealed.AuthenticationMethod == "mfa")
	if err != nil {
		return ceremony{}, err
	}
	return ceremony{digest: digest, purpose: actualPurpose, subject: sub, interaction: sealed.Interaction, authenticationMethod: sealed.AuthenticationMethod, state: sealed.Session, credentials: u.credentials, credentialVersion: u.credentialVersion}, nil
}
func (s *Service) passkeyOnly(ctx context.Context, subject string) (bool, error) {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT mode FROM identity_authentication_modes WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(q.Rows) == 0 {
		return false, nil
	}
	if len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		return false, ErrInvalid
	}
	mode, ok := q.Rows[0][0].(string)
	if !ok {
		return false, ErrInvalid
	}
	switch mode {
	case "password":
		return false, nil
	case "passkey":
		return true, nil
	default:
		return false, ErrInvalid
	}
}
func (s *Service) ceremonyConsumed(ctx context.Context, digest, attempt string) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_ceremonies WHERE code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 1 && q.Rows[0][0] == attempt
}
func (s *Service) credentialAtVersion(ctx context.Context, subject, id string, version int64) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential_version FROM identity_webauthn_credentials WHERE subject=? AND credential_id=?`, Args: []any{subject, id}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 1 && q.Rows[0][0] == version
}
func (s *Service) mfaCeremonyConsumed(ctx context.Context, digest, attempt string) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_ceremonies WHERE code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 1 && q.Rows[0][0] == attempt
}
func (s *Service) mfaProofReady(ctx context.Context, digest, purpose, subject, sessionDigest string, expires time.Time) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT p.subject,p.session_digest,p.expires_at_unix_ms,p.consumed_attempt,m.purpose FROM identity_webauthn_mfa_proofs p JOIN identity_webauthn_service_proof_purposes m ON m.code_digest=p.code_digest WHERE p.code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 5 && q.Rows[0][0] == subject && q.Rows[0][1] == sessionDigest && q.Rows[0][2] == expires.UnixMilli() && q.Rows[0][3] == nil && q.Rows[0][4] == purpose
}
func (s *Service) mfaProofConsumed(ctx context.Context, digest, attempt string) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM identity_webauthn_mfa_proofs WHERE code_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 1 && q.Rows[0][0] == attempt
}
func (s *Service) modificationTokenReady(ctx context.Context, digest, subject, sessionDigest string, expires time.Time) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,session_digest,expires_at_unix_ms,consumed_attempt FROM identity_mfa_mod_tokens WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 4 && q.Rows[0][0] == subject && q.Rows[0][1] == sessionDigest && q.Rows[0][2] == expires.UnixMilli() && q.Rows[0][3] == nil
}
func (s *Service) modificationFactor(ctx context.Context, digest, kind string) bool {
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT proof_kind FROM identity_mfa_mod_token_factors WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(q.Rows) == 1 && len(q.Rows[0]) == 1 && q.Rows[0][0] == kind
}
func (s *Service) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(s.random, b)
	return b, e
}
func (s *Service) token(n int) (string, error) {
	b, e := s.randomBytes(n)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func (s *Service) alnum(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, 0, n)
	b := make([]byte, 1)
	for len(out) < n {
		if _, e := io.ReadFull(s.random, b); e != nil {
			return "", e
		}
		if b[0] < 248 {
			out = append(out, alphabet[int(b[0])%len(alphabet)])
		}
	}
	return string(out), nil
}
func (s *Service) encrypt(plain, aad []byte) ([]byte, error) {
	n, e := s.randomBytes(s.cookie.NonceSize())
	if e != nil {
		return nil, e
	}
	return append(n, s.cookie.Seal(nil, n, plain, aad)...), nil
}

func (s *Service) encryptDB(plain []byte, purpose string) ([]byte, string, error) {
	if s == nil || s.keyring == nil || purpose == "" {
		return nil, "", ErrInvalid
	}
	envelope, err := s.keyring.SealEnvelope(purpose, plain)
	if err != nil {
		return nil, "", err
	}
	keyID, err := s.keyring.PurposeEnvelopeKeyID(purpose, envelope)
	if err != nil {
		return nil, "", err
	}
	return envelope, keyID, nil
}

func (s *Service) executeEnvelope(ctx context.Context, writerKeyID string, request rhiza.ExecuteRequest) (rhiza.ExecuteResponse, error) {
	if s == nil || s.keyring == nil {
		return rhiza.ExecuteResponse{}, ErrInvalid
	}
	return storage.ExecuteEnvelope(ctx, s.db, writerKeyID, request)
}

// decryptDB accepts the legacy nonce+ciphertext format only when the value is
// not GAOP-shaped. A malformed, unknown-key, or tampered GAOP value therefore
// cannot fall back to the legacy CookieKey.
func (s *Service) decryptDB(value []byte, purpose string, legacyAAD []byte) ([]byte, error) {
	if isPurposeEnvelope(value) {
		if s == nil || s.keyring == nil {
			return nil, ErrInvalid
		}
		return s.keyring.OpenEnvelope(purpose, value)
	}
	return s.decrypt(value, legacyAAD)
}

func (s *Service) decrypt(v, aad []byte) ([]byte, error) {
	if len(v) < s.cookie.NonceSize() {
		return nil, ErrInvalid
	}
	plain, err := s.cookie.Open(nil, v[:s.cookie.NonceSize()], v[s.cookie.NonceSize():], aad)
	if err != nil && s.previousCookie != nil && len(v) >= s.previousCookie.NonceSize() {
		plain, err = s.previousCookie.Open(nil, v[:s.previousCookie.NonceSize()], v[s.previousCookie.NonceSize():], aad)
	}
	return plain, err
}

func isPurposeEnvelope(value []byte) bool {
	return len(value) >= 4 && bytes.Equal(value[:4], []byte("GAOP"))
}

func challengeDigest(v string) string {
	d := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func credentialEnvelopePurpose(subject string) string {
	return "passkey/credential/" + challengeDigest(subject)
}
func ceremonyEnvelopePurpose(purpose, subject, digest string) string {
	return "passkey/ceremony/" + challengeDigest(purpose+"\x00"+subject+"\x00"+digest)
}
func mfaCeremonyEnvelopePurpose(subject, digest string) string {
	return "passkey/mfa-ceremony/" + challengeDigest(subject+"\x00"+digest)
}
func credentialAAD(subject string) []byte { return []byte("goauthy/passkey/credential/" + subject) }
func ceremonyAAD(purpose, subject, digest string) []byte {
	return []byte("goauthy/passkey/ceremony/" + purpose + "\x00" + subject + "\x00" + digest)
}
func mfaCeremonyAAD(subject, digest string) []byte {
	return []byte("goauthy/passkey/mfa-ceremony/" + subject + "\x00" + digest)
}
func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func validSubject(v string) bool { return len(v) > 0 && len(v) <= 512 }

// validName mirrors Rauthy's passkey-name character class. unicode.IsSpace is
// used for its Unicode whitespace semantics, matching Rust regex's Unicode
// \s behaviour; names are limited by code points, not UTF-8 bytes.
func validName(v string) bool {
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) < 1 || utf8.RuneCountInString(v) > 32 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || (r >= '\u00c0' && r <= '\u024f') || r == '-' || r == '\'' || unicode.IsSpace(r) {
			continue
		}
		return false
	}
	return true
}
func validCode(v string) bool {
	if len(v) != 48 {
		return false
	}
	for _, b := range []byte(v) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", rune(b)) {
			return false
		}
	}
	return true
}
func validDigest(v string) bool {
	b, e := base64.RawURLEncoding.DecodeString(v)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}

func validServicePurpose(v string) bool { return v == modificationPurpose || v == passwordNewPurpose }
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func rid(p ...string) string {
	d := sha256.Sum256([]byte(strings.Join(p, "\x00")))
	return "passkey/" + base64.RawURLEncoding.EncodeToString(d[:])
}
