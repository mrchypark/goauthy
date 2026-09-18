package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/captcha"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const passwordResetLifetime = 30 * time.Minute

var (
	ErrInvalidEmail = errors.New("invalid recovery email")
	ErrEmailBound   = errors.New("recovery email belongs to another subject")
)

// SchemaStatements owns the recovery email-to-subject mapping. Both columns
// are unique so a verified local identity has one exact recovery destination.
func SchemaStatements() []rhiza.SQLStatement {
	stmts := append([]rhiza.SQLStatement{{SQL: `CREATE TABLE IF NOT EXISTS identity_recovery_emails (
		subject TEXT PRIMARY KEY NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
		email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254 AND email = lower(email))
	) STRICT`}}, otpSchemaStatements()...)
	return append(stmts, emailOutboxSchemaStatements()...)
}

// Service holds recovery dependencies. OnError is only for delivery failures;
// callers never receive sender details or reset bearer tokens.
type Service struct {
	db            *rhiza.DB
	identity      *identity.Store
	sender        Sender
	issuer        string
	rules         credential.Rules
	policy        *loginpolicy.Store
	pow           *ProofOfWork
	powDifficulty uint8
	powTTL        time.Duration
	now           func() time.Time
	OnError       func(error)
	OnUserCreated func()
	registration  *openRegistration
	captcha       captcha.Verifier
	passkeys      *passkey.Service
}

type openRegistration struct {
	config   RegistrationConfig
	ttl      time.Duration
	validate func(context.Context, string) (bool, error)
}

// ServiceOption extends recovery without making public registration opt-out.
// Existing callers get no registration endpoint until they provide this option.
type ServiceOption func(*Service) error

// WithOpenRegistration enables public registration with a fixed policy. The
// contextual validator is where callers check the URI against their live
// client configuration; it must exact-match, never prefix-match.
func WithOpenRegistration(config RegistrationConfig, ttl time.Duration, validate func(context.Context, string) (bool, error)) ServiceOption {
	return func(s *Service) error {
		if ttl == 0 {
			ttl = 72 * time.Hour
		}
		if ttl < time.Minute || ttl > 7*24*time.Hour || validate == nil {
			return ErrRegistrationConfig
		}
		// Validation of the policy requires a URI checker. The contextual one is
		// installed by RegisterOpen, so use a closed-world placeholder here only
		// to validate the static domain policy.
		if config.RedirectValidator == nil {
			config.RedirectValidator = func(string) bool { return true }
		}
		if err := config.Validate(); err != nil {
			return err
		}
		s.registration = &openRegistration{config: config, ttl: ttl, validate: validate}
		return nil
	}
}

func NewService(db *rhiza.DB, identities *identity.Store, sender Sender, issuer string, rules credential.Rules, policy *loginpolicy.Store, pow *ProofOfWork, powDifficulty uint8, powTTL time.Duration, options ...ServiceOption) (*Service, error) {
	if db == nil || identities == nil || sender == nil || policy == nil || pow == nil || powDifficulty < 10 || powDifficulty > 98 || powTTL < time.Second || powTTL > MaxProofTTL {
		return nil, errors.New("recovery service requires database, identity, sender, policy, and proof of work")
	}
	issuer, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	service := &Service{db: db, identity: identities, sender: sender, issuer: issuer, rules: rules, policy: policy, pow: pow, powDifficulty: powDifficulty, powTTL: powTTL, now: time.Now}
	for _, option := range options {
		if option == nil {
			return nil, ErrRegistrationConfig
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// SetCaptchaVerifier attaches a captcha verifier for open registration.
func (s *Service) SetCaptchaVerifier(v captcha.Verifier) {
	s.captcha = v
}

// BindEmail canonically binds one deliverable address to its active subject.
// INSERT OR IGNORE plus the following linearizable read resolves concurrent
// ownership claims without accepting an ambiguous result.
func (s *Service) BindEmail(ctx context.Context, subject, email string) error {
	if s == nil || s.db == nil || s.identity == nil {
		return errors.New("recovery service unavailable")
	}
	canonical, err := canonicalEmail(email)
	if err != nil {
		return err
	}
	if err := s.identity.ValidateSubject(ctx, subject); err != nil {
		return err
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: recoveryMutationID("email-bind", subject, canonical), SQL: `INSERT OR IGNORE INTO identity_recovery_emails (subject,email) VALUES (?,?)`, Args: []any{subject, canonical}}); err != nil {
		return err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject FROM identity_recovery_emails WHERE email = ?`, Args: []any{canonical}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return errors.New("invalid recovery email row")
	}
	owner, ok := result.Rows[0][0].(string)
	if !ok {
		return errors.New("invalid recovery email row")
	}
	if owner != subject {
		return ErrEmailBound
	}
	return nil
}

func recoveryMutationID(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "recovery/" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Service) issue(ctx context.Context, email string) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject FROM identity_recovery_emails WHERE email = ?`, Args: []any{email}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return errors.New("invalid recovery email row")
	}
	subject, ok := result.Rows[0][0].(string)
	if !ok {
		return errors.New("invalid recovery email row")
	}
	return s.issueFor(ctx, subject, email)
}

// IssueForSubject starts the same recovery delivery flow used by an email
// request, but begins with an already-authenticated subject (for example, an
// expired-password login callback). Missing recovery registration remains a
// no-op so this callback does not disclose account configuration.
func (s *Service) IssueForSubject(ctx context.Context, subject string) error {
	if s == nil || s.db == nil || s.identity == nil || s.sender == nil {
		return errors.New("recovery service unavailable")
	}
	if err := s.identity.ValidateSubject(ctx, subject); err != nil {
		return err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT email FROM identity_recovery_emails WHERE subject = ?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return errors.New("invalid recovery email row")
	}
	email, ok := result.Rows[0][0].(string)
	if !ok {
		return errors.New("invalid recovery email row")
	}
	return s.issueFor(ctx, subject, email)
}

func (s *Service) issueFor(ctx context.Context, subject, email string) error {
	lang, err := s.identity.UserLanguage(ctx, subject)
	if errors.Is(err, identity.ErrInactiveSubject) {
		return nil // Concurrent deletion remains non-actionable, not an existence oracle.
	}
	if err != nil {
		return err
	}
	token, expires, err := s.identity.IssuePasswordResetForEmail(ctx, subject, email, passwordResetLifetime)
	if errors.Is(err, identity.ErrInvalidPasswordReset) {
		return nil // disabled or otherwise non-actionable is indistinguishable.
	}
	if err != nil {
		return err
	}
	if err := s.sender.SendPasswordReset(ctx, Message{To: email, Language: lang, ResetURL: s.resetURL(subject, token), ExpiresAt: expires}); err != nil && s.OnError != nil {
		s.OnError(err)
	}
	return nil
}

func (s *Service) resetURL(subject, token string) string {
	return strings.TrimRight(s.issuer, "/") + "/auth/v1/users/" + pathEscape(subject) + "/reset/" + pathEscape(token)
}

func canonicalEmail(value string) (string, error) {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value || !ascii(value) {
		return "", ErrInvalidEmail
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Name != "" || parsed.Address != value {
		return "", ErrInvalidEmail
	}
	canonical := strings.ToLower(value)
	if len(canonical) > 254 {
		return "", ErrInvalidEmail
	}
	return canonical, nil
}

func ascii(value string) bool {
	for _, c := range value {
		if c > 0x7f {
			return false
		}
	}
	return true
}

func pathEscape(value string) string {
	return url.PathEscape(value)
}

func (s *Service) cookieName() string {
	if strings.HasPrefix(s.issuer, "https://") {
		return secureCookie
	}
	return resetCookie
}

func (s *Service) cookie(value string, expires time.Time) (*http.Cookie, error) {
	remaining := expires.UTC().Sub(s.now().UTC())
	if remaining <= 0 {
		return nil, errors.New("reset cookie already expired")
	}
	return &http.Cookie{Name: s.cookieName(), Value: value, Path: "/", Expires: expires.UTC(), MaxAge: int((remaining + time.Second - 1) / time.Second), HttpOnly: true, Secure: strings.HasPrefix(s.issuer, "https://"), SameSite: http.SameSiteLaxMode}, nil
}

func (s *Service) deleteCookie() (*http.Cookie, error) {
	return &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(s.issuer, "https://"), SameSite: http.SameSiteLaxMode}, nil
}
