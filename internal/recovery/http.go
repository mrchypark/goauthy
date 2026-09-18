package recovery

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/passkey"
)

const (
	requestLimit  = 4 << 10
	passwordLimit = 256
	resetCookie   = "goauthy_pwd_reset"
	secureCookie  = "__Host-goauthy_pwd_reset"
)

// RequestReset implements POST /auth/v1/users/request_reset.
func (s *Service) RequestReset(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	request, err := decodeJSON[requestReset](w, r, requestLimit)
	if err != nil {
		badRequest(w)
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		badRequest(w)
		return
	}
	if request.Proof == "" {
		badRequest(w)
		return
	}
	if s.pow == nil || s.pow.VerifyAndConsume(r.Context(), request.Proof) != nil {
		forbidden(w)
		return
	}
	ip, ok := loginpolicy.PeerIP(r.RemoteAddr)
	if !ok {
		unavailable(w)
		return
	}
	allowed, err := s.policy.AllowPasswordReset(r.Context(), ip, s.now().UTC())
	if err != nil {
		unavailable(w)
		return
	}
	if !allowed {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.issue(r.Context(), email); err != nil {
		unavailable(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ProofOfWork implements POST /auth/v1/pow and returns an unsigned textual
// challenge. It is intentionally CORS-readable so a reset page on another
// origin can solve it, while consumption remains server-side and one-use.
func (s *Service) ProofOfWork(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if s.pow == nil {
		unavailable(w)
		return
	}
	ip, ok := loginpolicy.PeerIP(r.RemoteAddr)
	if !ok {
		unavailable(w)
		return
	}
	challenge, err := s.pow.IssueForPeer(r.Context(), ip, s.powDifficulty, s.powTTL)
	if errors.Is(err, ErrProofIssueLimited) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(challenge))
}

// GetReset implements GET /auth/v1/users/{subject}/reset/{token}.
func (s *Service) GetReset(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	subject, token := r.PathValue("subject"), r.PathValue("token")
	challenge, err := s.identity.BeginPasswordReset(r.Context(), subject, token)
	if err != nil {
		if errors.Is(err, identity.ErrPasswordResetUnavailable) {
			unavailable(w)
		} else {
			badRequest(w)
		}
		return
	}
	cookie, err := s.cookie(challenge.CookieToken, challenge.ExpiresAt)
	if err != nil {
		unavailable(w)
		return
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resetResponse{CSRFToken: challenge.CSRFToken, PasswordPolicy: passwordPolicyResponse(s.rules)})
}

// PutReset implements PUT /auth/v1/users/{subject}/reset.
func (s *Service) PutReset(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPut {
		methodNotAllowed(w, http.MethodPut)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	payload, err := decodeJSON[putReset](w, r, requestLimit)
	if err != nil || !bounded(payload.Password) {
		badRequest(w)
		return
	}
	cookie, err := r.Cookie(s.cookieName())
	if err != nil || cookie.Value == "" || r.Header.Get("X-Pwd-CSRF-Token") == "" {
		unauthorized(w)
		return
	}
	next := []byte(payload.Password)
	defer clear(next)
	ip := browser.PeerIPFromContext(r.Context())
	if ip == "" {
		var ok bool
		ip, ok = loginpolicy.PeerIP(r.RemoteAddr)
		if !ok {
			unavailable(w)
			return
		}
	}
	redirect, err := s.identity.ResetPassword(r.Context(), r.PathValue("subject"), payload.MagicLinkID, cookie.Value, r.Header.Get("X-Pwd-CSRF-Token"), next, ip)
	if err != nil {
		if errors.Is(err, identity.ErrPasswordResetUnavailable) {
			unavailable(w)
		} else {
			badRequest(w)
		}
		return
	}
	deleted, err := s.deleteCookie()
	if err != nil {
		unavailable(w)
		return
	}
	http.SetCookie(w, deleted)
	if redirect != "" {
		w.Header().Set("Location", redirect)
	}
	w.WriteHeader(http.StatusAccepted)
}

// RegisterOpen implements POST /auth/v1/users/register. It is intentionally
// CORS-readable: its only successful response is an empty 204, regardless of
// whether the canonical email already existed.
func (s *Service) RegisterOpen(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if s == nil || s.registration == nil || !s.registration.config.Enabled {
		forbidden(w)
		return
	}
	request, err := decodeJSON[RegistrationRequest](w, r, requestLimit)
	if err != nil {
		badRegistration(w)
		return
	}
	if err := validateCaptcha(r.Context(), s.captcha, request.CaptchaResponse, r.RemoteAddr); err != nil {
		badRegistration(w)
		return
	}
	// Validate only local syntax/domain policy first. Dynamic client redirect
	// lookup is deliberately deferred until the one-use PoW is consumed.
	basicConfig := s.registration.config
	basicConfig.RedirectValidator = func(string) bool { return true }
	request, err = basicConfig.ValidateRequest(request)
	if err != nil {
		if errors.Is(err, ErrRegistrationDisabled) {
			forbidden(w)
		} else if errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
			http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
		} else {
			badRegistration(w)
		}
		return
	}
	// PoW deliberately precedes all replicated lookups, including the quota
	// and duplicate check, so an attacker cannot use registration as an oracle.
	if s.pow == nil || s.pow.VerifyAndConsume(r.Context(), request.ProofOfWork) != nil {
		forbidden(w)
		return
	}
	config := s.registration.config
	config.RedirectValidator = func(uri string) bool {
		allowed, err := s.registration.validate(r.Context(), uri)
		return err == nil && allowed
	}
	if _, err := config.ValidateRequest(request); err != nil {
		// The PoW has already been consumed; never reveal redirect/client state.
		badRegistration(w)
		return
	}
	ip, ok := loginpolicy.PeerIP(r.RemoteAddr)
	if !ok {
		unavailable(w)
		return
	}
	allowed, err := s.policy.AllowOpenRegistration(r.Context(), ip, s.now().UTC())
	if err != nil {
		unavailable(w)
		return
	}
	if !allowed {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	values, err := canonicalUserValues(request.UserValues)
	if err != nil {
		unavailable(w)
		return
	}
	preferredUsername := ""
	if request.PreferredUsername != nil {
		preferredUsername = *request.PreferredUsername
	}
	result, err := s.identity.RegisterOpenUser(r.Context(), identity.OpenRegistration{
		Language: i18n.UserLanguageFromRequest(r),
		Email:    request.Email, PreferredUsername: preferredUsername,
		PreferredUsernamePolicy: config.UserValuesPolicy.PreferredUsername,
		GivenName:               request.GivenName, FamilyName: request.FamilyName,
		UserValuesJSON: values, RedirectURI: request.RedirectURI, TTL: s.registration.ttl, SourceIP: ip,
	})
	if err != nil {
		unavailable(w)
		return
	}
	if result.Created && s.OnUserCreated != nil {
		s.OnUserCreated()
	}
	lang, err := s.identity.UserLanguage(r.Context(), result.Subject)
	if err != nil {
		unavailable(w)
		return
	}
	if result.Created {
		message := Message{To: request.Email, Language: lang, ResetURL: s.resetURL(result.Subject, result.Token), ExpiresAt: result.ExpiresAt}
		if err := s.sender.SendPasswordNew(r.Context(), message); err != nil && s.OnError != nil {
			s.OnError(err)
		}
	} else if err := s.sender.SendAlreadyRegistered(r.Context(), Message{To: request.Email, Language: lang}); err != nil && s.OnError != nil {
		// Keep the duplicate path synchronous with account creation so SMTP
		// latency and sender failures do not disclose account existence.
		s.OnError(err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func canonicalUserValues(values *UserValues) (string, error) {
	if values == nil {
		return "", nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

type requestReset struct {
	Email string `json:"email"`
	Proof string `json:"pow"`
}
type putReset struct {
	MagicLinkID string `json:"magic_link_id"`
	Password    string `json:"password"`
}
type resetResponse struct {
	CSRFToken      string         `json:"csrf_token"`
	PasswordPolicy passwordPolicy `json:"password_policy"`
}
type passwordPolicy struct {
	LengthMin int `json:"length_min"`
	LengthMax int `json:"length_max"`
	LowerCase int `json:"lower_case"`
	UpperCase int `json:"upper_case"`
	Digits    int `json:"digits"`
	Special   int `json:"special"`
	History   int `json:"history"`
	ValidDays int `json:"valid_days"`
}

func passwordPolicyResponse(rules credential.Rules) passwordPolicy {
	return passwordPolicy{LengthMin: rules.LengthMin, LengthMax: rules.LengthMax, LowerCase: rules.LowerCase, UpperCase: rules.UpperCase, Digits: rules.Digits, Special: rules.Special, History: rules.History, ValidDays: rules.ValidDays}
}

func decodeJSON[T any](w http.ResponseWriter, r *http.Request, limit int64) (T, error) {
	var value T
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return value, errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return value, errors.New("trailing JSON")
	}
	return value, nil
}

func bounded(value string) bool {
	return len(value) > 0 && len(value) <= passwordLimit && utf8.ValidString(value) && utf8.RuneCountInString(value) <= passwordLimit
}
func crossSite(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site")
}
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
}
func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}
func badRequest(w http.ResponseWriter) {
	http.Error(w, "Invalid password reset request", http.StatusBadRequest)
}
func badRegistration(w http.ResponseWriter) {
	http.Error(w, "Invalid registration request", http.StatusBadRequest)
}
func passkeyRegistrationDisabled(w http.ResponseWriter) {
	http.Error(w, "Passkey registration is not enabled", http.StatusForbidden)
}
func unauthorized(w http.ResponseWriter) { http.Error(w, "Unauthorized", http.StatusUnauthorized) }
func forbidden(w http.ResponseWriter)    { http.Error(w, "Forbidden", http.StatusForbidden) }
func unavailable(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

type passkeyRegistrationStartRequest struct {
	Email             string      `json:"email"`
	PreferredUsername *string     `json:"preferred_username,omitempty"`
	FamilyName        string      `json:"family_name,omitempty"`
	GivenName         string      `json:"given_name,omitempty"`
	UserValues        *UserValues `json:"user_values,omitempty"`
	PasskeyName       string      `json:"passkey_name"`
	ProofOfWork       string      `json:"pow"`
	RedirectURI       string      `json:"redirect_uri,omitempty"`
	CaptchaResponse   string      `json:"captcha_response,omitempty"`
}

type passkeyRegistrationStartResponse struct {
	CredentialCreation interface{} `json:"credential_creation"`
	Code               string      `json:"code"`
	ExpiresAt          string      `json:"expires_at"`
}

type passkeyRegistrationFinishRequest struct {
	Code         string `json:"code"`
	PasskeyName  string `json:"passkey_name"`
	CredentialID string `json:"credential_id"`
}

func (s *Service) SetPasskeyService(ps *passkey.Service) {
	s.passkeys = ps
}

// RegisterPasskeyStart implements POST /auth/v1/register/passkey/start.
func (s *Service) RegisterPasskeyStart(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if s == nil || s.registration == nil || !s.registration.config.Enabled || !s.registration.config.PasskeyEnabled || s.passkeys == nil {
		passkeyRegistrationDisabled(w)
		return
	}
	request, err := decodeJSON[passkeyRegistrationStartRequest](w, r, requestLimit)
	if err != nil {
		badRegistration(w)
		return
	}
	if request.PasskeyName == "" {
		badRegistration(w)
		return
	}
	if err := validateCaptcha(r.Context(), s.captcha, request.CaptchaResponse, r.RemoteAddr); err != nil {
		badRegistration(w)
		return
	}
	basicConfig := s.registration.config
	basicConfig.RedirectValidator = func(string) bool { return true }
	regRequest := RegistrationRequest{
		Email:             request.Email,
		PreferredUsername: request.PreferredUsername,
		FamilyName:        request.FamilyName,
		GivenName:         request.GivenName,
		UserValues:        request.UserValues,
		ProofOfWork:       request.ProofOfWork,
		RedirectURI:       request.RedirectURI,
		CaptchaResponse:   request.CaptchaResponse,
	}
	regRequest, err = basicConfig.ValidateRequest(regRequest)
	if err != nil {
		if errors.Is(err, ErrRegistrationDisabled) {
			passkeyRegistrationDisabled(w)
		} else if errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
			http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
		} else {
			badRegistration(w)
		}
		return
	}
	if s.pow == nil || s.pow.VerifyAndConsume(r.Context(), request.ProofOfWork) != nil {
		forbidden(w)
		return
	}
	config := s.registration.config
	config.RedirectValidator = func(uri string) bool {
		allowed, err := s.registration.validate(r.Context(), uri)
		return err == nil && allowed
	}
	if _, err := config.ValidateRequest(regRequest); err != nil {
		badRegistration(w)
		return
	}
	ip, ok := loginpolicy.PeerIP(r.RemoteAddr)
	if !ok {
		unavailable(w)
		return
	}
	allowed, err := s.policy.AllowOpenRegistration(r.Context(), ip, s.now().UTC())
	if err != nil {
		unavailable(w)
		return
	}
	if !allowed {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	values, err := canonicalUserValues(request.UserValues)
	if err != nil {
		unavailable(w)
		return
	}
	preferredUsername := ""
	if request.PreferredUsername != nil {
		preferredUsername = *request.PreferredUsername
	}
	subject, err := s.identity.RegisterPasskeyUser(r.Context(), identity.OpenRegistration{
		Language:                i18n.UserLanguageFromRequest(r),
		Email:                   request.Email,
		PreferredUsername:       preferredUsername,
		PreferredUsernamePolicy: config.UserValuesPolicy.PreferredUsername,
		GivenName:               request.GivenName,
		FamilyName:              request.FamilyName,
		UserValuesJSON:          values,
		RedirectURI:             request.RedirectURI,
		TTL:                     s.registration.ttl,
		SourceIP:                ip,
	})
	if err != nil {
		unavailable(w)
		return
	}
	if s.OnUserCreated != nil {
		s.OnUserCreated()
	}
	sessionDigest := request.PasskeyName
	opts, code, exp, err := s.passkeys.BeginRegistration(r.Context(), subject, request.Email, request.PasskeyName, sessionDigest)
	if err != nil {
		unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(passkeyRegistrationStartResponse{
		CredentialCreation: opts,
		Code:               code,
		ExpiresAt:          exp.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// RegisterPasskeyFinish implements POST /auth/v1/register/passkey/finish.
func (s *Service) RegisterPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if s == nil || s.registration == nil || !s.registration.config.Enabled || !s.registration.config.PasskeyEnabled || s.passkeys == nil {
		passkeyRegistrationDisabled(w)
		return
	}
	request, err := decodeJSON[passkeyRegistrationFinishRequest](w, r, requestLimit)
	if err != nil || request.Code == "" || request.PasskeyName == "" {
		badRegistration(w)
		return
	}
	sessionDigest := request.PasskeyName
	cred, err := s.passkeys.FinishPasskeyRegistration(r.Context(), "", request.PasskeyName, sessionDigest, request.Code, r)
	if err != nil {
		badRegistration(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cred)
}
