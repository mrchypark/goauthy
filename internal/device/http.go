// Package device provides the HTTP boundary for RFC 8628 device authorization.
package device

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	deviceAuthorizationPath = "/oidc/device"
	verificationPath        = "/oidc/device/verify"
	deviceFormLimit         = 8 << 10
	csrfCookieName          = "__Host-goauthy_device_csrf"
	localCSRFCookieName     = "goauthy_device_csrf"
)

const (
	defaultRateWindow        = time.Minute
	defaultCreationLimit     = 20
	defaultVerificationLimit = 20
)

var verificationPage = template.Must(template.New("device-verification").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Device verification</title><link rel="stylesheet" href="{{.CSS}}"></head><body><main><header class="page-header"><div><p class="eyebrow">GoAuthy · Device access</p><h1>Device verification</h1></div></header>
{{if .Message}}<p role="alert">{{.Message}}</p>{{end}}
{{if .Review}}<p>Only approve if you started this request and the code matches your device. Signing in has not granted access.</p><dl class="connection-key-settings"><dt>Requesting app (client ID)</dt><dd id="device-client">{{.Review.ClientID}}</dd>{{if .Review.Resource}}<dt>Resource receiving access</dt><dd>{{.Review.Resource}}</dd>{{end}}</dl><h2>Requested permissions</h2><ul id="device-scopes">{{range .Review.Scopes}}<li>{{.}}</li>{{else}}<li>No named permissions requested</li>{{end}}</ul>
<form method="post" action="verify"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Code <input name="user_code" value="{{.UserCode}}" readonly required></label><button type="submit" name="action" value="approve">Approve device</button><button class="secondary" type="submit" name="action" value="deny">Deny request</button></form><p><a href="verify">Enter a different code</a></p>
{{else}}<p>Enter the code shown on your device to review its requested access.</p><form method="get" action="verify"><label>Device code <input name="user_code" autocomplete="one-time-code" maxlength="64" required></label><button type="submit">Review request</button></form>{{end}}</main></body></html>`))

type verificationPageData struct {
	UserCode, CSRFToken, CSS, Message string
	Review                            *Review
}

// ClientAuthorizer authenticates the parsed request and checks device grant/scope
// policy. OAuth client representations and secret verification stay in the OAuth layer.
type ClientAuthorizer func(*http.Request, string, []string) error

var ErrClientAuthentication = errors.New("device client authentication failed")

// Subject returns the browser-authenticated subject and verified MFA evidence. A nil callback, or a
// callback returning ok=false, makes approval fail closed.
type Subject func(*http.Request) (subject string, mfa bool, ok bool)

// Limits controls the distributed, fixed-window abuse boundaries. A zero
// value uses conservative defaults; disabling these limits is not supported.
type Limits struct {
	Window            time.Duration
	CreationLimit     int
	VerificationLimit int
}

// Handler serves the device authorization and verification endpoints.
type Handler struct {
	store          *Store
	issuer         *url.URL
	authorize      ClientAuthorizer
	subject        Subject
	reauthenticate func(http.ResponseWriter, *http.Request, string)
	limits         Limits
	now            func() time.Time
}

// SetReauthentication configures the same-subject MFA login continuation.
func (h *Handler) SetReauthentication(fn func(http.ResponseWriter, *http.Request, string)) {
	h.reauthenticate = fn
}

// NewHandler constructs the narrowly scoped device HTTP boundary. subject may
// be nil until browser-session wiring exists; in that state approval is denied.
func NewHandler(store *Store, issuer string, authorize ClientAuthorizer, subject Subject) (*Handler, error) {
	return NewHandlerWithLimits(store, issuer, authorize, subject, Limits{})
}

// NewHandlerWithLimits is provided for runtime policy wiring and deterministic
// tests. All limits must be positive after defaults are applied.
func NewHandlerWithLimits(store *Store, issuer string, authorize ClientAuthorizer, subject Subject, limits Limits) (*Handler, error) {
	if store == nil || authorize == nil {
		return nil, errors.New("device handler requires store and client authorizer")
	}
	u, err := parseIssuer(issuer)
	if err != nil {
		return nil, err
	}
	limits, err = normalizedLimits(limits)
	if err != nil {
		return nil, err
	}
	return &Handler{store: store, issuer: u, authorize: authorize, subject: subject, limits: limits, now: time.Now}, nil
}

// ServeHTTP retains route boundaries even if a parent mux mounts a subtree.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == deviceAuthorizationPath:
		h.authorizeDevice(w, r)
	case r.Method == http.MethodGet && r.URL.Path == verificationPath:
		h.verifyPage(w, r)
	case r.Method == http.MethodPost && r.URL.Path == verificationPath:
		h.verifyDevice(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, "not_found")
	}
}

func (h *Handler) authorizeDevice(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	r = WithClientBinding(r)
	clientID, scopes, err := parseDeviceForm(w, r)
	if err != nil {
		if errors.Is(err, ErrInvalidTarget) {
			writeJSONError(w, http.StatusBadRequest, "invalid_target")
		} else {
			writeJSONError(w, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	// Bound failed authentication attempts before the OAuth layer hashes secrets.
	if !h.allow(w, r, "create/"+clientID, h.limits.CreationLimit) {
		return
	}
	if err := h.authorize(r, clientID, scopes); err != nil {
		if errors.Is(err, ErrClientAuthentication) {
			w.Header().Set("WWW-Authenticate", `Basic realm="goauthy"`)
			writeJSONError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		if errors.Is(err, ErrInvalidTarget) {
			writeJSONError(w, http.StatusBadRequest, "invalid_target")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	binding := ClientBindingFromRequest(r)
	if values, present := r.PostForm["resource"]; present && values[0] != binding.Resource {
		writeJSONError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	grant, err := h.store.CreateWithBinding(r.Context(), clientID, scopes, binding, h.now().UTC())
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	expiresIn := int64(grant.ExpiresAt.Sub(h.now().UTC()).Seconds())
	if expiresIn < 1 || grant.DeviceCode == "" || grant.UserCode == "" || grant.Interval < time.Second {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	verificationURI := h.endpoint(verificationPath)
	complete, err := url.Parse(verificationURI)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	query := complete.Query()
	query.Set("user_code", grant.UserCode)
	complete.RawQuery = query.Encode()
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               grant.DeviceCode,
		"user_code":                 grant.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": complete.String(),
		"expires_in":                expiresIn,
		"interval":                  int64(grant.Interval / time.Second),
	})
}

func (h *Handler) verifyPage(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validVerificationQuery(query) {
		writeHTMLStatus(w, http.StatusBadRequest, "Invalid verification request")
		return
	}
	if h.subject == nil {
		h.redirectToDeviceLogin(w, r)
		return
	}
	subject, mfa, ok := h.subject(r)
	if !ok || !validSubject(subject) {
		h.redirectToDeviceLogin(w, r)
		return
	}
	data := verificationPageData{CSS: h.endpoint("/account/account.css")}
	render := func(status int) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = verificationPage.Execute(w, data)
	}
	code := query.Get("user_code")
	if code == "" {
		render(http.StatusOK)
		return
	}
	if !h.allow(w, r, "review/"+subject, h.limits.VerificationLimit) {
		return
	}
	review, err := h.store.Review(r.Context(), code, h.now().UTC())
	if err != nil {
		if !errors.Is(err, ErrInvalid) {
			writeHTMLStatus(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
			return
		}
		data.Message = "This code is unavailable. Check the code or start a new request on your device."
		render(http.StatusBadRequest)
		return
	}
	if review.ForceMFA && !mfa && h.reauthenticate != nil {
		h.reauthenticate(w, r, code)
		return
	}
	token, err := csrfToken()
	if err != nil {
		writeHTMLStatus(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: h.csrfCookieName(), Value: token, Path: "/", HttpOnly: true, Secure: h.issuer.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: 300})
	data.UserCode, data.CSRFToken, data.Review = code, reviewedDeviceCSRF(token, code), &review
	render(http.StatusOK)
}

// Bind the form to the immutable grant that was displayed, not an editable code.
// The random HttpOnly cookie remains secret; knowing this MAC cannot sign another code.
func reviewedDeviceCSRF(cookie, code string) string {
	mac := hmac.New(sha256.New, []byte(cookie))
	mac.Write([]byte("goauthy/device-review/v1\x00" + NormalizeUserCode(code)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) redirectToDeviceLogin(w http.ResponseWriter, r *http.Request) {
	u := h.endpoint("/oidc/device/login")
	login, err := url.Parse(u)
	if err != nil {
		writeHTMLStatus(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	query := login.Query()
	query.Set("user_code", r.URL.Query().Get("user_code"))
	login.RawQuery = query.Encode()
	http.Redirect(w, r, login.String(), http.StatusSeeOther)
}

func (h *Handler) verifyDevice(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || crossSite(r.Header.Values("Sec-Fetch-Site")) || !sameOrigin(r, h.issuer) {
		writeHTMLStatus(w, http.StatusForbidden, "Invalid verification request")
		return
	}
	userCode, token, action, err := parseVerificationForm(w, r)
	if err != nil {
		writeHTMLStatus(w, http.StatusBadRequest, "Invalid verification request")
		return
	}
	cookies := r.CookiesNamed(h.csrfCookieName())
	if len(cookies) != 1 || !validCSRFToken(cookies[0].Value) || subtle.ConstantTimeCompare([]byte(reviewedDeviceCSRF(cookies[0].Value, userCode)), []byte(token)) != 1 {
		writeHTMLStatus(w, http.StatusForbidden, "Invalid verification request")
		return
	}
	if h.subject == nil {
		writeHTMLStatus(w, http.StatusForbidden, "Authentication required")
		return
	}
	subject, mfa, ok := h.subject(r)
	if !ok || !validSubject(subject) {
		writeHTMLStatus(w, http.StatusForbidden, "Authentication required")
		return
	}
	if !h.allow(w, r, "verify/"+subject, h.limits.VerificationLimit) {
		return
	}
	var decisionErr error
	message := "Device approved"
	if action == "deny" {
		decisionErr = h.store.Deny(r.Context(), userCode, h.now().UTC())
		message = "Device denied"
	} else {
		decisionErr = h.store.ApproveWithMFA(r.Context(), userCode, subject, mfa, h.now().UTC())
	}
	if decisionErr != nil {
		if action == "approve" && !mfa && h.reauthenticate != nil && errors.Is(decisionErr, ErrInvalid) {
			if review, err := h.store.Review(r.Context(), userCode, h.now().UTC()); err == nil && review.ForceMFA {
				h.reauthenticate(w, r, userCode)
				return
			}
		}
		writeHTMLStatus(w, http.StatusBadRequest, "Invalid verification request")
		return
	}
	// One-use cookie reduces accidental repeated approval from a browser back button.
	http.SetCookie(w, &http.Cookie{Name: h.csrfCookieName(), Value: "", Path: "/", HttpOnly: true, Secure: h.issuer.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: -1})
	writeHTMLStatus(w, http.StatusOK, message)
}

func parseDeviceForm(w http.ResponseWriter, r *http.Request) (string, []string, error) {
	if err := formContentType(r); err != nil {
		return "", nil, err
	}
	r.Body = http.MaxBytesReader(w, r.Body, deviceFormLimit)
	if err := r.ParseForm(); err != nil {
		return "", nil, errors.New("invalid device form")
	}
	for key, values := range r.PostForm {
		if (key != "client_id" && key != "scope" && key != "client_secret" && key != "resource") || len(values) != 1 || values[0] == "" {
			if key == "resource" {
				return "", nil, ErrInvalidTarget
			}
			return "", nil, errors.New("invalid device form")
		}
	}
	if resource, ok := r.PostForm["resource"]; ok && (!validResource(resource[0])) {
		return "", nil, ErrInvalidTarget
	}
	clientID := r.PostForm.Get("client_id")
	if len(r.Header.Values("Authorization")) > 1 {
		return "", nil, errors.New("ambiguous client authentication")
	}
	if len(r.Header.Values("Authorization")) == 1 {
		basicID, _, ok := r.BasicAuth()
		decodedID, err := url.QueryUnescape(basicID)
		if !ok || err != nil || r.PostForm.Has("client_secret") || (clientID != "" && clientID != decodedID) {
			return "", nil, errors.New("invalid client authentication")
		}
		clientID = decodedID
	}
	if !validClientID(clientID) {
		return "", nil, errors.New("invalid client ID")
	}
	scope, ok := oneFormValue(r.PostForm, "scope")
	if !ok {
		return "", nil, errors.New("invalid scope")
	}
	scopes, ok := parseScopes(scope)
	if !ok {
		return "", nil, errors.New("invalid scope")
	}
	return clientID, scopes, nil
}

func parseVerificationForm(w http.ResponseWriter, r *http.Request) (string, string, string, error) {
	if err := formContentType(r); err != nil {
		return "", "", "", err
	}
	r.Body = http.MaxBytesReader(w, r.Body, deviceFormLimit)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 3 {
		return "", "", "", errors.New("invalid verification form")
	}
	userCode, userOK := oneFormValue(r.PostForm, "user_code")
	token, tokenOK := oneFormValue(r.PostForm, "csrf_token")
	action, actionOK := oneFormValue(r.PostForm, "action")
	if !userOK || !tokenOK || !actionOK || !validUserCode(userCode) || !validCSRFToken(token) || (action != "approve" && action != "deny") {
		return "", "", "", errors.New("invalid verification form")
	}
	return userCode, token, action, nil
}

func formContentType(r *http.Request) error {
	if len(r.Header.Values("Content-Type")) != 1 {
		return errors.New("invalid content type")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return errors.New("invalid content type")
	}
	return nil
}

func oneFormValue(form url.Values, key string) (string, bool) {
	values, ok := form[key]
	returnValue := ""
	if ok && len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, ok && len(values) == 1 && returnValue != ""
}

func parseScopes(value string) ([]string, bool) {
	if !utf8.ValidString(value) || value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
		return nil, false
	}
	scopes := strings.Fields(value)
	if len(scopes) == 0 || strings.Join(scopes, " ") != value {
		return nil, false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if len(scope) > 128 {
			return nil, false
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, false
		}
		seen[scope] = struct{}{}
	}
	return scopes, true
}

func validClientID(value string) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && len(value) <= 128 && value != ""
}

func validUserCode(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || len(value) < 4 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validSubject(value string) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && value != "" && len(value) <= 256
}

func validVerificationQuery(query url.Values) bool {
	if len(query) == 0 {
		return true
	}
	values, ok := query["user_code"]
	if !ok || len(values) != 1 || len(query) != 1 {
		return false
	}
	return values[0] == "" || validUserCode(values[0])
}

func csrfToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func validCSRFToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (h *Handler) endpoint(path string) string {
	u := *h.issuer
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (h *Handler) csrfCookieName() string {
	if h.issuer.Scheme == "https" {
		return csrfCookieName
	}
	return localCSRFCookieName
}

func parseIssuer(issuer string) (*url.URL, error) {
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, errors.New("invalid device issuer")
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, errors.New("invalid device issuer")
	}
	return u, nil
}

func normalizedLimits(limits Limits) (Limits, error) {
	if limits.Window == 0 {
		limits.Window = defaultRateWindow
	}
	if limits.CreationLimit == 0 {
		limits.CreationLimit = defaultCreationLimit
	}
	if limits.VerificationLimit == 0 {
		limits.VerificationLimit = defaultVerificationLimit
	}
	if limits.Window < time.Second || limits.CreationLimit < 1 || limits.VerificationLimit < 1 {
		return Limits{}, errors.New("invalid device rate limits")
	}
	return limits, nil
}

func (h *Handler) allow(w http.ResponseWriter, r *http.Request, suffix string, limit int) bool {
	ip, ok := directRemoteIP(r.RemoteAddr)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	allowed, err := h.store.Allow(r.Context(), ip+"/"+suffix, h.now().UTC(), h.limits.Window, limit)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int((h.limits.Window+time.Second-1)/time.Second)))
		writeJSONError(w, http.StatusTooManyRequests, "temporarily_unavailable")
		return false
	}
	return true
}

func directRemoteIP(remoteAddr string) (string, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

func crossSite(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "cross-site") {
			return true
		}
	}
	return false
}

func sameOrigin(r *http.Request, issuer *url.URL) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	if values[0] == "null" {
		// Match the login form boundary: no-referrer native forms emit null
		// Origin. Require same-origin browser metadata; verifyDevice still
		// checks the authenticated subject and double-submit CSRF token.
		var protection http.CrossOriginProtection
		return len(r.Header.Values("Sec-Fetch-Site")) == 1 && r.Header.Get("Sec-Fetch-Site") == "same-origin" && protection.Check(r) == nil
	}
	u, err := url.Parse(values[0])
	return err == nil && u.Scheme == issuer.Scheme && u.Host == issuer.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeHTMLStatus(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}
