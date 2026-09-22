package login

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/device"
)

const (
	deviceLoginPayload            = "goauthy-device-login/v1"
	connectionHandoffLoginPayload = "goauthy-connection-handoff-login/v1"
)

var deviceLoginCode = regexp.MustCompile(`^[A-Z0-9]{4,32}$`)
var deviceLoginPage = template.Must(template.New("device-login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>{{.Title}}</title></head><body><main><h1>{{.Title}}</h1><p>{{.Intro}}</p><form method="post" action="{{.Action}}"><input type="hidden" name="interaction" value="{{.Interaction}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form></main></body></html>`))

type deviceLoginData struct{ Action, Title, Intro, Interaction, CSRFToken, ThemeURL string }
type deviceLoginInteraction struct{ Purpose, UserCode string }
type connectionHandoffLoginInteraction struct{ Purpose, HandoffID string }

// DeviceLoginHandler authenticates a browser for the device verification page.
// It never looks up the code, so this boundary cannot disclose whether a code exists.
func (h *Handler) DeviceLoginHandler(forceMFA bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if r.URL.Path != "/oidc/device/login" || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
			return
		}
		if r.Method == http.MethodGet {
			h.deviceLoginGet(w, r, forceMFA)
		} else {
			h.deviceLoginPost(w, r, forceMFA)
		}
	})
}

func (h *Handler) deviceLoginGet(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) > 1 || (r.URL.RawQuery != "" && len(query["user_code"]) != 1) {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	code := device.NormalizeUserCode(query.Get("user_code"))
	if code != "" && !deviceLoginCode.MatchString(code) {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	if current, _, ok := h.session(r); ok && current.Authenticated() {
		if forceMFA && current.AuthenticationMethod != "mfa" {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		h.deviceLoginRedirect(w, code)
		return
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok || peerIP == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(deviceLoginInteraction{Purpose: deviceLoginPayload, UserCode: code})
	interaction, csrf, cookie, err := h.createLoginInteraction(r, peerIP, payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	themeURL, err := h.resolveThemeURL(r.Context(), "rauthy")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceLoginPage.Execute(w, deviceLoginData{Action: "login", Title: "Device sign in", Intro: "Sign in to review the code from your device. Signing in does not approve it.", Interaction: interaction.Token, CSRFToken: csrf, ThemeURL: themeURL})
}

func (h *Handler) deviceLoginPost(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	if r.URL.RawQuery != "" || crossSite(r.Header.Values("Sec-Fetch-Site")) || !sameIssuerOrigin(r, h.issuer) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	h.loginPost(w, r, forceMFA, deviceLoginDestination)
}

type loginPostDestination uint8

const (
	deviceLoginDestination loginPostDestination = iota
	connectionHandoffDestination
)

func (h *Handler) loginPost(w http.ResponseWriter, r *http.Request, forceMFA bool, destination loginPostDestination) {
	form, err := parseDeviceLoginForm(w, r)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || session.Authenticated() || session.PeerIP == "" || browser.ValidateCSRFToken(sessionToken, form.CSRFToken) != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	auth, peerIP, started, ok := h.authenticatePassword(w, r, form.Username, form.Password)
	if !ok {
		return
	}
	if forceMFA {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	interaction, err := h.browser.ConsumeAuthorizationInteraction(r.Context(), sessionToken, form.Interaction)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	var deviceSaved deviceLoginInteraction
	var handoffSaved connectionHandoffLoginInteraction
	switch destination {
	case deviceLoginDestination:
		if json.Unmarshal(interaction.Payload, &deviceSaved) != nil || deviceSaved.Purpose != deviceLoginPayload || (deviceSaved.UserCode != "" && !deviceLoginCode.MatchString(deviceSaved.UserCode)) {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
	case connectionHandoffDestination:
		if json.Unmarshal(interaction.Payload, &handoffSaved) != nil || handoffSaved.Purpose != connectionHandoffLoginPayload {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		if _, ok := canonicalHandoffID(handoffSaved.HandoffID); !ok {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
	default:
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	if _, ok := h.completeBrowserAuthentication(w, r, sessionToken, auth.Subject, "pwd", peerIP, func() error {
		return h.recordSuccessfulAuthentication(r.Context(), peerIP, h.now().Sub(started), nil)
	}, nil); !ok {
		return
	}
	if destination == deviceLoginDestination {
		h.deviceLoginRedirect(w, deviceSaved.UserCode)
	} else {
		h.connectionHandoffRedirect(w, handoffSaved.HandoffID)
	}
}

type deviceLoginForm struct{ Interaction, CSRFToken, Username, Password string }

func parseDeviceLoginForm(w http.ResponseWriter, r *http.Request) (deviceLoginForm, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return deviceLoginForm{}, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return deviceLoginForm{}, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 4 {
		return deviceLoginForm{}, errors.New("form")
	}
	get := func(key string) (string, bool) {
		v, ok := r.PostForm[key]
		return func() string {
			if !ok || len(v) != 1 {
				return ""
			}
			return v[0]
		}(), ok && len(v) == 1 && v[0] != ""
	}
	i, iok := get("interaction")
	c, cok := get("csrf_token")
	u, uok := get("username")
	p, pok := get("password")
	if !iok || !cok || !uok || !pok {
		return deviceLoginForm{}, errors.New("fields")
	}
	if !utf8Valid(p) {
		return deviceLoginForm{}, errors.New("password")
	}
	return deviceLoginForm{Interaction: i, CSRFToken: c, Username: u, Password: p}, nil
}
func utf8Valid(v string) bool { return len(v) <= 256 && utf8.ValidString(v) }
func randomDeviceLoginID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "device-login:" + base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *Handler) createLoginInteraction(r *http.Request, peerIP string, payload []byte) (browser.IssuedAuthorizationInteraction, string, *http.Cookie, error) {
	var session browser.IssuedSession
	if current, token, ok := h.session(r); ok && !current.Authenticated() && current.PeerIP != "" {
		session = browser.IssuedSession{Session: current, Token: token}
	} else {
		var err error
		session, err = h.browser.CreateInitSession(r.Context(), h.now().Add(interactionLifetime), peerIP)
		if err != nil {
			return browser.IssuedAuthorizationInteraction{}, "", nil, err
		}
	}
	interactionToken, err := randomDeviceLoginID()
	if err != nil {
		return browser.IssuedAuthorizationInteraction{}, "", nil, err
	}
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), session.Token, interactionToken, payload, h.now().Add(interactionLifetime))
	if err != nil {
		return browser.IssuedAuthorizationInteraction{}, "", nil, err
	}
	csrf, err := browser.DeriveCSRFToken(session.Token)
	if err != nil {
		return browser.IssuedAuthorizationInteraction{}, "", nil, err
	}
	cookie, err := browser.SessionCookie(h.issuer, session.Token, session.ExpiresAt)
	if err != nil {
		return browser.IssuedAuthorizationInteraction{}, "", nil, err
	}
	return interaction, csrf, cookie, nil
}

// ConnectionHandoffLoginHandler authenticates the owner for a pending handoff.
// It only redirects to review; approval remains an explicit separate action.
func (h *Handler) ConnectionHandoffLoginHandler(forceMFA bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if r.URL.Path != "/account/connection-login" || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
			return
		}
		if len(r.Header.Values("Authorization")) != 0 || r.URL.RawPath != "" {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			h.connectionHandoffLoginGet(w, r, forceMFA)
			return
		}
		h.connectionHandoffLoginPost(w, r, forceMFA)
	})
}

func canonicalHandoffID(raw string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	return raw, err == nil && len(b) == 18 && base64.RawURLEncoding.EncodeToString(b) == raw
}

func (h *Handler) connectionHandoffLoginGet(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["handoff_id"]) != 1 {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	handoffID, ok := canonicalHandoffID(query.Get("handoff_id"))
	if !ok {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	if current, _, ok := h.session(r); ok && current.Authenticated() {
		if forceMFA && current.AuthenticationMethod != "mfa" {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		h.connectionHandoffRedirect(w, handoffID)
		return
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok || peerIP == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(connectionHandoffLoginInteraction{Purpose: connectionHandoffLoginPayload, HandoffID: handoffID})
	interaction, csrf, cookie, err := h.createLoginInteraction(r, peerIP, payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	themeURL, err := h.resolveThemeURL(r.Context(), "rauthy")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceLoginPage.Execute(w, deviceLoginData{Action: "connection-login", Title: "Continue connection handoff", Intro: "Sign in to review this connection handoff. Signing in does not approve it.", Interaction: interaction.Token, CSRFToken: csrf, ThemeURL: themeURL})
}

func (h *Handler) connectionHandoffLoginPost(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || crossSite(r.Header.Values("Sec-Fetch-Site")) || !sameIssuerOrigin(r, h.issuer) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	h.loginPost(w, r, forceMFA, connectionHandoffDestination)
}

func (h *Handler) connectionHandoffRedirect(w http.ResponseWriter, handoffID string) {
	href := h.issuer + "/account/connection-handoffs/" + url.PathEscape(handoffID)
	w.Header().Set("Location", href)
	w.WriteHeader(http.StatusSeeOther)
}
func (h *Handler) deviceLoginRedirect(w http.ResponseWriter, code string) {
	target := h.issuer + "/oidc/device/verify"
	if code != "" {
		target += "?user_code=" + url.QueryEscape(code)
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
}
