package account

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
)

//go:embed dashboard.html dashboard.js dashboard.css connections.js connection_grants.js devices.js
var dashboardFS embed.FS

var dashboardTemplate = template.Must(template.ParseFS(dashboardFS, "dashboard.html"))

// Dashboard serves the current browser account, never bearer/API-key authority.
// Existing mutation handlers remain the only password/profile policy authority.
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r == nil || r.URL == nil || r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if r.Header.Values("Authorization") != nil {
		unauthorized(w)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case "/account", "/account/data", "/account/app.js", "/account/connections.js", "/account/connection-grants.js", "/account/devices.js", "/account/account.css":
	default:
		http.NotFound(w, r)
		return
	}
	session, token, ok := h.session(r)
	if !ok {
		unauthorized(w)
		return
	}
	profile, err := h.identity.AccountProfileBySubject(r.Context(), session.Subject)
	if err != nil {
		if errors.Is(err, identity.ErrInactiveSubject) {
			unauthorized(w)
		} else {
			http.Error(w, "Account unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	issuer, _ := url.Parse(h.issuer)
	base := strings.TrimRight(issuer.Path, "/")
	if r.URL.Path == "/account/data" {
		csrf, err := browser.DeriveCSRFToken(token)
		if err != nil {
			unauthorized(w)
			return
		}
		passkeyOnly, err := h.identity.IsPasskeyOnly(r.Context(), session.Subject)
		if err != nil {
			http.Error(w, "Account unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject": profile.Subject, "email": profile.Email, "email_verified": profile.EmailVerified,
			"preferred_username": profile.PreferredUsername, "given_name": profile.GivenName, "family_name": profile.FamilyName,
			"csrf_token": csrf, "base_path": base, "password_policy": policyResponse(h.rules),
			"features": map[string]bool{
				"password": !passkeyOnly, "passkeys": h.passkeys != nil,
				"passkey_conversion": !passkeyOnly && h.passkeys != nil && session.AuthenticationMethod == "mfa" && session.PeerIP != "",
			},
		})
		return
	}
	switch r.URL.Path {
	case "/account/app.js", "/account/connections.js", "/account/connection-grants.js", "/account/devices.js", "/account/account.css":
		name, media := "dashboard.js", "text/javascript; charset=utf-8"
		if strings.HasSuffix(r.URL.Path, "connections.js") {
			name = "connections.js"
		}
		if strings.HasSuffix(r.URL.Path, "connection-grants.js") {
			name = "connection_grants.js"
		}
		if strings.HasSuffix(r.URL.Path, "devices.js") {
			name = "devices.js"
		}
		if strings.HasSuffix(r.URL.Path, ".css") {
			name, media = "dashboard.css", "text/css; charset=utf-8"
		}
		w.Header().Set("Content-Type", media)
		data, _ := dashboardFS.ReadFile(name)
		_, _ = w.Write(data)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dashboardTemplate.Execute(w, struct{ BasePath string }{base})
	}
}
