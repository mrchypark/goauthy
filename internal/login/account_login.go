package login

import (
	"encoding/json"
	"net/http"
)

// AccountLoginHandler authenticates a browser for the fixed account dashboard.
func (h *Handler) AccountLoginHandler(forceMFA bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if r.URL.Path != "/account/login" || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
			return
		}
		if len(r.Header.Values("Authorization")) != 0 || r.URL.RawPath != "" {
			http.Error(w, "Invalid login request", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			h.accountLoginGet(w, r, forceMFA)
			return
		}
		h.accountLoginPost(w, r, forceMFA)
	})
}

func (h *Handler) accountLoginGet(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	if current, _, ok := h.session(r); ok && current.Authenticated() {
		if forceMFA && current.AuthenticationMethod != "mfa" {
			h.startApprovalReauthentication(w, r, approvalLoginInteraction{Purpose: approvalLoginPayload, Account: true, ForceMFA: true}, "/account/login")
			return
		}
		h.accountLoginRedirect(w)
		return
	}
	peerIP, ok := h.resolvePeerIP(r)
	if !ok || peerIP == "" {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(approvalLoginInteraction{Purpose: approvalLoginPayload, Account: true, ForceMFA: forceMFA})
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
	h.renderApprovalLoginPage(w, r, payload, "/account/login", "Sign in to manage your account.", interaction.Token, csrf, themeURL)
}

func (h *Handler) accountLoginPost(w http.ResponseWriter, r *http.Request, forceMFA bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || crossSite(r.Header.Values("Sec-Fetch-Site")) || !sameIssuerOrigin(r, h.issuer) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	h.loginPost(w, r, forceMFA, accountLoginDestination)
}

func (h *Handler) accountLoginRedirect(w http.ResponseWriter) {
	w.Header().Set("Location", h.issuer+"/")
	w.WriteHeader(http.StatusSeeOther)
}
