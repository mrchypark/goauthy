package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

func (h *Handler) AccountConnectionOAuth2Start(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.saasProviderStore == nil || h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	var in struct {
		ProviderID string `json:"provider_id"`
	}
	if err := decodeJSON(r, &in, map[string]bool{"provider_id": true}, []string{"provider_id"}, nil); err != nil || strings.TrimSpace(in.ProviderID) == "" {
		h.badRequest(w)
		return
	}
	collectionID, connectionID := r.PathValue("collection_id"), r.PathValue("connection_id")
	if collectionID == "" || connectionID == "" {
		h.notFound(w)
		return
	}
	cookies := r.CookiesNamed(mustCookieName(h.issuer))
	if len(cookies) != 1 || cookies[0].Value == "" {
		h.genericUnauthorized(w)
		return
	}
	callback := h.issuer + "/auth/v1/saas/callback/" + url.PathEscape(in.ProviderID)
	start, err := h.saasCredentials.BeginOAuth2(r.Context(), h.saasProviderStore, owner, collectionID, connectionID, in.ProviderID, upstreamprovider.DigestSHA256(cookies[0].Value), callback, authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(start)
}

func (h *Handler) AccountConnectionOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodGet || r.URL.RawQuery == "" || len(r.URL.RawQuery) > 8192 || !emptyBody(r) {
		h.genericUnauthorized(w)
		return
	}
	if h.saasProviderStore == nil || h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	query, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		h.badRequest(w)
		return
	}
	if len(query["error"]) > 0 {
		if len(query["error"]) != 1 || len(query["error_description"]) > 1 {
			h.badRequest(w)
			return
		}
		h.badRequest(w)
		return
	}
	if len(query["state"]) != 1 || len(query["code"]) != 1 || len(query) != 2 || query.Get("state") == "" || query.Get("code") == "" {
		h.badRequest(w)
		return
	}
	cookies := r.CookiesNamed(mustCookieName(h.issuer))
	if len(cookies) != 1 || cookies[0].Value == "" {
		h.genericUnauthorized(w)
		return
	}
	providerID := r.PathValue("provider_id")
	if providerID == "" {
		h.notFound(w)
		return
	}
	callback := h.issuer + "/auth/v1/saas/callback/" + url.PathEscape(providerID)
	status, err := h.saasCredentials.CompleteOAuth2(r.Context(), h.saasProviderStore, owner, "", "", providerID, upstreamprovider.DigestSHA256(cookies[0].Value), callback, query.Get("state"), query.Get("code"), authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	h.writeOAuth2Completion(w, r, status)
}

func (h *Handler) oauth2ConnectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, saas.ErrCredentialNotFound), errors.Is(err, saas.ErrProviderNotFound), errors.Is(err, saas.ErrAuthorizationNotFound):
		h.notFound(w)
	case errors.Is(err, saas.ErrCredentialConflict), errors.Is(err, saas.ErrAuthorizationConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrCredentialUnauthorized), errors.Is(err, saas.ErrProviderUnauthorized):
		h.genericUnauthorized(w)
	case errors.Is(err, saas.ErrProviderInvalid), errors.Is(err, saas.ErrOAuth2Exchange), errors.Is(err, saas.ErrOAuth2Identity):
		h.badRequest(w)
	default:
		h.unavailable(w)
	}
}

func mustCookieName(issuer string) string {
	name, _ := browser.CookieName(issuer)
	return name
}

func (h *Handler) AccountConnectionOAuth2Reconnect(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) || len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	version, err := apiKeyVersion(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	status, err := h.saasCredentials.PrepareOAuth2Reconnect(r.Context(), owner, r.PathValue("collection_id"), r.PathValue("connection_id"), version, authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// AccountConnectionOAuth2Status returns owner metadata, never credentials.
func (h *Handler) AccountConnectionOAuth2Status(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) || !emptyBody(r) {
		h.badRequest(w)
		return
	}
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	status, err := h.saasCredentials.OAuth2Status(r.Context(), owner, r.PathValue("collection_id"), r.PathValue("connection_id"), authority)
	if err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// AccountConnectionOAuth2Revoke blocks future local use. It does not claim to
// revoke the provider's token remotely or delete the connection metadata.
func (h *Handler) AccountConnectionOAuth2Revoke(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) || len(r.Header.Values("If-Match")) != 0 {
		h.badRequest(w)
		return
	}
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	version, err := apiKeyVersion(r)
	if err != nil {
		h.badRequest(w)
		return
	}
	if err := h.saasCredentials.RevokeOAuth2(r.Context(), owner, r.PathValue("collection_id"), r.PathValue("connection_id"), version, authority); err != nil {
		h.oauth2ConnectionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
