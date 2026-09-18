package upstreamprovider

import (
	"context"
	"mime"
	"net/http"
	"time"
)

// BackchannelLogoutHandler accepts logout only for the provider selected by the
// mounted route. apply must atomically commit replay state and local revocation;
// a successful signature check alone is not a successful logout.
func (h *Handler) BackchannelLogoutHandler(apply func(context.Context, string, *LogoutTokenClaims, string) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		reject := func() { http.Error(w, "Invalid logout request", http.StatusBadRequest) }
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if h == nil || apply == nil {
			reject()
			return
		}
		verifier, ok := h.verifier.(*JWKSVerifier)
		if !ok || verifier == nil {
			reject()
			return
		}
		providerID := r.PathValue("providerID")
		cfg, ok := h.configs[providerID]
		if !ok || cfg.NormalizedKind() != ProviderKindOIDC {
			reject()
			return
		}
		contentTypes := r.Header.Values("Content-Type")
		if len(contentTypes) != 1 {
			reject()
			return
		}
		contentType, _, err := mime.ParseMediaType(contentTypes[0])
		if err != nil || contentType != "application/x-www-form-urlencoded" {
			reject()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 24<<10)
		if r.ParseForm() != nil {
			reject()
			return
		}
		tokens := r.PostForm["logout_token"]
		if len(tokens) != 1 || tokens[0] == "" {
			reject()
			return
		}
		claims, err := verifier.VerifyLogoutToken(r.Context(), tokens[0], cfg.Issuer, cfg.ClientID, h.now(), 2*time.Minute)
		if err != nil {
			reject()
			return
		}
		if err := apply(r.Context(), cfg.ClientID, claims, DigestSHA256(tokens[0])); err != nil {
			reject()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
