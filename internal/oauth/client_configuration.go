package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/ory/fosite"
)

const clientConfigurationPath = "/oidc/client-configuration"

type clientConfiguration struct {
	Version       string   `json:"version"`
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	ClientKind    string   `json:"client_kind"`
	Enabled       bool     `json:"enabled"`
	Confidential  bool     `json:"confidential"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	Scopes        []string `json:"scopes"`
	DefaultScopes []string `json:"default_scopes"`
	Audience      []string `json:"audience"`
	DefaultAud    []string `json:"default_aud"`
}

// ClientConfigurationHandler returns the effective configuration of only the
// authenticated bootstrap client. It is read-only and never returns secrets.
func (s *Server) ClientConfigurationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.Error(w, "query parameters are not allowed", http.StatusBadRequest)
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				http.Error(w, "request body is not allowed", http.StatusBadRequest)
				return
			}
		}
		provider, ok := s.provider.(*fosite.Fosite)
		_, _, basic := r.BasicAuth()
		if !ok || !basic || s.oidc == nil || s.store == nil || s.store.client == nil || len(r.Header.Values("Authorization")) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="client-configuration"`)
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		client, err := provider.AuthenticateClient(r.Context(), r, url.Values{})
		if err != nil || client == nil || client.GetID() != s.store.client.GetID() || client.IsPublic() {
			w.Header().Set("WWW-Authenticate", `Basic realm="client-configuration"`)
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		var defaults []string
		if snapshot, ok := client.(*bootstrapScopedClient); ok {
			defaults = snapshot.defaultScopes
		}
		cfg := clientConfiguration{
			Version: "goauthy.client-configuration.v1", Issuer: s.oidc.Issuer,
			ClientID: client.GetID(), ClientKind: "bootstrap", Enabled: true,
			Confidential: !client.IsPublic(), RedirectURIs: client.GetRedirectURIs(),
			GrantTypes: append([]string(nil), client.GetGrantTypes()...), Scopes: []string{},
			DefaultScopes: append([]string{}, defaults...), Audience: append([]string{}, client.GetAudience()...),
			DefaultAud: []string{},
		}
		cfg.RedirectURIs = append([]string{}, cfg.RedirectURIs...)
		cfg.GrantTypes = append([]string{}, cfg.GrantTypes...)
		for _, scope := range client.GetScopes() {
			if !slices.Contains(cfg.Scopes, scope) {
				cfg.Scopes = append(cfg.Scopes, scope)
			}
		}
		if audience := s.defaultAudiences[client.GetID()]; audience != "" {
			cfg.DefaultAud = []string{audience}
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			http.Error(w, "configuration unavailable", http.StatusInternalServerError)
			return
		}
		digest := sha256.Sum256(body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"sha256:`+hex.EncodeToString(digest[:])+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}
