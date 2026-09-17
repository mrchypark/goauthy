package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"unicode"
)

type SaaSProviderInfo struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	CallbackURI string   `json:"callback_uri"`
	Scopes      []string `json:"scopes"`
}

func (h *Handler) BindSaaSProviders(providers []SaaSProviderInfo) error {
	if h == nil {
		return errors.New("RBAC handler required")
	}
	copyProviders := make([]SaaSProviderInfo, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for i, provider := range providers {
		if provider.ID == "" || len(provider.ID) > 64 || strings.TrimSpace(provider.ID) != provider.ID || provider.ID != strings.ToLower(provider.ID) {
			return errors.New("invalid SaaS provider ID")
		}
		for _, r := range provider.ID {
			if r > unicode.MaxASCII {
				return errors.New("invalid SaaS provider ID")
			}
		}
		if _, ok := seen[provider.ID]; ok {
			return errors.New("duplicate SaaS provider ID")
		}
		if (provider.Kind != "oauth2" && provider.Kind != "github") || provider.CallbackURI == "" {
			return errors.New("invalid SaaS provider metadata")
		}
		seen[provider.ID] = struct{}{}
		copyProviders[i] = provider
		copyProviders[i].Scopes = append([]string{}, provider.Scopes...)
	}
	sort.Slice(copyProviders, func(i, j int) bool { return copyProviders[i].ID < copyProviders[j].ID })
	h.saasProviders = copyProviders
	return nil
}

func (h *Handler) SaaSProviders(w http.ResponseWriter, r *http.Request) {
	if h.saasProviderStore != nil {
		h.managedSaaSProviders(w, r)
		return
	}
	h.securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	if _, ok := h.actor(w, r, false); !ok {
		return
	}
	providers := make([]SaaSProviderInfo, len(h.saasProviders))
	copy(providers, h.saasProviders)
	for i := range providers {
		providers[i].Scopes = append([]string{}, providers[i].Scopes...)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(providers)
}
