package upstreamprovider

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
)

// reservedProviderIssuers contains issuer strings that must never be
// created through the public API. Matches the pinned rauthy v0.36.2
// PROVIDER_ATPROTO constant.
var reservedProviderIssuers = map[string]bool{
	"atproto": true,
}

// alphanumericAlphabet is the 62-character set matching the pinned
// rauthy v0.36.2 rand::distr::Alphanumeric used by get_rand/new_store_id.
const alphanumericAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateProviderID returns a 24-character random alphanumeric ASCII
// string matching the pinned rauthy v0.36.2 new_store_id() output.
func GenerateProviderID() (string, error) {
	// 24 characters; each byte selects one of 62 alphanumeric chars.
	// We discard bytes >= 248 (62*4) to avoid modulo bias.
	id := make([]byte, 24)
	for i := range id {
		for {
			var buf [1]byte
			if _, err := rand.Read(buf[:]); err != nil {
				return "", err
			}
			if buf[0] < 248 {
				id[i] = alphanumericAlphabet[buf[0]%62]
				break
			}
		}
	}
	return string(id), nil
}

// maxProviderBodyBytes is the upper bound for a JSON-encoded ProviderRequest.
// 64 KiB covers every realistic field combination with large margins.
const maxProviderBodyBytes = 64 << 10

// decodeProviderBody reads at most maxProviderBodyBytes from r.Body,
// decodes exactly one JSON object with no trailing data, and rejects
// unknown fields. It returns 400 on any parse or trailing-input error.
func decodeProviderBody(w http.ResponseWriter, r *http.Request) (ProviderRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProviderBodyBytes)
	var req ProviderRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return ProviderRequest{}, false
	}
	// Reject trailing JSON after the first object.
	if _, err := decoder.Token(); err != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return ProviderRequest{}, false
	}
	if err := req.Validate(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return ProviderRequest{}, false
	}
	return req, true
}

// CreateProvider handles POST /auth/v1/providers/create. It validates
// the request body, enforces reserved-issuer and PKCE-or-secret rules,
// generates a random provider ID, and persists the new provider.
//
// Pinned rauthy v0.36.2 POST /providers/create does NOT enforce
// client_secret_basic | client_secret_post; that restriction is
// PUT-only.
func (h *RegistryHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	principal, ok := h.authorize(w, r, apikey.Create)
	if !ok {
		return
	}

	req, ok := decodeProviderBody(w, r)
	if !ok {
		return
	}
	if reservedProviderIssuers[req.Issuer] {
		http.Error(w, "Must not contain a reserved name", http.StatusBadRequest)
		return
	}
	if !req.UsePKCE && req.ClientSecret == nil {
		http.Error(w, "Must at least be a confidential client or use PKCE", http.StatusBadRequest)
		return
	}

	providerID, err := GenerateProviderID()
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	requestID, err := providerMutationRequestID("create", providerID)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	doc, err := h.store.CreateAuthorized(r.Context(), providerID, requestID, req, h.keys, principal)
	if err != nil {
		if errors.Is(err, ErrProviderExists) {
			http.Error(w, "Conflict", http.StatusConflict)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	secret, err := h.store.SecretCleartext(doc)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc.Response(secret))
}

// UpdateProvider handles PUT /auth/v1/providers/{id}. It validates the
// request body, enforces PKCE-or-secret and secret-method rules, and
// replaces all non-ID columns of the provider row.
func (h *RegistryHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	principal, ok := h.authorize(w, r, apikey.Update)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	req, ok := decodeProviderBody(w, r)
	if !ok {
		return
	}
	if reservedProviderIssuers[req.Issuer] {
		http.Error(w, "Must not contain a reserved name", http.StatusBadRequest)
		return
	}
	if !req.UsePKCE && req.ClientSecret == nil {
		http.Error(w, "Must at least be a confidential client or use PKCE", http.StatusBadRequest)
		return
	}
	// PUT-only: client_secret requires at least one secret transport method.
	if req.ClientSecret != nil && !(req.ClientSecretBasic || req.ClientSecretPost) {
		http.Error(w, "A confidential client must have a least one of client_secret_basic | client_secret_post", http.StatusBadRequest)
		return
	}

	requestID, err := providerMutationRequestID("update", id)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	_, err = h.store.UpdateAuthorized(r.Context(), id, requestID, req, h.keys, principal)
	if err != nil {
		if errors.Is(err, ErrProviderNotFound) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteProvider handles DELETE /auth/v1/providers/{id}. Missing providers
// succeed silently, matching the pinned rauthy v0.36.2 behavior.
func (h *RegistryHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	principal, ok := h.authorize(w, r, apikey.Delete)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	requestID, err := providerMutationRequestID("delete", id)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	err = h.store.DeleteAuthorized(r.Context(), id, requestID, h.keys, principal)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}
