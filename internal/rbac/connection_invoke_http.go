package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/rhiza"
)

// BindConnectionUseAuthorizer wires the OAuth resource-server adapter used by
// the public connection-use boundary.
func (h *Handler) BindConnectionUseAuthorizer(authorizer func(http.ResponseWriter, *http.Request) (string, string, func() (string, []any), bool)) error {
	if h == nil || authorizer == nil {
		return errors.New("connection use authorizer required")
	}
	h.connectionUseAuthorizer = authorizer
	return nil
}

func (h *Handler) authorizeConnectionUseBoundary(w http.ResponseWriter, r *http.Request, allowMethod string, allowSameOriginProxy bool, requireProviderStore bool, requireEmptyBody bool) (string, string, func() (string, []any), bool) {
	h.securityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	issuer, err := url.Parse(h.issuer)
	if err != nil || issuer.Scheme != "https" {
		slog.Error("connection use unavailable", "stage", "issuer_configuration")
		h.unavailable(w)
		return "", "", nil, false
	}
	if h.saasCredentials == nil || h.connectionUseAuthorizer == nil || h.connectionUseResource == "" || (requireProviderStore && h.saasProviderStore == nil) {
		slog.Error("connection use unavailable", "stage", "handler_configuration")
		h.unavailable(w)
		return "", "", nil, false
	}
	if r.Method != allowMethod {
		w.Header().Set("Allow", allowMethod)
		h.methodNotAllowed(w)
		return "", "", nil, false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 1 {
		h.genericUnauthorized(w)
		return "", "", nil, false
	}
	if allowSameOriginProxy {
		if h.crossSite(r) {
			h.genericUnauthorized(w)
			return "", "", nil, false
		}
	} else if len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 {
		h.genericUnauthorized(w)
		return "", "", nil, false
	}
	if !allowSameOriginProxy && (len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-CSRF-Token")) != 0 || (requireEmptyBody && !emptyBody(r))) {
		h.badRequest(w)
		return "", "", nil, false
	}
	owner, consumer, authority, ok := h.connectionUseAuthorizer(w, r)
	if !ok {
		return "", "", nil, false
	}
	if authority == nil {
		slog.Error("connection use request rejected", "stage", "authorizer_contract")
		h.genericUnauthorized(w)
		return "", "", nil, false
	}
	return owner, consumer, authority, true
}

// InvokeConnectionGrant executes one allowlisted operation using a consented
// connection. The request body contains no actor, URL, headers, or secret.
func (h *Handler) InvokeConnectionGrant(w http.ResponseWriter, r *http.Request) {
	owner, consumer, authority, ok := h.authorizeConnectionUseBoundary(w, r, http.MethodPost, true, false, false)
	if !ok {
		return
	}
	var in struct {
		Operation string `json:"operation"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	if err := decodeJSON(r, &in, map[string]bool{"operation": true}, []string{"operation"}, nil); err != nil || !validInvokeConnectorID(in.Operation) {
		h.badRequest(w)
		return
	}
	grantID := r.PathValue("grant_id")
	if grantID == "" {
		h.notFound(w)
		return
	}
	grant, guard, err := h.saasCredentials.AuthorizeUseGrant(r.Context(), owner, consumer, grantID, h.connectionUseResource, "proxy", authority)
	if err != nil {
		logConnectionUseFailure("authorize_use_grant", err)
		h.writeInvokeError(w, err)
		return
	}
	if grant.ConnectorDigest == "" {
		h.notFound(w)
		return
	}
	connector, err := h.saasCredentials.APIKeyConnector(r.Context(), grant.Owner, grant.CollectionID, grant.ConnectionID, guard)
	if err != nil {
		logConnectionUseFailure("connector_lookup", err)
		h.writeInvokeError(w, err)
		return
	}
	if connector.Digest() != grant.ConnectorDigest {
		h.notFound(w)
		return
	}
	if !connector.HasOperation(in.Operation) {
		h.badRequest(w)
		return
	}
	result, err := h.saasCredentials.CallAPIKey(r.Context(), grant.Owner, grant.CollectionID, grant.ConnectionID, connector, in.Operation, guard)
	if err != nil {
		h.writeInvokeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func logConnectionUseFailure(stage string, err error) {
	slog.Error("connection use failed", "stage", stage, "error_class", connectionUseErrorClass(err), "error_type", fmt.Sprintf("%T", err))
}

func connectionUseErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, rhiza.ErrCommitUnknown):
		return "commit_unknown"
	case errors.Is(err, rhiza.ErrNotReady):
		return "node_not_ready"
	case errors.Is(err, rhiza.ErrQuorumUnavailable):
		return "quorum_unavailable"
	case errors.Is(err, rhiza.ErrDurabilityUnavailable):
		return "durability_unavailable"
	case errors.Is(err, saas.ErrAPIKeyRequest):
		return "provider_request"
	case errors.Is(err, saas.ErrUseGrantConflict), errors.Is(err, saas.ErrCredentialConflict):
		return "conflict"
	case errors.Is(err, saas.ErrUseGrantNotFound), errors.Is(err, saas.ErrCredentialNotFound):
		return "not_found"
	case errors.Is(err, saas.ErrCredentialUnauthorized):
		return "unauthorized"
	case errors.Is(err, saas.ErrCredentialCorrupted):
		return "corrupted"
	case errors.Is(err, saas.ErrRefreshUncertain):
		return "refresh_uncertain"
	case errors.Is(err, saas.ErrUseGrantInvalid):
		return "invalid"
	default:
		return "unknown"
	}
}

func validInvokeConnectorID(s string) bool {
	if s == "" || len(s) > 64 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func (h *Handler) writeInvokeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, saas.ErrUseGrantInvalid):
		h.badRequest(w)
	case errors.Is(err, saas.ErrUseGrantNotFound), errors.Is(err, saas.ErrCredentialNotFound):
		h.notFound(w)
	case errors.Is(err, saas.ErrUseGrantConflict), errors.Is(err, saas.ErrCredentialConflict):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrCredentialUnauthorized), errors.Is(err, saas.ErrCredentialCorrupted):
		h.error(w, http.StatusInternalServerError, "Internal Server Error")
	case errors.Is(err, saas.ErrAPIKeyRequest), errors.Is(err, saas.ErrRefreshUncertain):
		h.error(w, http.StatusBadGateway, "Bad Gateway")
	default:
		h.unavailable(w)
	}
}
