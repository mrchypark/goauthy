package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/rhiza"
)

// BindConnectionUseAuthorizer wires the OAuth resource-server adapter used by
// the public connection-use boundary.
func (h *Handler) BindConnectionUseAuthorizer(authorizer func(*http.Request) (string, string, func() (string, []any), error)) error {
	if h == nil || authorizer == nil {
		return errors.New("connection use authorizer required")
	}
	h.connectionUseAuthorizer = authorizer
	return nil
}

// InvokeConnectionGrant executes one allowlisted operation using a consented
// connection. The request body contains no actor, URL, headers, or secret.
func (h *Handler) InvokeConnectionGrant(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.saasCredentials == nil || h.connectionUseAuthorizer == nil || h.connectionUseResource == "" {
		slog.Error("connection use unavailable", "stage", "handler_configuration")
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		slog.Error("connection use request rejected", "stage", "request_query")
		h.genericUnauthorized(w)
		return
	}
	if h.crossSite(r) {
		slog.Error("connection use request rejected", "stage", "cross_site")
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("Cookie")) != 0 {
		slog.Error("connection use request rejected", "stage", "cookie_header")
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("Authorization")) != 1 {
		slog.Error("connection use request rejected", "stage", "authorization_header_count")
		h.genericUnauthorized(w)
		return
	}
	owner, consumer, authority, err := h.connectionUseAuthorizer(r)
	if err != nil {
		slog.Error("connection use request rejected", "stage", "resource_authorization", "error_class", connectionUseErrorClass(err))
		h.genericUnauthorized(w)
		return
	}
	if authority == nil {
		slog.Error("connection use request rejected", "stage", "authorizer_contract")
		h.genericUnauthorized(w)
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
	case errors.Is(err, saas.ErrUseGrantConflict), errors.Is(err, saas.ErrCredentialConflict), errors.Is(err, saas.ErrCredentialUnauthorized):
		h.error(w, http.StatusConflict, "Conflict")
	case errors.Is(err, saas.ErrAPIKeyRequest):
		h.error(w, http.StatusBadGateway, "Bad Gateway")
	default:
		h.unavailable(w)
	}
}
