package rbac

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/saas"
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
		h.unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || h.crossSite(r) || len(r.Header.Values("Cookie")) != 0 {
		h.genericUnauthorized(w)
		return
	}
	if len(r.Header.Values("Authorization")) != 1 {
		h.genericUnauthorized(w)
		return
	}
	owner, consumer, authority, err := h.connectionUseAuthorizer(r)
	if err != nil || authority == nil {
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
		h.writeInvokeError(w, err)
		return
	}
	if grant.ConnectorDigest == "" {
		h.notFound(w)
		return
	}
	connector, err := h.saasCredentials.APIKeyConnector(r.Context(), grant.Owner, grant.CollectionID, grant.ConnectionID, guard)
	if err != nil {
		h.writeInvokeError(w, err)
		return
	}
	if connector.Digest() != grant.ConnectorDigest {
		h.notFound(w)
		return
	}
	allowed := false
	for _, operation := range connector.Info().Operations {
		if operation.ID == in.Operation {
			allowed = true
			break
		}
	}
	if !allowed {
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

func validInvokeConnectorID(s string) bool {
	if s == "" || len([]byte(s)) > 64 || !utf8.ValidString(s) || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
		return false
	}
	for _, b := range []byte(s[1:]) {
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return false
		}
	}
	return strings.ToLower(s) == s
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
