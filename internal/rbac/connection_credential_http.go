package rbac

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mrchypark/goauthy/internal/saas"
)

// DeliverConnectionCredential returns a consented credential to an
// authenticated server-side consumer. The request carries no caller data.
func (h *Handler) DeliverConnectionCredential(w http.ResponseWriter, r *http.Request) {
	owner, consumer, authority, ok := h.authorizeConnectionUseBoundary(w, r, http.MethodPost, false, false, true)
	if !ok {
		return
	}
	delivery, err := h.saasCredentials.DeliverUseGrantCredential(r.Context(), owner, consumer, r.PathValue("grant_id"), h.connectionUseResource, authority)
	if err != nil {
		if errors.Is(err, saas.ErrUseGrantInvalid) {
			h.badRequest(w)
			return
		}
		h.writeInvokeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(delivery)
}
