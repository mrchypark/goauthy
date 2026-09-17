package rbac

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/device"
)

// BindDeviceSessions wires the browser-account device-session store.
func (h *Handler) BindDeviceSessions(store *device.Store) error {
	if h == nil || store == nil {
		return errors.New("device sessions store required")
	}
	h.deviceSessions = store
	return nil
}

// AccountDevices handles GET /auth/v1/account/devices and
// DELETE /auth/v1/account/devices/{id}. It intentionally accepts only the
// current browser session; bearer/API-key authority is not a user account
// authority and is rejected by authConnectionSubject.
func (h *Handler) AccountDevices(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if h.deviceSessions == nil || r.URL.RawQuery != "" || h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	id := r.PathValue("id")
	if r.Method == http.MethodGet && id != "" {
		h.methodNotAllowed(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodGet)
		h.methodNotAllowed(w)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
		if err != nil || len(body) != 0 {
			h.badRequest(w)
			return
		}
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		items, err := h.deviceSessions.ListUserSessions(r.Context(), owner, authority)
		if err != nil {
			h.writeDeviceSessionError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	if !validID(id) {
		h.error(w, http.StatusNotFound, "Not found")
		return
	}
	if err := h.deviceSessions.RevokeUserSession(r.Context(), owner, id, authority); err != nil {
		h.writeDeviceSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeDeviceSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, device.ErrUserSessionNotFound):
		h.error(w, http.StatusNotFound, "Not found")
	case errors.Is(err, device.ErrUserSessionUnauthorized):
		h.genericUnauthorized(w)
	case errors.Is(err, device.ErrInvalid):
		h.badRequest(w)
	default:
		h.unavailable(w)
	}
}
