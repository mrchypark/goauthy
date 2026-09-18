package loginpolicy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
)

type LockdownHandler struct {
	lockdown *LockdownStore
	isAdmin  func(http.ResponseWriter, *http.Request, bool) bool
}

func NewLockdownHandler(lockdown *LockdownStore, isAdmin func(http.ResponseWriter, *http.Request, bool) bool) *LockdownHandler {
	return &LockdownHandler{lockdown: lockdown, isAdmin: isAdmin}
}

func (h *LockdownHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getStatus(w, r)
	case http.MethodPost:
		h.enable(w, r)
	case http.MethodDelete:
		h.disable(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+","+http.MethodPost+","+http.MethodDelete)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (h *LockdownHandler) getStatus(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, false) {
		return
	}
	locked, reason, until, err := h.lockdown.IsLockedDown(r.Context())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lockdownStatusResponse{
		Enabled:   locked,
		Reason:    reason,
		ExpiresAt: until,
	})
}

func (h *LockdownHandler) enable(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, true) {
		return
	}
	var req lockdownRequest
	if err := decodeStrictJSON(w, r, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}
	var until time.Time
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil || d <= 0 {
			http.Error(w, "invalid duration", http.StatusBadRequest)
			return
		}
		until = time.Now().UTC().Add(d)
	}
	if err := h.lockdown.SetLockdown(r.Context(), true, req.Reason, until); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *LockdownHandler) disable(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, true) {
		return
	}
	if err := h.lockdown.SetLockdown(r.Context(), false, "", time.Time{}); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *LockdownHandler) authorize(w http.ResponseWriter, r *http.Request, mutation bool) bool {
	if r.URL.RawQuery != "" || apikey.HasAuthorization(r) || strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return h.isAdmin(w, r, mutation)
}

type lockdownRequest struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason"`
	Duration string `json:"duration"`
}

type lockdownStatusResponse struct {
	Enabled   bool      `json:"enabled"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if len(r.Header.Values("Content-Type")) != 1 {
		return errors.New("invalid content type")
	}
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("invalid content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
