package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
)

type convertPasswordRequest struct {
	PasswordNew string `json:"password_new"`
}

func (h *Handler) AdminConvertPassword(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	subject := r.PathValue("subject")
	if !validSubjectID(subject) {
		h.notFound(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Users", apikey.Update, true)
	if !ok {
		return
	}
	_ = actor
	_ = key
	name, _ := browser.CookieName(h.issuer)
	cookie, err := r.Cookie(name)
	if err != nil {
		h.genericUnauthorized(w)
		return
	}
	peer := browser.PeerIPFromContext(r.Context())
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
	if err != nil || !session.Authenticated() || h.identity.ValidateSubject(r.Context(), session.Subject) != nil {
		h.genericUnauthorized(w)
		return
	}
	admin, err := h.store.IsAdmin(r.Context(), session.Subject)
	if err != nil {
		h.unavailable(w)
		return
	}
	if !admin {
		h.genericUnauthorized(w)
		return
	}
	if browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
		h.genericUnauthorized(w)
		return
	}
	if _, err := h.identity.UserBySubject(r.Context(), subject); err != nil {
		h.notFound(w)
		return
	}
	passkeyOnly, err := h.identity.IsPasskeyOnly(r.Context(), subject)
	if err != nil {
		h.unavailable(w)
		return
	}
	if !passkeyOnly {
		h.error(w, http.StatusConflict, "Conflict")
		return
	}
	input, err := decodeConvertPassword(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	if err := h.identity.SetPasswordAdmin(r.Context(), subject, []byte(input.PasswordNew)); err != nil {
		if errors.Is(err, identity.ErrPasswordRejected) {
			h.badRequest(w)
			return
		}
		h.unavailable(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeConvertPassword(w http.ResponseWriter, r *http.Request) (convertPasswordRequest, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return convertPasswordRequest{}, errors.New("content type")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return convertPasswordRequest{}, errors.New("content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 || rejectDuplicateJSONFields(body) != nil {
		return convertPasswordRequest{}, errors.New("invalid JSON")
	}
	var wire struct {
		PasswordNew *string `json:"password_new"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.PasswordNew == nil || *wire.PasswordNew == "" {
		return convertPasswordRequest{}, errors.New("invalid convert password request")
	}
	return convertPasswordRequest{PasswordNew: *wire.PasswordNew}, nil
}
