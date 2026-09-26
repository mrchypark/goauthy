package account

import (
	"net/http"
)

// Home routes browser sessions to their workspace without an intermediate page.
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	if len(r.Header.Values("Authorization")) != 0 {
		unauthorized(w)
		return
	}
	destination := "/account/login"
	if session, _, ok := h.session(r); ok {
		if err := h.identity.ValidateSubject(r.Context(), session.Subject); err == nil {
			admin, err := h.isAdminResult(r.Context(), session.Subject)
			if err != nil {
				http.Error(w, "Account unavailable", http.StatusServiceUnavailable)
				return
			}
			destination = "/account"
			if admin {
				destination = "/auth/v1/admin/dashboard"
				if h.adminForceMFA && session.AuthenticationMethod != "mfa" {
					destination = "/account/login"
				}
			}
		}
	}
	http.Redirect(w, r, h.issuer+destination, http.StatusSeeOther)
}
