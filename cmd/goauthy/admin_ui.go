package main

import (
	"encoding/json"
	"net/http"

	"github.com/mrchypark/goauthy/internal/admin"
	"github.com/mrchypark/goauthy/internal/browser"
)

// Invoked only after admin.UI has validated the live browser administrator.
// Return the derived CSRF token, never the HttpOnly session credential.
func adminCSRFTokenProvider(issuer string) admin.CSRFTokenProvider {
	name, nameErr := browser.CookieName(issuer)
	return func(w http.ResponseWriter, r *http.Request) bool {
		if nameErr != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return false
		}
		cookie, err := r.Cookie(name)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		token, err := browser.DeriveCSRFToken(cookie.Value)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(map[string]string{"token": token}) == nil
	}
}
