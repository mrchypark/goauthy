package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIStylesheetIsPublic(t *testing.T) {
	w := httptest.NewRecorder()
	UIStylesheet().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/v1/elysdui.css", nil))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") || !strings.Contains(w.Body.String(), "[data-slot=button]") {
		t.Fatalf("status=%d content type=%q", w.Code, w.Header().Get("Content-Type"))
	}
}
