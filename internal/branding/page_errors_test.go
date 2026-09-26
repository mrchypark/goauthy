package branding

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestBrowserErrorNavigationPreservesWriteDeadline(t *testing.T) {
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, "/account/login", nil)
	r.Header.Set("Accept", "text/html")
	deadline := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	BrowserPageErrors("https://auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		http.Error(w, "Invalid user credentials", http.StatusUnauthorized)
	})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || !w.deadline.Equal(deadline) {
		t.Fatalf("status=%d deadline=%s", w.Code, w.deadline)
	}
}

func TestBrowserErrorNavigationPreservesAuthority(t *testing.T) {
	for _, tc := range []struct {
		path, accept, media string
		status              int
		wrapped             bool
	}{
		{"/account/login", "text/html", "text/plain", 401, true},
		{"/account/login", "application/json", "application/json", 401, false},
		{"/oidc/token", "text/html", "application/json", 400, false},
		{"/oidc/authorize", "text/html", "text/html", 403, false},
		{"/account/login", "text/html", "text/plain", 303, false},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Header.Set("Accept", tc.accept)
		r.Header.Set("Accept-Language", "ko")
		w := httptest.NewRecorder()
		BrowserPageErrors("https://auth.test/tenant", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.media)
			w.WriteHeader(tc.status)
			w.Write([]byte("original"))
		})).ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("status changed", w.Code)
		}
		if tc.wrapped {
			if !strings.Contains(w.Body.String(), `href="/tenant/"`) || strings.Contains(w.Body.String(), "original") {
				t.Fatal(w.Body.String())
			}
		} else if w.Body.String() != "original" {
			t.Fatal("protocol response changed")
		}
	}
}
