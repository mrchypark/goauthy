package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestPasswordLoginRateLimitRetry(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		finalStatus, attempts int
	}{
		{"retry-success", http.StatusFound, 2},
		{"retry-unauthorized", http.StatusUnauthorized, 2},
		{"retry-still-limited", http.StatusTooManyRequests, 2},
		{"initial-unauthorized", http.StatusUnauthorized, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initializations, posts := 0, 0
			var limitedAt time.Time
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					initializations++
					http.SetCookie(w, &http.Cookie{Name: "goauthy_session", Value: strconv.Itoa(initializations), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300, Expires: time.Now().Add(5 * time.Minute)})
					fmt.Fprintf(w, "<input name=\"interaction\" value=\"%d\">", initializations)
					return
				}
				posts++
				if err := r.ParseForm(); err != nil || r.Form.Get("interaction") != strconv.Itoa(initializations) {
					t.Error("login did not use the fresh interaction")
				}
				if posts == 1 && tc.attempts == 2 {
					limitedAt = time.Now()
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				if !limitedAt.IsZero() && time.Since(limitedAt) < time.Second {
					t.Error("login retried before Retry-After")
				}
				w.WriteHeader(tc.finalStatus)
			}))
			defer server.Close()
			response, cookie := passwordLoginResponse(t, newBrowserClient(t), server.URL, server.URL, server.URL, "user", "password")
			response.Body.Close()
			if response.StatusCode != tc.finalStatus || initializations != tc.attempts || posts != tc.attempts || cookie.Value != strconv.Itoa(tc.attempts) {
				t.Fatalf("status=%d authorizations=%d posts=%d cookie=%q", response.StatusCode, initializations, posts, cookie.Value)
			}
		})
	}
}
