package device

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDeviceVerificationNativeFormOrigin(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		t.Run(action+" accepts native same-origin form", func(t *testing.T) {
			ctx, store, _ := testStore(t)
			grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool) { return "user-1", true })
			cookie, csrf := verificationCSRF(t, h, grant.UserCode)
			r := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {action}})
			r.Header.Set("Origin", "null")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d", w.Code)
			}
			poll, err := store.Poll(ctx, grant.DeviceCode, "client-1", deviceHTTPTestNow)
			if err != nil || (action == "approve" && (poll.Status != StatusClaimed || poll.Subject != "user-1")) || (action == "deny" && poll.Status != StatusDenied) {
				t.Fatalf("poll=%+v err=%v", poll, err)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		setup func(*http.Request)
		want  int
	}{
		{"null origin without fetch metadata", func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		{"null origin same-site", func(r *http.Request) { r.Header.Set("Origin", "null"); r.Header.Set("Sec-Fetch-Site", "same-site") }, http.StatusForbidden},
		{"null origin cross-site", func(r *http.Request) { r.Header.Set("Origin", "null"); r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"duplicate fetch metadata", func(r *http.Request) {
			r.Header.Set("Origin", "null")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
		}, http.StatusForbidden},
		{"duplicate origin", func(r *http.Request) {
			r.Header.Set("Origin", "null")
			r.Header.Add("Origin", "null")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}, http.StatusForbidden},
		{"missing csrf", func(r *http.Request) {
			r.Header.Set("Origin", "null")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}, http.StatusBadRequest},
		{"invalid csrf", func(r *http.Request) {
			r.Header.Set("Origin", "null")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, store, _ := testStore(t)
			grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool) { return "user-1", true })
			cookie, csrf := verificationCSRF(t, h, grant.UserCode)
			form := url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}}
			if tc.name == "missing csrf" {
				form.Del("csrf_token")
			} else if tc.name == "invalid csrf" {
				first := "A"
				if csrf[0] == 'A' {
					first = "B"
				}
				form.Set("csrf_token", first+csrf[1:])
			}
			r := formRequest(http.MethodPost, verificationPath, form)
			tc.setup(r)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			row, ok, err := store.load(ctx, digest(grant.DeviceCode), "client-1")
			if err != nil || !ok || row.state != "pending" {
				t.Fatalf("grant mutated after rejected form: ok=%t state=%q err=%v", ok, row.state, err)
			}
		})
	}
}
