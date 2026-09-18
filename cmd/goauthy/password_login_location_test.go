package main

import (
	"errors"
	"github.com/mrchypark/goauthy/internal/browser"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPasswordLoginLocationMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, ip, ua, id string
		valid            bool
	}{
		{"without cookie", "192.0.2.1", "Browser", "", true},
		{"with cookie", "192.0.2.1", "Browser", "known-browser", true},
		{"missing UA", "192.0.2.1", "", "", false},
		{"non ASCII UA", "192.0.2.1", "브라우저", "", false},
		{"invalid IP", "invalid", "Browser", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://issuer.test/oidc/token", nil)
			req = req.WithContext(browser.ContextWithPeerIP(req.Context(), tc.ip))
			req.Header.Set("User-Agent", tc.ua)
			if tc.id != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-rbid", Value: tc.id})
			}
			called := false
			observer := passwordLoginLocationObserver("https://issuer.test", nil, func(r *http.Request, subject, id, ip, ua string) error {
				called = true
				if r != req || subject != "alice" || id != tc.id || ip != tc.ip || ua != tc.ua {
					t.Fatal("incorrect login metadata")
				}
				return nil
			})
			response := httptest.NewRecorder()
			err := observer(response, req, "alice")
			if (err == nil) != tc.valid || called != tc.valid {
				t.Fatalf("error=%v called=%t", err, called)
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("password grant created browser identity")
			}
		})
	}
}

func TestLoginLocationLookupFailureIsSynchronous(t *testing.T) {
	failure := errors.New("location database unavailable")
	observer := loginLocationObserver(nil, nil, nil, nil, "https://issuer.test", "", func(ip netip.Addr) (*string, error) {
		if ip.String() != "192.0.2.1" {
			t.Fatal("wrong lookup IP")
		}
		return nil, failure
	})
	if err := observer(t.Context(), "alice", "", "192.0.2.1", "Browser"); !errors.Is(err, failure) {
		t.Fatalf("lookup error=%v", err)
	}
}
