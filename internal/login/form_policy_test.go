package login

import (
	"strings"
	"testing"
)

func TestAuthorizationFormCSP(t *testing.T) {
	for _, tc := range []struct{ redirect, action string }{
		{"https://rp.example.test/callback?tenant=one", "'self' https://rp.example.test"},
		{"https://rp.example.test:8443/callback", "'self' https://rp.example.test:8443"},
		{"https://bücher.example:8443/callback", "'self' https://xn--bcher-kva.example:8443"},
		{"http://localhost:5555/callback", "'self' http://localhost:5555"},
		{"http://[::1]:5555/callback", "'self' http://[::1]:5555"},
		{"", "'self'"},
		{"/callback", "'self'"},
		{"native-app:/callback", "'self'"},
		{"https://user@rp.example.test/callback", "'self'"},
		{"https://*.example.test/callback", "'self'"},
		{"https://invalid host/callback", "'self'"},
	} {
		want := "default-src 'none'; style-src 'self'; form-action " + tc.action + "; frame-ancestors 'none'"
		if got := authorizationFormCSP(tc.redirect); got != want || strings.Contains(got, "tenant=") {
			t.Fatalf("policy=%q want=%q", got, want)
		}
	}
}
