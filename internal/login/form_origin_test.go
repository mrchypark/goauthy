package login

import (
	"net/http/httptest"
	"testing"
)

func TestSameIssuerOriginNoReferrerForm(t *testing.T) {
	for _, site := range []string{"same-origin", "same-site", "cross-site", "none", ""} {
		t.Run(site, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://id.example/account/connection-login", nil)
			r.Header.Set("Origin", "null")
			if site != "" {
				r.Header.Set("Sec-Fetch-Site", site)
			}
			if got := sameIssuerOrigin(r, "https://id.example"); got != (site == "same-origin") {
				t.Fatalf("origin accepted=%v", got)
			}
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			if site != "" && sameIssuerOrigin(r, "https://id.example") {
				t.Fatal("duplicate fetch metadata accepted")
			}
		})
	}
}
