package rbac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/saas"
)

const pageTicket = "AQIDBAUGBwgJCgsMDQ4PEBES"

func TestConnectionHandoffPageDistinguishesKeyDelivery(t *testing.T) {
	for _, mode := range []string{"proxy", "credential_delivery"} {
		t.Run(mode, func(t *testing.T) {
			data := connectionHandoffPageData{Review: saas.UseHandoffReview{Grant: saas.UseGrant{Mode: mode}}}
			var out bytes.Buffer
			if err := connectionHandoffPage.Execute(&out, data); err != nil {
				t.Fatal(err)
			}
			page := out.String()
			delivery := mode == "credential_delivery"
			for _, warning := range []string{"The service will receive your original API key", "cannot recall a key already delivered", "not delivery restrictions", "Allow API key delivery", "Key retrieval allowed until"} {
				if strings.Contains(page, warning) != delivery {
					t.Errorf("mode=%s warning=%q mismatch", mode, warning)
				}
			}
			if strings.Contains(page, "not your API key") == delivery || strings.Contains(page, " checked") || !strings.Contains(page, `name="reviewed" value="yes" required`) {
				t.Fatal("consent promise or explicit confirmation mismatch")
			}
		})
	}
}

func TestConnectionHandoffPageNoReferrerForm(t *testing.T) {
	h, cookie, csrf := handoffHTTPFixture(t)
	for _, site := range []string{"same-origin", "same-site", "cross-site", "none", ""} {
		t.Run(site, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/account/connection-handoffs/"+pageTicket, strings.NewReader("decision=deny&csrf_token="+csrf))
			r.SetPathValue("handoff_id", pageTicket)
			r.Header.Set("Origin", "null")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if site != "" {
				r.Header.Set("Sec-Fetch-Site", site)
			}
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ConnectionHandoffPage(w, r)
			want := http.StatusUnauthorized
			if site == "same-origin" {
				want = http.StatusConflict
			} // authenticated; ticket does not exist
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
		})
	}
}

func TestConnectionHandoffPageOAuthReview(t *testing.T) {
	data := connectionHandoffPageData{Review: saas.UseHandoffReview{
		Grant:        saas.UseGrant{Mode: "credential_delivery"},
		ReviewDigest: "oauth-review-digest",
		OAuth2:       &saas.OAuth2Status{ProviderID: "github", AccountID: "acct-1", Scopes: []string{"repo", "user:email"}, Version: 7},
	}}
	var out bytes.Buffer
	if err := connectionHandoffPage.Execute(&out, data); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, want := range []string{"github", "acct-1", "repo, user:email", "7", "No refresh token or client secret is delivered", "cannot recall a token already delivered", `name="review_digest" value="oauth-review-digest"`, "Allow OAuth token delivery"} {
		if !strings.Contains(page, want) {
			t.Errorf("OAuth review missing %q", want)
		}
	}
	for _, unwanted := range []string{"Registered provider settings", "Allowed operations", "original API key", `name="connector_digest"`} {
		if strings.Contains(page, unwanted) {
			t.Errorf("OAuth review contains API-key content %q", unwanted)
		}
	}
}

func TestConnectionHandoffPageRefreshWarningOptIn(t *testing.T) {
	for _, allow := range []bool{false, true} {
		data := connectionHandoffPageData{Review: saas.UseHandoffReview{
			Grant:  saas.UseGrant{Mode: "credential_delivery", AllowRefresh: allow},
			OAuth2: &saas.OAuth2Status{ProviderID: "provider", AccountID: "account", Version: 1, Scopes: []string{"scope"}},
		}}
		var out bytes.Buffer
		if err := connectionHandoffPage.Execute(&out, data); err != nil {
			t.Fatal(err)
		}
		got := strings.Contains(out.String(), "Refresh delegation is enabled")
		if got != allow {
			t.Fatalf("allow_refresh=%v warning=%v", allow, got)
		}
	}
}

func TestConnectionHandoffPageNavigationBoundary(t *testing.T) {
	h, cookie, csrf := handoffHTTPFixture(t)
	path := "/auth/v1/connection-handoffs/" + pageTicket
	for name, alter := range map[string]func(*http.Request){
		"cross site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"bearer":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") },
		"post cross site": func(r *http.Request) {
			r.Method = http.MethodPost
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://evil.example")
			r.Body = httptest.NewRequest(http.MethodPost, path, strings.NewReader("decision=deny&csrf_token="+csrf)).Body
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.SetPathValue("handoff_id", pageTicket)
			alter(r)
			w := httptest.NewRecorder()
			h.ConnectionHandoffPage(w, r)
			if name == "cross site" {
				if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/account/connection-login?handoff_id="+pageTicket) {
					t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
				}
			} else if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	for _, raw := range []string{"bad", pageTicket + "=", pageTicket + "?x=1", pageTicket + "?x=1&x=2", pageTicket + "&x=1"} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/connection-handoffs/"+raw, nil)
		r.SetPathValue("handoff_id", raw)
		w := httptest.NewRecorder()
		h.ConnectionHandoffPage(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("raw=%q status=%d", raw, w.Code)
		}
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, path, nil)
		r.SetPathValue("handoff_id", pageTicket)
		w := httptest.NewRecorder()
		h.ConnectionHandoffPage(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("decision=deny&csrf_token="+csrf))
	r.SetPathValue("handoff_id", pageTicket)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ConnectionHandoffPage(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("missing ticket POST status=%d", w.Code)
	}
}

func TestConnectionHandoffPageRejectsUnauthenticatedAndCSRF(t *testing.T) {
	h, cookie, _ := handoffHTTPFixture(t)
	path := "/auth/v1/connection-handoffs/" + pageTicket
	for name, r := range map[string]*http.Request{
		"no cookie": httptest.NewRequest(http.MethodPost, path, strings.NewReader("decision=deny&csrf_token=x")),
		"missing csrf": func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("decision=deny&csrf_token=x"))
			r.AddCookie(cookie)
			return r
		}(),
	} {
		r.SetPathValue("handoff_id", pageTicket)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ConnectionHandoffPage(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d", name, w.Code)
		}
	}
}

func TestConnectionHandoffPageEscapesReviewMetadata(t *testing.T) {
	data := connectionHandoffPageData{Review: saas.UseHandoffReview{RequestClientID: "<script>alert(1)</script>", ReturnURI: "https://client.example/?x=\"bad\""}}
	var out bytes.Buffer
	if err := connectionHandoffPage.Execute(&out, data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<script>") || strings.Contains(out.String(), "href=\"https://client.example/?x=\"bad\"") {
		t.Fatalf("unescaped metadata: %s", out.String())
	}
	if !strings.Contains(out.String(), "&lt;script&gt;") {
		t.Fatal("metadata was not HTML escaped")
	}
	if !strings.Contains(out.String(), `id="handoff-approve"`) || !strings.Contains(out.String(), `id="handoff-deny"`) || !strings.Contains(out.String(), "required") {
		t.Fatal("approval/deny controls missing")
	}
}
