package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/saas"
)

func TestWantsOAuth2CompletionPage(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(*http.Request){
		"single matching values": func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		},
		"omitted": func(r *http.Request) {},
		"duplicate": func(r *http.Request) {
			r.Header.Add("Sec-Fetch-Mode", "navigate")
			r.Header.Add("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		},
		"mixed": func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("Sec-Fetch-Dest", "document")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/callback?state=secret&code=secret", nil)
			setup(r)
			want := name == "single matching values"
			if got := wantsOAuth2CompletionPage(r); got != want {
				t.Fatalf("wants page=%v, want %v", got, want)
			}
		})
	}
}

func TestRenderOAuth2CompletionPageEscapesFixedAccountPath(t *testing.T) {
	t.Parallel()
	h := &Handler{issuer: `https://issuer.example/<script>alert("x")</script>`}
	w := httptest.NewRecorder()
	h.renderOAuth2CompletionPage(w)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `id="oauth2-complete"`) || !strings.Contains(body, `id="oauth2-account-link"`) {
		t.Fatalf("unexpected page: status=%d body=%s", w.Code, body)
	}
	if strings.Contains(body, "state=secret") || strings.Contains(body, "code=secret") || strings.Contains(body, "<script>") {
		t.Fatalf("page reflected secret or unescaped issuer: %s", body)
	}
	if !strings.Contains(body, "https://issuer.example/%3cscript%3ealert%28%22x%22%29%3c/script%3e/account") {
		t.Fatalf("escaped fixed account path missing: %s", body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("frame policy=%q", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" {
		t.Fatalf("csp=%q", got)
	}
}

func TestWriteOAuth2CompletionJSONCompatibility(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=secret&code=secret", nil)
	w := httptest.NewRecorder()
	want := saas.OAuth2ConnectionStatus{Connected: true, AccountID: "account", Scopes: []string{"openid"}}
	(&Handler{issuer: "https://issuer.example"}).writeOAuth2Completion(w, r, want)
	var got saas.OAuth2ConnectionStatus
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || got.Connected != want.Connected || got.AccountID != want.AccountID || len(got.Scopes) != 1 || got.Scopes[0] != "openid" {
		t.Fatalf("status=%d body=%s decoded=%+v", w.Code, w.Body.String(), got)
	}
}
