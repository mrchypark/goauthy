package login

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/i18n"
	"golang.org/x/net/html"
)

func TestElyAuthenticationControlsPreserveContracts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		page     *template.Template
		data     any
		controls map[string]map[string]string
	}{
		{"login", loginPage, loginPageData{IssuerPath: "/tenant", Action: "/tenant/auth/login", Interaction: "interaction", CSRFToken: "csrf", PasskeyLogin: true, PasskeyNonce: "nonce", BrandButton: `Continue <script>`, Messages: i18n.Messages{}}, map[string]map[string]string{
			"username":    {"autocomplete": "username", "required": "", "data-slot": "input"},
			"password":    {"type": "password", "autocomplete": "current-password", "required": "", "data-slot": "input"},
			"interaction": {"type": "hidden", "value": "interaction"}, "csrf_token": {"type": "hidden", "value": "csrf"},
			"passkey-btn": {"type": "button", "data-i18n": "Sign in with a passkey", "data-slot": "button"},
		}},
		{"otp", otpStepUpPage, loginPageData{IssuerPath: "/tenant"}, map[string]map[string]string{"code": {"pattern": "[0-9]{6}", "inputmode": "numeric", "autocomplete": "one-time-code", "maxlength": "6", "required": "", "autofocus": "", "data-slot": "input"}}},
		{"fedcm", fedCMLandingPage, fedCMLandingPageData{Interaction: "interaction", CSRFToken: "csrf"}, map[string]map[string]string{"fedcm": {"type": "hidden", "value": "1"}, "csrf_token": {"value": "csrf"}, "password": {"autocomplete": "current-password", "data-slot": "input"}}},
		{"profile", profilePage, profilePageData{IssuerPath: "/tenant", Interaction: "interaction", CSRFToken: "csrf", Fields: []profileField{{Name: "email", Value: `a"<b`, Required: true, Readonly: true}, {Name: "hidden", Value: "hidden-value", Hidden: true}}}, map[string]map[string]string{"email": {"value": `a"<b`, "required": "", "readonly": "", "data-slot": "input"}, "hidden": {"type": "hidden", "value": "hidden-value"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tc.page.Execute(&out, tc.data); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			for _, forbidden := range []string{"hx-post=", "hx-boost=", "htmx.js", "unsafe-inline", "<script>"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("unexpected %s", forbidden)
				}
			}
			if !strings.Contains(body, "/auth/v1/ui/") {
				t.Fatal("missing Ely assets")
			}
			seen := map[string]bool{}
			tokenizer := html.NewTokenizer(strings.NewReader(body))
			for {
				kind := tokenizer.Next()
				if kind == html.ErrorToken {
					break
				}
				if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
					continue
				}
				token := tokenizer.Token()
				attrs := map[string]string{}
				for _, a := range token.Attr {
					attrs[a.Key] = a.Val
				}
				key := attrs["name"]
				if attrs["id"] != "" {
					key = attrs["id"]
				}
				want, ok := tc.controls[key]
				if !ok {
					continue
				}
				seen[key] = true
				for name, value := range want {
					got, exists := attrs[name]
					if !exists || got != value {
						t.Errorf("%s %s=%q exists=%t want=%q", key, name, got, exists, value)
					}
				}
			}
			for key := range tc.controls {
				if !seen[key] {
					t.Errorf("missing %s", key)
				}
			}
			if tc.name == "login" && (!strings.Contains(body, `nonce="nonce"`) || !strings.Contains(body, `action="/tenant/auth/login"`) || !strings.Contains(body, "Continue &lt;script&gt;")) {
				t.Fatal("nonce, action or brand escaping changed")
			}
		})
	}
}

func TestElyFedCMPagesUseIssuerPrefix(t *testing.T) {
	h := testHandler(t)
	h.issuer = "https://issuer.example.test/tenant"
	if err := h.EnableFedCM(true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		render func(http.ResponseWriter, *http.Request)
	}{{"landing", h.FedCMLanding}, {"success", h.writeFedCMSuccess}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			r.RemoteAddr = "198.51.100.10:1234"
			w := httptest.NewRecorder()
			tc.render(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			for _, asset := range []string{"ui/app.css", "ui/ely-controls.css", "ui/ely-patterns.css", "ui/brand.css", "theme/global.css"} {
				if !strings.Contains(body, `href="/tenant/auth/v1/`+asset+`"`) {
					t.Errorf("missing tenant asset %s", asset)
				}
			}
			if strings.Contains(body, `href="/auth/v1/`) || strings.Contains(body, "<script") || strings.Contains(body, "hx-") {
				t.Fatal("root asset or changed script/form behavior")
			}
			if tc.name == "landing" {
				for _, want := range []string{`method="post" action=""`, `name="fedcm" value="1"`, `name="interaction"`, `name="csrf_token"`} {
					if !strings.Contains(body, want) {
						t.Errorf("missing protocol field %s", want)
					}
				}
			}
		})
	}
}
