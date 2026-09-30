package device

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeviceReviewedRequestBinding(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, testSubject("user-1", false))
	first, err := store.Create(ctx, "reviewed-app", []string{"openid", "groups"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, "other-app", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := verificationCSRF(t, h, first.UserCode)
	for _, code := range []string{second.UserCode, first.UserCode} {
		r := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {strings.ToLower(code)}, "csrf_token": {csrf}, "action": {"approve"}})
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := http.StatusForbidden
		if code == first.UserCode {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("decision status=%d want=%d", w.Code, want)
		}
		if want == http.StatusOK && !strings.Contains(w.Header().Get("Content-Security-Policy"), "font-src 'self'") {
			t.Fatal("completion page blocks bundled fonts")
		}
	}
	state, found, err := store.load(ctx, digest(second.DeviceCode), "other-app")
	if err != nil || !found || state.state != "pending" {
		t.Fatal("unreviewed grant changed")
	}
}

func TestDeviceReviewPageStates(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, testSubject("user-1", false))
	grant, err := store.Create(ctx, "app<script>", []string{"openid", "groups"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code string
		status     int
		review     bool
	}{
		{"manual", "", 200, false},
		{"unknown", "ABCD-2345-XY", 400, false},
		{"pending", grant.UserCode, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, verificationPath+"?user_code="+url.QueryEscape(tc.code), nil))
			body := w.Body.String()
			if !strings.Contains(w.Header().Get("Content-Security-Policy"), "font-src 'self'") {
				t.Fatal("review page blocks bundled fonts")
			}
			if w.Code != tc.status {
				t.Fatalf("status=%d", w.Code)
			}
			if strings.Contains(body, `value="approve"`) != tc.review {
				t.Fatal("unexpected approval control")
			}
			if strings.Contains(body, grant.DeviceCode) || strings.Contains(body, "<script>") {
				t.Fatal("unsafe review content")
			}
			if tc.review {
				for _, want := range []string{"app&lt;script&gt;", "<li>openid</li>", "<li>groups</li>", "readonly"} {
					if !strings.Contains(body, want) {
						t.Fatalf("missing %q", want)
					}
				}
			} else if !strings.Contains(body, `method="get"`) || len(w.Result().Cookies()) != 0 {
				t.Fatal("lookup page issued an approval form/cookie")
			}
		})
	}
	h.now = func() time.Time { return grant.ExpiresAt }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, verificationPath+"?user_code="+url.QueryEscape(grant.UserCode), nil))
	if w.Code != 400 || strings.Contains(w.Body.String(), "app&lt;script&gt;") {
		t.Fatal("expired request disclosed")
	}
}

func TestDeviceReviewPageUsesSelectedLocaleAndSafeExits(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, testSubject("user-1", false))
	grant, err := store.Create(ctx, "client-1", []string{"openid"}, deviceHTTPTestNow)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, verificationPath+"?user_code="+url.QueryEscape(grant.UserCode), nil)
	r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Language") != "ko" || !strings.Contains(w.Body.String(), "기기 승인") || !strings.Contains(w.Body.String(), `href="https://id.example.test/account"`) {
		t.Fatalf("status=%d language=%q body=%s", w.Code, w.Header().Get("Content-Language"), w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, verificationPath+"?user_code=INVALID", nil)
	r.AddCookie(&http.Cookie{Name: "goauthy_ui_locale", Value: "ko"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "사용할 수 없는 코드입니다") || !strings.Contains(w.Body.String(), `href="https://id.example.test/auth/v1/theme/global.css"`) || !strings.Contains(w.Body.String(), `class="auth-panel"`) || !strings.Contains(w.Body.String(), `class="auth-error" role="alert"`) {
		t.Fatalf("localized invalid code: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDeviceReviewLookupRateLimit(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h, err := NewHandlerWithLimits(store, "https://id.example.test", func(*http.Request, string, []string) error { return nil }, testSubject("user-1", false), Limits{VerificationLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return deviceHTTPTestNow }
	for _, want := range []int{400, 429} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, verificationPath+"?user_code=ABCD-2345-XY", nil))
		if w.Code != want {
			t.Fatalf("status=%d want=%d", w.Code, want)
		}
		if strings.Contains(w.Body.String(), `value="approve"`) {
			t.Fatal("unavailable lookup exposed approval")
		}
	}
}
