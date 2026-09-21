package account

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

func TestDynamicExternalLinks(t *testing.T) {
	t.Parallel()
	h, _, identities, cookie, csrf := testPasswordHandler(t)
	ctx := context.Background()

	// Static provider.
	if err := h.ConfigureExternalLinks(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}),
		[]string{"google"},
	); err != nil {
		t.Fatal(err)
	}

	// Dynamic resolver and start handler.
	startCalls := 0
	dynamicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startCalls++
		w.WriteHeader(http.StatusAccepted)
	})
	resolverCalls := 0
	resolver := func(_ context.Context, id string) (bool, error) {
		resolverCalls++
		switch id {
		case "GitHubEnterprise", "DisabledProvider":
			return true, nil
		case "ResolverError":
			return false, errors.New("db error")
		default:
			return false, nil
		}
	}
	if err := h.ConfigureDynamicExternalLinks(dynamicHandler, resolver); err != nil {
		t.Fatal(err)
	}

	fixedNow := time.Date(2099, time.January, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return fixedNow }
	h.random = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i + 1)
		}
		return len(p), nil
	}

	request := func(method, provider string, sessionCookie *http.Cookie, token string) *http.Request {
		r := httptest.NewRequest(method, "/auth/v1/providers/"+provider+"/link", nil)
		if sessionCookie != nil {
			r.AddCookie(sessionCookie)
		}
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.SetPathValue("providerID", provider)
		return r
	}

	t.Run("nil config rejected", func(t *testing.T) {
		if err := h.ConfigureDynamicExternalLinks(nil, resolver); err == nil {
			t.Fatal("nil start accepted")
		}
		if err := h.ConfigureDynamicExternalLinks(dynamicHandler, nil); err == nil {
			t.Fatal("nil resolver accepted")
		}
	})

	t.Run("unauthorized rejects before lookup", func(t *testing.T) {
		resolverCalls = 0
		w := httptest.NewRecorder()
		h.StartExternalLink(w, request(http.MethodPost, "GitHubEnterprise", nil, ""))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", w.Code)
		}
		if resolverCalls != 0 {
			t.Fatalf("resolver called %d times", resolverCalls)
		}
	})

	t.Run("csrf rejects before lookup", func(t *testing.T) {
		resolverCalls = 0
		w := httptest.NewRecorder()
		h.StartExternalLink(w, request(http.MethodPost, "GitHubEnterprise", cookie, "wrong"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status=%d", w.Code)
		}
		if resolverCalls != 0 {
			t.Fatalf("resolver called %d times", resolverCalls)
		}
	})

	t.Run("mixed case forwarded exactly", func(t *testing.T) {
		resolverCalls = 0
		startCalls = 0
		w := httptest.NewRecorder()
		h.StartExternalLink(w, request(http.MethodPost, "GitHubEnterprise", cookie, csrf))
		if w.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
		if startCalls != 1 {
			t.Fatalf("start calls=%d", startCalls)
		}
	})

	t.Run("resolver error 503", func(t *testing.T) {
		resolverCalls = 0
		startCalls = 0
		w := httptest.NewRecorder()
		h.StartExternalLink(w, request(http.MethodPost, "ResolverError", cookie, csrf))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
		if startCalls != 0 {
			t.Fatalf("start calls=%d want=0", startCalls)
		}
	})

	t.Run("resolver missing 404", func(t *testing.T) {
		resolverCalls = 0
		startCalls = 0
		w := httptest.NewRecorder()
		h.StartExternalLink(w, request(http.MethodPost, "UnknownProvider", cookie, csrf))
		if w.Code != http.StatusNotFound {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
		if startCalls != 0 {
			t.Fatalf("start calls=%d want=0", startCalls)
		}
	})

	t.Run("unlink resolver error 503", func(t *testing.T) {
		resolverCalls = 0
		w := httptest.NewRecorder()
		h.UnlinkExternal(w, request(http.MethodDelete, "ResolverError", cookie, csrf))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
	})

	t.Run("unlink resolver missing 404", func(t *testing.T) {
		resolverCalls = 0
		w := httptest.NewRecorder()
		h.UnlinkExternal(w, request(http.MethodDelete, "UnknownProvider", cookie, csrf))
		if w.Code != http.StatusNotFound {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
	})

	t.Run("unlink disabled existing by resolver", func(t *testing.T) {
		// Link DisabledProvider first so unlink has work to do.
		if _, err := identities.LinkExternal(ctx, "subject-1", upstreamprovider.SubjectResult{ProviderID: "DisabledProvider", Subject: "ext-disabled"}, fixedNow); err != nil {
			t.Fatal(err)
		}
		resolverCalls = 0
		w := httptest.NewRecorder()
		h.UnlinkExternal(w, request(http.MethodDelete, "DisabledProvider", cookie, csrf))
		if w.Code != http.StatusNoContent {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		if resolverCalls != 1 {
			t.Fatalf("resolver calls=%d", resolverCalls)
		}
		if _, found, err := identities.FindExternalLink(ctx, upstreamprovider.SubjectResult{ProviderID: "DisabledProvider", Subject: "ext-disabled"}); err != nil || found {
			t.Fatalf("link still found=%t err=%v", found, err)
		}
	})
}
