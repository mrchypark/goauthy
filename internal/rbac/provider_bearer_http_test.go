package rbac

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestProviderBearerBoundaryScopesAndAuthShape(t *testing.T) {
	t.Parallel()
	h, store, adminCookie, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	seen := make([]string, 0, 2)
	// This stand-in checks boundary composition only; token verification is covered by live OAuth tests.
	if err := h.BindProviderResourceAuthorizer(func(_ *http.Request, scope string) (string, func() (string, []any), error) {
		seen = append(seen, scope)
		return "admin", func() (string, []any) { return "1=1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}

	r := providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", nil, "", "")
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.SaaSProviders(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("read status=%d body=%s", w.Code, w.Body.String())
	}

	r = providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, nil, "", "")
	r.Header.Set("Authorization", "Bearer test-token")
	w = httptest.NewRecorder()
	h.SaaSProviders(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("write status=%d body=%s", w.Code, w.Body.String())
	}
	if len(seen) != 2 || seen[0] != "goauthy.providers.read" || seen[1] != "goauthy.providers.write" {
		t.Fatalf("scopes=%v", seen)
	}

	for name, setup := range map[string]func(*http.Request){
		"cookie plus bearer": func(r *http.Request) {
			r.AddCookie(adminCookie)
		},
		"duplicate bearer": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer second")
		},
		"api key": func(r *http.Request) {
			r.Header.Set("Authorization", "API-Key invalid")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", nil, "", "")
			r.Header.Set("Authorization", "Bearer test-token")
			setup(r)
			w := httptest.NewRecorder()
			h.SaaSProviders(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	h2, store2, _, _ := membershipHTTPFixture(t)
	if err := h2.BindSaaSProviderStore(providerHTTPStore(t, store2)); err != nil {
		t.Fatal(err)
	}
	r = providerRequest(http.MethodGet, "/auth/v1/saas/providers", "", nil, "", "")
	r.Header.Set("Authorization", "Bearer test-token")
	w = httptest.NewRecorder()
	h2.SaaSProviders(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unset authorizer status=%d", w.Code)
	}
}

func TestProviderBearerGuardRechecksAdminAtMutation(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSProviderStore(providerHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	adminRole := roleByName(t, store.db, AdminRole)
	if err := h.BindProviderResourceAuthorizer(func(_ *http.Request, scope string) (string, func() (string, []any), error) {
		if scope != "goauthy.providers.write" {
			t.Fatalf("scope=%q", scope)
		}
		return "admin", func() (string, []any) {
			if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "provider-bearer-revoke-admin", SQL: `DELETE FROM rbac_user_roles WHERE subject=? AND role_id=?`, Args: []any{"admin", adminRole}}); err != nil {
				t.Fatalf("revoke admin: %v", err)
			}
			return "1=1", nil
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	r := providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, nil, "", "")
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.SaaSProviders(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("revoked mutation status=%d body=%s", w.Code, w.Body.String())
	}
	q, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM saas_providers WHERE id=?`, Args: []any{"managed-oauth"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(0) {
		t.Fatalf("provider mutation rows=%v err=%v", q.Rows, err)
	}
}
