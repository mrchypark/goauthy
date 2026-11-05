//go:build accountdataproof

package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The test-only overlay counts real identity queries without production hooks.
func TestDashboardIdentitySingleSnapshot(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	queries := 0
	r := httptest.NewRequest(http.MethodGet, "/account/data", nil)
	r.AddCookie(cookie)
	r = r.WithContext(context.WithValue(r.Context(), "account-data-proof-query-count", &queries))
	w := httptest.NewRecorder()
	h.Dashboard(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if queries != 1 {
		t.Fatalf("account-data identity queries=%d want=1", queries)
	}
	t.Logf("account-data identity queries=%d", queries)
}
