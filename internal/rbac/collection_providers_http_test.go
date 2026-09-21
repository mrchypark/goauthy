package rbac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/authcollection"
)

func TestCollectionProvidersHTTPRequiresConfiguredProvider(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "github", Kind: "github", CallbackURI: "https://auth.example/callback", Scopes: []string{"read:user"}}}); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"provider-test","name":"Provider test","auth_method":"oauth2","enabled":true,"fields":[],"provider_ids":["github"]}`
	w := httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", strings.ReplaceAll(body, "github", "unknown"), cookie, csrf))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", body, cookie, csrf))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"provider_ids":["github"]`) {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r := authCollectionRequestWithPath(http.MethodPut, "/auth/v1/auth-collections/provider-test", `{"name":"Provider test","auth_method":"oauth2","enabled":true,"fields":[],"provider_ids":[]}`, cookie, csrf, map[string]string{"collection_id": "provider-test"})
	r.Header.Set("If-Match", `"1"`)
	h.AuthCollection(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"provider_ids":[]`) {
		t.Fatalf("clear=%d body=%s", w.Code, w.Body.String())
	}
}
