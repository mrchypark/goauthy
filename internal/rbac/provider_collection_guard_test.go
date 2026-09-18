package rbac

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/saas"
)

func TestManagedProviderCollectionReferenceAndAtomicGuard(t *testing.T) {
	h, store, cookie, csrf := membershipHTTPFixture(t)
	providers := providerHTTPStore(t, store)
	if err := h.BindSaaSProviderStore(providers); err != nil {
		t.Fatal(err)
	}
	if err := h.BindAuthCollections(authcollection.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	trusted := func() (string, []any) { return "1", nil }
	in, err := decodeProvider(providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, cookie, csrf, ""), true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := providers.Create(t.Context(), in, trusted)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"provider-policy","name":"Provider policy","auth_method":"oauth2","enabled":true,"fields":[],"provider_ids":["managed-oauth"]}`
	w := httptest.NewRecorder()
	h.AuthCollections(w, authCollectionRequest(http.MethodPost, "/auth/v1/auth-collections", body, cookie, csrf))
	if w.Code != http.StatusCreated {
		t.Fatalf("collection status=%d", w.Code)
	}
	if _, err := providers.Update(t.Context(), p.ID, p.Revision, in, trusted); !errors.Is(err, saas.ErrProviderConflict) {
		t.Fatalf("referenced update=%v", err)
	}
	if err := providers.Delete(t.Context(), p.ID, p.Revision, trusted); !errors.Is(err, saas.ErrProviderConflict) {
		t.Fatalf("referenced delete=%v", err)
	}
	if err := h.authCollections.DeleteDefinition(t.Context(), "provider-policy", 1, trusted); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/auth-collections", nil)
	authority, ok := h.collectionProviderAuthority(r, "oauth2", []string{p.ID}, trusted)
	if !ok {
		t.Fatal("provider guard unavailable")
	}
	if err := providers.Delete(t.Context(), p.ID, p.Revision, trusted); err != nil {
		t.Fatal(err)
	}
	_, err = h.authCollections.CreateDefinition(t.Context(), authcollection.DefinitionInput{ID: "late-policy", Name: "Late", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{p.ID}}, authority)
	if !errors.Is(err, authcollection.ErrConflict) {
		t.Fatalf("deleted provider accepted at commit: %v", err)
	}
}
