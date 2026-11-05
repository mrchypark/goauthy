package rbac

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/authcollection"
)

func TestCollectionProviderBatchAuthorityReads(t *testing.T) {
	h, store, _, _ := membershipHTTPFixture(t)
	providers := providerHTTPStore(t, store)
	if err := h.BindSaaSProviderStore(providers); err != nil {
		t.Fatal(err)
	}
	trusted := func() (string, []any) { return "1", nil }
	in, err := decodeProvider(providerRequest(http.MethodPost, "/auth/v1/saas/providers", oauthProviderBody, nil, "", ""), true)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 32)
	for i := range ids {
		ids[i] = fmt.Sprintf("batch-%02d", i)
		in.ID = ids[i]
		if _, err := providers.Create(t.Context(), in, trusted); err != nil {
			t.Fatal(err)
		}
	}
	reads := 0
	authority := func() (string, []any) { reads++; return "1", nil }
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/auth-collections", nil)
	guard, ok := h.collectionProviderAuthority(r, "oauth2", ids, authority)
	if !ok || guard == nil {
		t.Fatal("valid provider set rejected")
	}
	t.Logf("providers=32 preflight_authority_evaluations=%d", reads)
	if reads != 1 {
		t.Fatalf("preflight authority evaluations=%d; want one batched lookup", reads)
	}
	if err := h.BindSaaSProviders([]SaaSProviderInfo{{ID: "github", Kind: "github", CallbackURI: "https://auth.example/callback", Scopes: []string{"read:user"}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		ids       []string
		wantReads int
	}{
		{"static only", []string{"github"}, 0},
		{"mixed", append(append([]string(nil), ids[:31]...), "github"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads = 0
			if _, ok := h.collectionProviderAuthority(r, "oauth2", tc.ids, authority); !ok || reads != tc.wantReads {
				t.Fatalf("ok=%v authority evaluations=%d want=%d", ok, reads, tc.wantReads)
			}
		})
	}
	// Revoke the last provider after the preflight. The original per-provider
	// mutation predicates must still reject the whole collection atomically.
	in.Enabled = false
	if _, err := providers.Update(t.Context(), in.ID, 1, in, trusted); err != nil {
		t.Fatal(err)
	}
	collections := authcollection.NewStore(store.db)
	_, err = collections.CreateDefinition(t.Context(), authcollection.DefinitionInput{ID: "batch-policy", Name: "Batch", AuthMethod: "oauth2", Enabled: true, ProviderIDs: ids}, guard)
	if !errors.Is(err, authcollection.ErrConflict) {
		t.Fatalf("interposed disable accepted: %v", err)
	}
	if _, err := collections.GetDefinition(t.Context(), "batch-policy", trusted); !errors.Is(err, authcollection.ErrNotFound) {
		t.Fatalf("rejected collection persisted: %v", err)
	}
}
