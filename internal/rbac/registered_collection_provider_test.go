package rbac

import (
	"net/http"
	"testing"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/rhiza"
)

func TestRegisteredAPIKeyCollectionProviderAuthority(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	providers := providerHTTPStore(t, store)
	if err := h.BindSaaSProviderStore(providers); err != nil {
		t.Fatal(err)
	}
	trusted := func() (string, []any) { return "1", nil }
	api, err := decodeProvider(providerRequest(http.MethodPost, "/auth/v1/saas/providers", apiKeyProviderBody, nil, "", ""), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = providers.Create(t.Context(), api, trusted); err != nil {
		t.Fatal(err)
	}
	api2 := apiKeyProviderInput(true)
	api2.ID, api2.Name, api2.Connector.ID = "other", "Other API", "other"
	if _, err = providers.Create(t.Context(), api2, trusted); err != nil {
		t.Fatal(err)
	}
	r := providerRequest(http.MethodPost, "/auth/v1/auth-collections", "", nil, "", "")
	for name, tc := range map[string]struct {
		method string
		ids    []string
		ok     bool
	}{
		"registered api key": {"api_key", []string{"managed-api"}, true},
		"missing":            {"api_key", []string{"missing"}, false},
		"wrong kind":         {"oauth2", []string{"managed-api"}, false},
		"multiple":           {"api_key", []string{"managed-api", "other"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := h.collectionProviderAuthority(r, tc.method, tc.ids, trusted); ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
		})
	}
	guard, ok := h.collectionProviderAuthority(r, "api_key", []string{api.ID}, trusted)
	if !ok {
		t.Fatal("enabled provider authority unavailable")
	}
	if _, err := providers.Update(t.Context(), api.ID, 1, apiKeyProviderInput(false), trusted); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.collectionProviderAuthority(r, "api_key", []string{api.ID}, trusted); ok {
		t.Fatal("disabled provider accepted")
	}
	g, args := guard()
	rows, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 WHERE ` + g + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("disabled commit guard rows=%v err=%v", rows.Rows, err)
	}
}

func apiKeyProviderInput(enabled bool) (in saas.ProviderInput) {
	return saas.ProviderInput{ID: "managed-api", Name: "Managed API", Kind: "api_key", Enabled: enabled, Connector: &saas.APIKeyConnectorConfig{ID: "managed-api", Header: "X-API-Key", Operations: []saas.APIKeyOperationConfig{{ID: "whoami", URL: "https://provider.example/me", ResponseFields: map[string]string{"id": "string"}}}}}
}
