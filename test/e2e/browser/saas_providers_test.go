package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/chromedp/chromedp"
	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestSaaSProvidersCatalog(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SAAS_PROVIDERS") != "1" {
		t.Skip("SaaS catalog E2E disabled")
	}
	want := os.Getenv("GOAUTHY_E2E_SAAS_PROVIDER_ID")
	if want == "" {
		t.Fatal("GOAUTHY_E2E_SAAS_PROVIDER_ID required")
	}
	primary, secondary, user, password, _ := browserE2EConfig(t)
	client := newBrowserClient(t)
	_, cookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), user, password, "saas-catalog-admin")
	response := do(t, client, http.MethodGet, primary+"/auth/v1/saas/providers", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("catalog status=%d", response.StatusCode)
	}
	var providers []map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&providers); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, provider := range providers {
		for key := range provider {
			switch key {
			case "id", "kind", "callback_uri", "scopes":
			default:
				t.Fatalf("unexpected catalog field=%s", key)
			}
		}
		var id string
		if err := json.Unmarshal(provider["id"], &id); err != nil {
			t.Fatal(err)
		}
		found = found || id == want
	}
	if !found {
		t.Fatalf("configured provider %q missing", want)
	}
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	id := uniqueCollectionID(t)
	definition := map[string]any{"id": id, "name": "SaaS policy", "auth_method": "oauth2", "enabled": true, "fields": []any{}, "provider_ids": []string{want}}
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	created := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", bytes.NewReader(body), headers)
	_, revision := readCollection(t, created, http.StatusCreated)
	t.Cleanup(func() {
		r := do(t, client, http.MethodDelete, primary+"/auth/v1/auth-collections/"+id, nil, cloneCollectionHeaders(headers, revision))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("policy cleanup status=%d", r.StatusCode)
		}
	})
	read := do(t, client, http.MethodGet, primary+"/auth/v1/auth-collections/"+id, nil, headers)
	stored, _ := readCollection(t, read, http.StatusOK)
	ids, ok := stored["provider_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != want {
		t.Fatalf("stored provider policy=%v", stored["provider_ids"])
	}
	ui, closeUI := newCollectionUIContext(t, cookie, primary)
	defer closeUI()
	var displayed string
	if err := chromedp.Run(ui, chromedp.Navigate(primary+"/auth/v1/admin/collections/"+id+"/edit"), chromedp.WaitVisible("#collection-providers"), chromedp.Value("#collection-providers", &displayed)); err != nil {
		t.Fatal(err)
	}
	if displayed != want {
		t.Fatalf("provider editor value=%q", displayed)
	}
	if err := chromedp.Run(ui, chromedp.Click("#collection-save"), collectionUIListReady()); err != nil {
		t.Fatal(err)
	}
	read = do(t, client, http.MethodGet, primary+"/auth/v1/auth-collections/"+id, nil, headers)
	stored, revision = readCollection(t, read, http.StatusOK)
	ids, ok = stored["provider_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != want {
		t.Fatalf("UI save lost provider policy=%v", stored["provider_ids"])
	}
	delete(definition, "id")
	definition["provider_ids"] = []string{}
	body, err = json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	updated := do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+id, bytes.NewReader(body), cloneCollectionHeaders(headers, revision))
	stored, revision = readCollection(t, updated, http.StatusOK)
	ids, ok = stored["provider_ids"].([]any)
	if !ok || len(ids) != 0 {
		t.Fatalf("cleared provider policy=%v", stored["provider_ids"])
	}
	anonymous := newBrowserClient(t)
	denied := do(t, anonymous, http.MethodGet, primary+"/auth/v1/saas/providers", nil, nil)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", denied.StatusCode)
	}
}
