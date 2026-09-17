package branding

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestThemePutAuthorizedAllowsBootstrapClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "bootstrap-theme"
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "theme-kind-bootstrap",
		SQL:       `INSERT INTO managed_oauth_client_bootstrap(singleton,id) VALUES(1,?)`,
		Args:      []any{clientID},
	}); err != nil {
		t.Fatal(err)
	}

	theme := DefaultTheme(clientID)
	theme.BorderRadius = "11px"
	if err := store.PutAuthorized(ctx, theme, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetDefault(ctx, clientID)
	if err != nil || !reflect.DeepEqual(got, theme) {
		t.Fatalf("stored bootstrap theme=%#v err=%v want=%#v", got, err, theme)
	}
}

func TestThemePutAuthorizedAllowsDynamicClientAndDeniesAfterDeletion(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "dynamic-theme"
	dynamic := dcr.NewStore(db)
	registration, err := dynamic.Create(ctx, dcr.CreateRequest{
		ClientID:                clientID,
		RedirectURIs:            []string{"https://rp.example.test/callback"},
		Scopes:                  []string{"openid"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Audiences:               []string{"https://api.example.test"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone,
		Name:                    "Theme RP",
	})
	if err != nil {
		t.Fatal(err)
	}

	theme := DefaultTheme(clientID)
	theme.BorderRadius = "13px"
	if err := store.PutAuthorized(ctx, theme, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetDefault(ctx, clientID)
	if err != nil || !reflect.DeepEqual(got, theme) {
		t.Fatalf("stored dynamic theme=%#v err=%v want=%#v", got, err, theme)
	}

	if err := dynamic.DeleteRegistration(ctx, registration.ClientID, registration.RegistrationAccessToken); err != nil {
		t.Fatal(err)
	}
	theme.BorderRadius = "17px"
	if err := store.PutAuthorized(ctx, theme, keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted dynamic client theme put=%v", err)
	}
	got, err = store.GetDefault(ctx, clientID)
	if err != nil || got.ClientID != "rauthy" {
		t.Fatalf("deleted dynamic theme after denied put=%#v err=%v", got, err)
	}
}

func TestThemePutAuthorizedRejectsMissingClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	theme := DefaultTheme("missing-theme")
	if err := store.PutAuthorized(ctx, theme, keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("missing client theme put=%v", err)
	}
	got, err := store.GetDefault(ctx, theme.ClientID)
	if err != nil || got.ClientID != "rauthy" {
		t.Fatalf("missing client theme after denied put=%#v err=%v", got, err)
	}
}

func TestThemePutAuthorizedAllowsDisabledManagedClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "disabled-theme"
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "theme-kind-disabled-managed",
		SQL:       `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?, 'test',1,0,0,'{}')`,
		Args:      []any{clientID},
	}); err != nil {
		t.Fatal(err)
	}

	theme := DefaultTheme(clientID)
	theme.BorderRadius = "15px"
	if err := store.PutAuthorized(ctx, theme, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetDefault(ctx, clientID)
	if err != nil || !reflect.DeepEqual(got, theme) {
		t.Fatalf("stored disabled managed theme=%#v err=%v want=%#v", got, err, theme)
	}
}
