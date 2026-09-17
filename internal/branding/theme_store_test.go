package branding

import (
	"errors"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestThemeStoreFallbackAndCrossStoreUpdates(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	first, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	builtin := DefaultTheme("rauthy")
	got, err := second.GetFallback(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, builtin) {
		t.Fatalf("default error=%v", err)
	}
	global := DefaultTheme("rauthy")
	global.BorderRadius = "8px"
	if err := first.Put(ctx, global); err != nil {
		t.Fatal(err)
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, global) {
		t.Fatalf("global fallback error=%v", err)
	}
	got, err = second.GetDefault(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, builtin) {
		t.Fatalf("admin default incorrectly used global override: %v", err)
	}
	custom := DefaultTheme("client-a")
	custom.BorderRadius = "12px"
	if err := first.Put(ctx, custom); err != nil {
		t.Fatal(err)
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, custom) {
		t.Fatalf("client override error=%v", err)
	}
	custom.BorderRadius = "</style>"
	if err := first.Put(ctx, custom); err == nil {
		t.Fatal("invalid CSS accepted")
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || got.BorderRadius != "12px" {
		t.Fatal("failed mutation changed theme")
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "theme-future-version", SQL: `UPDATE client_themes SET version=2 WHERE client_id='client-a'`}); err != nil {
		t.Fatal(err)
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || got.ClientID != "client-a" || got.BorderRadius != "12px" || !reflect.DeepEqual(got.Light, builtin.Light) {
		t.Fatalf("unknown version fallback error=%v", err)
	}
	if err := first.Delete(ctx, "client-a"); err != nil {
		t.Fatal(err)
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, global) {
		t.Fatalf("delete did not reveal global theme: %v", err)
	}
	if err := first.Delete(ctx, "rauthy"); err != nil {
		t.Fatal(err)
	}
	got, err = second.GetFallback(ctx, "client-a")
	if err != nil || !reflect.DeepEqual(got, builtin) {
		t.Fatalf("global delete fallback error=%v", err)
	}
}

func TestThemeMutationsRejectRevokedAPIKey(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "theme-key", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update, apikey.Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "theme-client-seed", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,metadata_json) VALUES('client-a','test',1,0,'{}')`}); err != nil {
		t.Fatal(err)
	}
	theme := DefaultTheme("client-a")
	theme.BorderRadius = "9px"
	if err := store.PutAuthorized(ctx, theme, keys, &principal); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	theme.BorderRadius = "17px"
	if err := store.PutAuthorized(ctx, theme, keys, &principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked put: %v", err)
	}
	if err := store.DeleteAuthorized(ctx, theme.ClientID, keys, &principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked delete: %v", err)
	}
	got, err := store.GetDefault(ctx, theme.ClientID)
	if err != nil || got.BorderRadius != "9px" {
		t.Fatalf("revoked mutation changed theme: %v", err)
	}
	if err := store.DeleteAuthorized(ctx, theme.ClientID, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetDefault(ctx, theme.ClientID)
	if err != nil || got.ClientID != "rauthy" {
		t.Fatalf("admin delete failed: %v", err)
	}
}

func TestThemePutCannotRecreateDeletedClientTheme(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	theme := DefaultTheme("deleted-client")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "deleted-theme-client", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?, 'test',1,0,1,'{}')`, Args: []any{theme.ClientID}}); err != nil {
		t.Fatal(err)
	}
	// A handler may have already observed this client before another request deleted it.
	if err := store.PutAuthorized(ctx, theme, keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted client theme write: %v", err)
	}
	got, err := store.GetDefault(ctx, theme.ClientID)
	if err != nil || got.ClientID != "rauthy" {
		t.Fatalf("orphan theme persisted: %v", err)
	}
}

func TestThemeStylesheetURLTracksEffectiveFallback(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "client/with?path"
	first, err := store.StylesheetURL(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(first, "/")
	if len(parts) != 6 || parts[4] != url.PathEscape(clientID) {
		t.Fatalf("unsafe stylesheet URL %q", first)
	}
	if _, err := strconv.ParseInt(parts[5], 10, 64); err != nil {
		t.Fatal(err)
	}
	global := DefaultTheme("rauthy")
	global.BorderRadius = "19px"
	if err := store.Put(ctx, global); err != nil {
		t.Fatal(err)
	}
	second, err := store.StylesheetURL(ctx, clientID)
	if err != nil || first == second {
		t.Fatalf("global update kept stale CSS URL: %v", err)
	}
	if err := store.Delete(ctx, "rauthy"); err != nil {
		t.Fatal(err)
	}
	third, err := store.StylesheetURL(ctx, clientID)
	if err != nil || third != first {
		t.Fatalf("default URL changed unexpectedly: %v", err)
	}
}
