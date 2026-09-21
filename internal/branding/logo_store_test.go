package branding

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestClientLogoStoreReplacementAndFallback(t *testing.T) {
	t.Parallel()
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-small"), 11)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-favicon"), 12)
	seedLogo(t, ctx, db, "rauthy", "small", "image/webp", []byte("global-small"), 13)
	keys, principal := logoUpdateKey(t, ctx, db, "logo-replace-key")

	if err := store.ReplaceAuthorized(ctx, "client-a", []LogoAsset{{Resolution: "svg", ContentType: "image/svg+xml", Data: []byte("<svg/>")}}, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, "client-a", "small")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, []byte("<svg/>")) {
		t.Fatalf("svg fallback=%#v err=%v", got, err)
	}
	public, err := store.GetFallback(ctx, "client-a")
	if err != nil || public.Resolution != "svg" || !bytes.Equal(public.Data, []byte("<svg/>")) {
		t.Fatalf("public SVG must precede global raster: %#v err=%v", public, err)
	}
	favicon, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("favicon after svg replacement=%#v err=%v", favicon, err)
	}

	if err := store.ReplaceAuthorized(ctx, "client-a", []LogoAsset{
		{Resolution: "medium", ContentType: "image/webp", Data: []byte("new-medium")},
		{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")},
	}, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err = store.Find(ctx, "client-a", "small")
	if err != nil || got.Resolution != "small" || !bytes.Equal(got.Data, []byte("new-small")) || got.Updated <= 0 {
		t.Fatalf("raster replacement=%#v err=%v", got, err)
	}
	favicon, err = store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("favicon after raster replacement=%#v err=%v", favicon, err)
	}

	if err := store.DeleteAuthorized(ctx, "client-a", keys, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Find(ctx, "client-a", "small"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("deleted small err=%v", err)
	}
	favicon, err = store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("favicon after delete=%#v err=%v", favicon, err)
	}
	fallback, err := store.GetFallback(ctx, "client-a")
	if err != nil || fallback.Resolution != "small" || !bytes.Equal(fallback.Data, []byte("global-small")) {
		t.Fatalf("global fallback=%#v err=%v", fallback, err)
	}
}

func TestClientLogoStoreMalformedBatchPreservesOld(t *testing.T) {
	t.Parallel()
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-small"), 21)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-favicon"), 22)
	keys, principal := logoUpdateKey(t, ctx, db, "logo-malformed-key")
	if err := store.ReplaceAuthorized(ctx, "client-a", []LogoAsset{
		{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")},
		{Resolution: "small", ContentType: "image/webp", Data: []byte("duplicate")},
	}, keys, principal); !errors.Is(err, ErrInvalidLogo) {
		t.Fatalf("malformed batch err=%v", err)
	}
	got, err := store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("malformed batch changed old logo=%#v err=%v", got, err)
	}
	favicon, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("malformed batch changed favicon=%#v err=%v", favicon, err)
	}
}

func TestClientLogoStoreMixedSVGAndRasterPreservesOld(t *testing.T) {
	t.Parallel()
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-small"), 23)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-favicon"), 24)
	keys, principal := logoUpdateKey(t, ctx, db, "logo-mixed-key")
	if err := store.ReplaceAuthorized(ctx, "client-a", []LogoAsset{
		{Resolution: "svg", ContentType: "image/svg+xml", Data: []byte("<svg/>")},
		{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")},
	}, keys, principal); !errors.Is(err, ErrInvalidLogo) {
		t.Fatalf("mixed SVG/raster batch err=%v", err)
	}
	got, err := store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("mixed batch changed old logo=%#v err=%v", got, err)
	}
	favicon, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(favicon.Data, []byte("old-favicon")) {
		t.Fatalf("mixed batch changed favicon=%#v err=%v", favicon, err)
	}
}

func TestClientLogoStoreRevokedKeyDeniesReplacement(t *testing.T) {
	t.Parallel()
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("old-small"), 31)
	keys, principal := logoUpdateKey(t, ctx, db, "logo-revoked-key")
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAuthorized(ctx, "client-a", []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")}}, keys, principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked replacement err=%v", err)
	}
	got, err := store.Find(ctx, "client-a", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("revoked replacement changed old logo=%#v err=%v", got, err)
	}
}

func TestClientLogoStoreDeletedClientDeniesMutation(t *testing.T) {
	t.Parallel()
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "deleted-client", true)
	seedLogo(t, ctx, db, "deleted-client", "small", "image/webp", []byte("old-small"), 41)
	keys, principal := logoUpdateKey(t, ctx, db, "logo-deleted-key")
	if err := store.ReplaceAuthorized(ctx, "deleted-client", []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")}}, keys, principal); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted replacement err=%v", err)
	}
	got, err := store.Find(ctx, "deleted-client", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("deleted replacement changed old logo=%#v err=%v", got, err)
	}
	if err := store.DeleteAuthorized(ctx, "deleted-client", keys, principal); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted delete err=%v", err)
	}
}

func seedLogoClient(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string, deleted bool) {
	t.Helper()
	deletedValue := 0
	if deleted {
		deletedValue = 1
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logo-client-" + clientID, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json) VALUES(?, 'logo-test',1,0,?,'{}')`, Args: []any{clientID, deletedValue}}); err != nil {
		t.Fatal(err)
	}
}

func seedLogo(t *testing.T, ctx context.Context, db *rhiza.DB, clientID, resolution, contentType string, data []byte, updated int64) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "logo-row-" + clientID + "-" + resolution, SQL: `INSERT INTO client_logos(client_id,res,content_type,data,updated) VALUES(?,?,?,?,?)`, Args: []any{clientID, resolution, contentType, data, updated}}); err != nil {
		t.Fatal(err)
	}
}

func logoUpdateKey(t *testing.T, ctx context.Context, db *rhiza.DB, name string) (*apikey.Store, *apikey.Principal) {
	t.Helper()
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: name, Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return keys, &principal
}
