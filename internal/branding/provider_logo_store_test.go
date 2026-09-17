package branding

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestProviderLogoStoreReplaceAndFind(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-a")
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-a")
	assets := providerRasterFixture(t)
	if err := store.ReplaceAuthorized(ctx, "provider-a", assets, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, "provider-a", "small")
	if err != nil || got.Resolution != "small" || len(got.Data) == 0 || got.Updated <= 0 {
		t.Fatalf("find small=%#v err=%v", got, err)
	}
	got, err = store.Find(ctx, "provider-a", "medium")
	if err != nil || got.Resolution != "medium" || len(got.Data) == 0 {
		t.Fatalf("find medium=%#v err=%v", got, err)
	}
	if _, err := store.Find(ctx, "provider-a", "svg"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("find svg after raster err=%v", err)
	}
	if err := store.DeleteAuthorized(ctx, "provider-a", keys, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Find(ctx, "provider-a", "small"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("find small after delete err=%v", err)
	}
}

func TestProviderLogoStoreSVGReplaceAndFind(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-b")
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-b")
	svg := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\"><rect width=\"20\" height=\"20\" fill=\"blue\"/></svg>")
	clean, err := SanitizedLogoSVG(svg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-b", []LogoAsset{{Resolution: "svg", ContentType: "image/svg+xml", Data: clean}}, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, "provider-b", "svg")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, clean) {
		t.Fatalf("find svg=%#v err=%v", got, err)
	}
	// SVG-only upload: Find("small") must fall back to SVG within the provider.
	got, err = store.Find(ctx, "provider-b", "small")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, clean) {
		t.Fatalf("find small svg-fallback=%#v err=%v", got, err)
	}
	got, err = store.Find(ctx, "provider-b", "medium")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, clean) {
		t.Fatalf("find medium svg-fallback=%#v err=%v", got, err)
	}
}

func TestProviderLogoStoreSVGUploadFindSmallRegression(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-h")
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-h")
	svg := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\"><circle cx=\"10\" cy=\"10\" r=\"8\" fill=\"red\"/></svg>")
	clean, err := SanitizedLogoSVG(svg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-h", []LogoAsset{{Resolution: "svg", ContentType: "image/svg+xml", Data: clean}}, keys, principal); err != nil {
		t.Fatal(err)
	}
	// Regression: SVG uploaded then public Find(small) must succeed.
	got, err := store.Find(ctx, "provider-h", "small")
	if err != nil {
		t.Fatalf("SVG upload -> Find(small) failed: %v", err)
	}
	if got.Resolution != "svg" || !bytes.Equal(got.Data, clean) {
		t.Fatalf("expected SVG fallback, got resolution=%q data_len=%d", got.Resolution, len(got.Data))
	}
	// Exact SVG also works.
	got, err = store.Find(ctx, "provider-h", "svg")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, clean) {
		t.Fatalf("exact SVG find=%#v err=%v", got, err)
	}
}

func TestProviderLogoStoreMalformedBatchPreservesOld(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-c")
	seedProviderLogo(t, ctx, db, "provider-c", "small", "image/webp", []byte("old-small"), 31)
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-c")
	if err := store.ReplaceAuthorized(ctx, "provider-c", []LogoAsset{
		{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")},
		{Resolution: "small", ContentType: "image/webp", Data: []byte("dup")},
	}, keys, principal); !errors.Is(err, ErrInvalidLogo) {
		t.Fatalf("dup batch err=%v", err)
	}
	got, err := store.Find(ctx, "provider-c", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("dup batch changed old=%#v err=%v", got, err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-c", []LogoAsset{
		{Resolution: "svg", ContentType: "image/svg+xml", Data: []byte("<svg/>")},
		{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")},
	}, keys, principal); !errors.Is(err, ErrInvalidLogo) {
		t.Fatalf("mixed batch err=%v", err)
	}
	got, err = store.Find(ctx, "provider-c", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("mixed batch changed old=%#v err=%v", got, err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-c", []LogoAsset{
		{Resolution: "small", ContentType: "image/svg+xml", Data: []byte("<svg/>")},
	}, keys, principal); !errors.Is(err, ErrInvalidLogo) {
		t.Fatalf("wrong content-type err=%v", err)
	}
	got, err = store.Find(ctx, "provider-c", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("wrong ct batch changed old=%#v err=%v", got, err)
	}
}

func TestProviderLogoStoreRevokedKeyDeniesMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-d")
	seedProviderLogo(t, ctx, db, "provider-d", "small", "image/webp", []byte("old-small"), 41)
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-d")
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-d", []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("new-small")}}, keys, principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked replace err=%v", err)
	}
	got, err := store.Find(ctx, "provider-d", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("old-small")) {
		t.Fatalf("revoked changed old=%#v err=%v", got, err)
	}
	if err := store.DeleteAuthorized(ctx, "provider-d", keys, principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked delete err=%v", err)
	}
}

func TestProviderLogoStoreInexistentProviderDeniesMutation(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-e")
	if err := store.ReplaceAuthorized(ctx, "no-such-provider", []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("x")}}, keys, principal); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("inexistent replace err=%v", err)
	}
	if err := store.DeleteAuthorized(ctx, "no-such-provider", keys, principal); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("inexistent delete err=%v", err)
	}
}

func TestProviderLogoStoreDeleteOnlyTarget(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-f1")
	seedAuthProvider(t, ctx, db, "provider-f2")
	seedProviderLogo(t, ctx, db, "provider-f1", "small", "image/webp", []byte("f1-small"), 61)
	seedProviderLogo(t, ctx, db, "provider-f2", "small", "image/webp", []byte("f2-small"), 62)
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-f")
	if err := store.DeleteAuthorized(ctx, "provider-f1", keys, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Find(ctx, "provider-f1", "small"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("target not deleted err=%v", err)
	}
	got, err := store.Find(ctx, "provider-f2", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("f2-small")) {
		t.Fatalf("other provider affected=%#v err=%v", got, err)
	}
}

func TestProviderLogoStoreNoGlobalFallback(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewProviderLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedAuthProvider(t, ctx, db, "provider-g")
	// Seed a client logo that must NOT be returned for provider lookups.
	seedLogoClient(t, ctx, db, "provider-g", false)
	seedLogo(t, ctx, db, "provider-g", "small", "image/webp", []byte("client-small"), 71)
	keys, principal := providerUpdateKey(t, ctx, db, "prov-logo-key-g")
	if _, err := store.Find(ctx, "provider-g", "small"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("provider must not fall back to client logos err=%v", err)
	}
	if err := store.ReplaceAuthorized(ctx, "provider-g", []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("prov-small")}}, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, "provider-g", "small")
	if err != nil || !bytes.Equal(got.Data, []byte("prov-small")) {
		t.Fatalf("expected provider logo, got=%#v err=%v", got, err)
	}
	// Provider SVG fallback must not cross into client logos.
	seedProviderLogo(t, ctx, db, "provider-g", "svg", "image/svg+xml", []byte("<svg/>"), 72)
	if err := store.ReplaceAuthorized(ctx, "provider-g", []LogoAsset{{Resolution: "svg", ContentType: "image/svg+xml", Data: []byte("<svg-new/>")}}, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err = store.Find(ctx, "provider-g", "small")
	if err != nil || got.Resolution != "svg" || !bytes.Equal(got.Data, []byte("<svg-new/>")) {
		t.Fatalf("provider svg fallback=%#v err=%v", got, err)
	}
}

func seedAuthProvider(t *testing.T, ctx context.Context, db *rhiza.DB, id string) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "provider-logo-seed-" + id,
		SQL:       "INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,scope,use_pkce) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		Args:      []any{id, int64(1), id, "oidc", "https://" + id + ".example", "https://" + id + ".example/auth", "https://" + id + ".example/token", "https://" + id + ".example/userinfo", "client-" + id, "openid", int64(1)},
	}); err != nil {
		t.Fatal(err)
	}
}

func seedProviderLogo(t *testing.T, ctx context.Context, db *rhiza.DB, providerID, resolution, contentType string, data []byte, updated int64) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "provider-logo-row-" + providerID + "-" + resolution,
		SQL:       "INSERT INTO auth_provider_logos(auth_provider_id,res,content_type,data,updated) VALUES(?,?,?,?,?)",
		Args:      []any{providerID, resolution, contentType, data, updated},
	}); err != nil {
		t.Fatal(err)
	}
}

func providerUpdateKey(t *testing.T, ctx context.Context, db *rhiza.DB, name string) (*apikey.Store, *apikey.Principal) {
	t.Helper()
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: name, Access: []apikey.Access{{Group: "AuthProviders", AccessRights: []apikey.Right{apikey.Update}}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return keys, &principal
}

func providerRasterFixture(t *testing.T) []LogoAsset {
	t.Helper()
	img := logoFixture(256, 256)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	assets, err := ProcessRasterLogo(buf.Bytes(), logoProviderSmallSize, false)
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

