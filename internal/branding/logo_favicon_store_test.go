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

func TestClientLogoFaviconAuthorizedReplaceDeletePreservesLogo(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("logo-small"), 11)
	seedLogo(t, ctx, db, "client-a", "svg", "image/svg+xml", []byte("logo-svg"), 12)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-unified-favicon"), 13)
	seedLegacyClientLogoFavicon(t, ctx, db, "client-a", []byte("old-legacy-favicon"), 14)
	keys, principal := logoUpdateKey(t, ctx, db, "favicon-replace-key")

	newFavicon := LogoAsset{Resolution: "favicon", ContentType: "image/webp", Data: []byte("new-favicon")}
	if err := store.ReplaceFaviconAuthorized(ctx, "client-a", newFavicon, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || got.Resolution != "favicon" || got.ContentType != "image/webp" || !bytes.Equal(got.Data, newFavicon.Data) {
		t.Fatalf("replaced favicon=%#v err=%v", got, err)
	}
	for _, resolution := range []string{"small", "svg"} {
		got, err := store.Find(ctx, "client-a", resolution)
		want := map[string][]byte{"small": []byte("logo-small"), "svg": []byte("logo-svg")}[resolution]
		if err != nil || !bytes.Equal(got.Data, want) {
			t.Fatalf("nonfavicon %s=%#v err=%v", resolution, got, err)
		}
	}
	if got := legacyClientLogoFaviconCount(t, ctx, db, "client-a"); got != 0 {
		t.Fatalf("legacy favicon rows after replace=%d, want 0", got)
	}

	newSVGFavicon := LogoAsset{Resolution: "favicon", ContentType: "image/svg+xml", Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`)}
	if err := store.ReplaceFaviconAuthorized(ctx, "client-a", newSVGFavicon, keys, principal); err != nil {
		t.Fatal(err)
	}
	got, err = store.Find(ctx, "client-a", "favicon")
	if err != nil || got.ContentType != "image/svg+xml" || !bytes.Equal(got.Data, newSVGFavicon.Data) {
		t.Fatalf("SVG favicon=%#v err=%v", got, err)
	}

	if err := store.DeleteFaviconAuthorized(ctx, "client-a", keys, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Find(ctx, "client-a", "favicon"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("deleted favicon err=%v", err)
	}
	for _, resolution := range []string{"small", "svg"} {
		got, err := store.Find(ctx, "client-a", resolution)
		want := map[string][]byte{"small": []byte("logo-small"), "svg": []byte("logo-svg")}[resolution]
		if err != nil || !bytes.Equal(got.Data, want) {
			t.Fatalf("nonfavicon %s after delete=%#v err=%v", resolution, got, err)
		}
	}
	if got := legacyClientLogoFaviconCount(t, ctx, db, "client-a"); got != 0 {
		t.Fatalf("legacy favicon rows after delete=%d, want 0", got)
	}
}

func TestClientLogoFaviconAuthorizedRejectsInvalidAsset(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("logo-small"), 21)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("old-favicon"), 22)
	keys, principal := logoUpdateKey(t, ctx, db, "favicon-invalid-key")

	for _, asset := range []LogoAsset{
		{Resolution: "small", ContentType: "image/webp", Data: []byte("wrong-resolution")},
		{Resolution: "favicon", ContentType: "image/webp"},
		{Resolution: "favicon", ContentType: "image/png", Data: []byte("wrong-content-type")},
	} {
		if err := store.ReplaceFaviconAuthorized(ctx, "client-a", asset, keys, principal); !errors.Is(err, ErrInvalidLogo) {
			t.Fatalf("invalid asset %#v err=%v", asset, err)
		}
	}
	got, err := store.Find(ctx, "client-a", "favicon")
	if err != nil || !bytes.Equal(got.Data, []byte("old-favicon")) {
		t.Fatalf("invalid asset changed favicon=%#v err=%v", got, err)
	}
}

func TestClientLogoFaviconAuthorizedRevokedAndDeletedPreserveBoth(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedLogoClient(t, ctx, db, "client-a", false)
	seedLogo(t, ctx, db, "client-a", "small", "image/webp", []byte("active-logo"), 31)
	seedLogo(t, ctx, db, "client-a", "favicon", "image/webp", []byte("active-favicon"), 32)
	seedLegacyClientLogoFavicon(t, ctx, db, "client-a", []byte("active-legacy"), 33)
	keys, principal := logoUpdateKey(t, ctx, db, "favicon-revoked-key")
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	asset := LogoAsset{Resolution: "favicon", ContentType: "image/webp", Data: []byte("new-favicon")}
	if err := store.ReplaceFaviconAuthorized(ctx, "client-a", asset, keys, principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked replace err=%v", err)
	}
	if err := store.DeleteFaviconAuthorized(ctx, "client-a", keys, principal); !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked delete err=%v", err)
	}
	assertClientLogoFaviconRows(t, ctx, db, "client-a", []byte("active-logo"), []byte("active-favicon"), []byte("active-legacy"))

	seedLogoClient(t, ctx, db, "deleted-client", true)
	seedLogo(t, ctx, db, "deleted-client", "small", "image/webp", []byte("deleted-logo"), 41)
	seedLogo(t, ctx, db, "deleted-client", "favicon", "image/webp", []byte("deleted-favicon"), 42)
	seedLegacyClientLogoFavicon(t, ctx, db, "deleted-client", []byte("deleted-legacy"), 43)
	_, deletedPrincipal := logoUpdateKey(t, ctx, db, "favicon-deleted-key")
	if err := store.ReplaceFaviconAuthorized(ctx, "deleted-client", asset, keys, deletedPrincipal); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted replace err=%v", err)
	}
	if err := store.DeleteFaviconAuthorized(ctx, "deleted-client", keys, deletedPrincipal); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("deleted delete err=%v", err)
	}
	assertClientLogoFaviconRows(t, ctx, db, "deleted-client", []byte("deleted-logo"), []byte("deleted-favicon"), []byte("deleted-legacy"))
}

func seedLegacyClientLogoFavicon(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string, data []byte, updated int64) {
	t.Helper()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "legacy-favicon-" + clientID,
		SQL:       `INSERT INTO client_favicons(client_id,content_type,data,updated_at_unix_ms) VALUES(?,?,?,?)`,
		Args:      []any{clientID, "image/png", data, updated},
	}); err != nil {
		t.Fatal(err)
	}
}

func legacyClientLogoFaviconCount(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string) int64 {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM client_favicons WHERE client_id=?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("legacy favicon count rows=%#v err=%v", result.Rows, err)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("legacy favicon count type=%T", result.Rows[0][0])
	}
	return count
}

func assertClientLogoFaviconRows(t *testing.T, ctx context.Context, db *rhiza.DB, clientID string, logo, favicon, legacy []byte) {
	t.Helper()
	store, err := NewClientLogoStore(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Find(ctx, clientID, "small")
	if err != nil || !bytes.Equal(got.Data, logo) {
		t.Fatalf("logo=%#v err=%v", got, err)
	}
	got, err = store.Find(ctx, clientID, "favicon")
	if err != nil || !bytes.Equal(got.Data, favicon) {
		t.Fatalf("favicon=%#v err=%v", got, err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT data FROM client_favicons WHERE client_id=?`, Args: []any{clientID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("legacy favicon rows=%#v err=%v", result.Rows, err)
	}
	data, ok := result.Rows[0][0].([]byte)
	if !ok || !bytes.Equal(data, legacy) {
		t.Fatalf("legacy favicon=%#v", result.Rows[0][0])
	}
}
