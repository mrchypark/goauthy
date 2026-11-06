package branding

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

func TestLegacyHTTPRealAPIKeyAuthorization(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	themes, _ := NewThemeStore(db)
	logos, _ := NewClientLogoStore(db)
	seedLogo(t, ctx, db, GlobalBrandID, "small", "image/webp", []byte("legacy"), 1)
	keys, token, principal := logoHTTPKey(t, ctx, db, "legacy-boundary", apikey.Read, apikey.Update)
	themeHandler, _ := NewThemeHandler(themes, keys, nil, func(context.Context, string) error { return nil })
	logoHandler, _ := NewClientLogoHandler(logos, keys, nil)
	endpoints := []struct {
		name, method string
		call         http.HandlerFunc
	}{
		{"status", http.MethodGet, themeHandler.LegacyStatus},
		{"theme", http.MethodGet, themeHandler.LegacyTheme},
		{"logo", http.MethodGet, logoHandler.LegacyLogo},
		{"resolve", http.MethodPost, themeHandler.ResolveLegacy},
	}
	for _, endpoint := range endpoints {
		w := httptest.NewRecorder()
		endpoint.call(w, httptest.NewRequest(endpoint.method, "/", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s status=%d", endpoint.name, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	themeHandler.LegacyStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid API key status=%d", w.Code)
	}
	_, readOnly, _ := logoHTTPKey(t, ctx, db, "legacy-reader", apikey.Read)
	r = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":false,"copy_logo":false}`))
	r.Header.Set("Authorization", "API-Key "+readOnly)
	w = httptest.NewRecorder()
	themeHandler.ResolveLegacy(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only mutation status=%d", w.Code)
	}
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		r := httptest.NewRequest(endpoint.method, "/", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":false,"copy_logo":false}`))
		r.Header.Set("Authorization", "API-Key "+token)
		w := httptest.NewRecorder()
		endpoint.call(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("revoked %s status=%d", endpoint.name, w.Code)
		}
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM branding_legacy_resolution", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(0) {
		t.Fatal("denied request changed resolution")
	}
}

func TestLegacyResolutionPartialConflictRollsBackBothScopes(t *testing.T) {
	for _, conflict := range []string{"theme", "logo"} {
		t.Run(conflict, func(t *testing.T) {
			ctx, db := clientFaviconDB(t)
			themes, _ := NewThemeStore(db)
			logos, _ := NewClientLogoStore(db)
			legacy := DefaultTheme(GlobalBrandID)
			legacy.BrandName = "Legacy"
			if err := themes.Put(ctx, legacy); err != nil {
				t.Fatal(err)
			}
			seedLogo(t, ctx, db, GlobalBrandID, "small", "image/webp", []byte("legacy"), 1)
			keys, token, _ := logoHTTPKey(t, ctx, db, "partial-conflict", apikey.Update)
			if conflict == "theme" {
				global := DefaultTheme(GlobalBrandID)
				global.BrandName = "Already set"
				if err := themes.PutGlobalAuthorized(ctx, global, keys, nil); err != nil {
					t.Fatal(err)
				}
			} else if err := logos.ReplaceGlobalAuthorized(ctx, []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("already set")}}, keys, nil); err != nil {
				t.Fatal(err)
			}
			query := rhiza.QueryRequest{SQL: `SELECT (SELECT document_json FROM client_themes WHERE client_id='goauthy'), (SELECT data FROM client_logos WHERE client_id='goauthy'), (SELECT document_json FROM global_brand_themes), (SELECT data FROM global_brand_logos), (SELECT COUNT(*) FROM branding_legacy_resolution)`, Consistency: rhiza.ConsistencyLinearizable}
			before, err := db.Query(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := NewThemeHandler(themes, keys, nil, func(context.Context, string) error { return nil })
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":true,"copy_logo":true}`))
			r.Header.Set("Authorization", "API-Key "+token)
			w := httptest.NewRecorder()
			handler.ResolveLegacy(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("conflict status=%d", w.Code)
			}
			after, err := db.Query(ctx, query)
			if err != nil || !reflect.DeepEqual(before.Rows, after.Rows) {
				t.Fatal("partial conflict changed either scope or resolution")
			}
		})
	}
}

func TestLegacyResolutionConcurrentOneWinner(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	themes, _ := NewThemeStore(db)
	legacy := DefaultTheme(GlobalBrandID)
	legacy.BrandName = "Legacy"
	if err := themes.Put(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	seedLogo(t, ctx, db, GlobalBrandID, "small", "image/webp", []byte("legacy"), 1)
	keys, token, _ := logoHTTPKey(t, ctx, db, "concurrent-resolve", apikey.Update)
	handler, _ := NewThemeHandler(themes, keys, nil, func(context.Context, string) error { return nil })
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":true,"copy_logo":true}`))
			r.Header.Set("Authorization", "API-Key "+token)
			w := httptest.NewRecorder()
			handler.ResolveLegacy(w, r)
			statuses <- w.Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusNoContent] != 1 || counts[http.StatusServiceUnavailable] != 1 {
		t.Fatalf("resolution statuses=%v", counts)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM global_brand_themes), (SELECT COUNT(*) FROM global_brand_logos), (SELECT COUNT(*) FROM branding_legacy_resolution), (SELECT COUNT(*) FROM client_themes WHERE client_id='goauthy'), (SELECT COUNT(*) FROM client_logos WHERE client_id='goauthy')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || !reflect.DeepEqual(rows.Rows, [][]any{{int64(1), int64(1), int64(1), int64(1), int64(1)}}) {
		t.Fatal("concurrent resolution lost or duplicated records")
	}
}
