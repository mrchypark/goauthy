package branding

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestGlobalStorageDoesNotClaimClientRecords(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	themes, _ := NewThemeStore(db)
	logos, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	old := DefaultTheme(GlobalBrandID)
	old.BrandName = "Existing client"
	if err := themes.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	seedLogo(t, ctx, db, GlobalBrandID, "small", "image/webp", []byte("existing"), 1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "global-storage-bootstrap", SQL: `INSERT INTO managed_oauth_client_bootstrap(singleton,id) VALUES(1,'goauthy')`}); err != nil {
		t.Fatal(err)
	}
	global, err := themes.GetGlobal(ctx)
	if err != nil || global.BrandName == old.BrandName {
		t.Fatalf("legacy theme claimed: %+v %v", global, err)
	}
	if _, err := logos.GetGlobal(ctx); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("legacy logo claimed: %v", err)
	}
	global.BrandName = "Common brand"
	global.BorderRadius = "8px"
	if err := themes.PutGlobalAuthorized(ctx, global, keys, nil); err != nil {
		t.Fatal(err)
	}
	if err := logos.ReplaceGlobalAuthorized(ctx, []LogoAsset{{Resolution: "small", ContentType: "image/webp", Data: []byte("common")}}, keys, nil); err != nil {
		t.Fatal(err)
	}
	themeHandler, _ := NewThemeHandler(themes, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, func(context.Context, string) error { return nil })
	logoHandler, _ := NewClientLogoHandler(logos, keys, nil)
	css := httptest.NewRecorder()
	cssRequest := httptest.NewRequest(http.MethodGet, "/auth/v1/branding/theme/1", nil)
	cssRequest.SetPathValue("timestamp", "1")
	themeHandler.GlobalTheme(css, cssRequest)
	if css.Code != http.StatusOK || css.Body.String() != global.CSS() {
		t.Fatalf("global CSS: %d %s", css.Code, css.Body.String())
	}
	image := httptest.NewRecorder()
	logoHandler.GlobalLogo(image, httptest.NewRequest(http.MethodGet, "/auth/v1/branding/logo", nil))
	if image.Code != http.StatusOK || image.Body.String() != "common" {
		t.Fatalf("global logo HTTP: %d %s", image.Code, image.Body.String())
	}
	brand, err := themes.Brand(ctx, logos, "")
	if err != nil || brand.Name != global.BrandName || !strings.HasPrefix(brand.ThemeURL, "/auth/v1/branding/theme/") || !strings.HasPrefix(brand.LogoURL, "/auth/v1/branding/logo?") {
		t.Fatalf("central brand: %+v %v", brand, err)
	}
	client, err := themes.GetFallback(ctx, GlobalBrandID)
	if err != nil || client.BrandName != global.BrandName {
		t.Fatalf("unresolved client inherited legacy theme: %+v %v", client, err)
	}
	logo, err := logos.GetFallback(ctx, GlobalBrandID)
	if err != nil || string(logo.Data) != "common" {
		t.Fatalf("unresolved client inherited legacy logo: %+v %v", logo, err)
	}
	inherited, err := themes.GetFallback(ctx, "other")
	if err != nil || inherited.BrandName != global.BrandName {
		t.Fatalf("global theme missing: %+v %v", inherited, err)
	}
	logo, err = logos.GetFallback(ctx, "other")
	if err != nil || string(logo.Data) != "common" {
		t.Fatalf("global logo missing: %+v %v", logo, err)
	}
	if err := themes.DeleteGlobalAuthorized(ctx, keys, nil); err != nil {
		t.Fatal(err)
	}
	if err := logos.DeleteGlobalAuthorized(ctx, keys, nil); err != nil {
		t.Fatal(err)
	}
	client, err = themes.get(ctx, GlobalBrandID, false, false, true)
	if err != nil || client.BrandName != old.BrandName {
		t.Fatalf("client theme deleted: %+v %v", client, err)
	}
	logo, err = logos.find(ctx, GlobalBrandID, "small", true)
	if err != nil || string(logo.Data) != "existing" {
		t.Fatalf("client logo deleted: %+v %v", logo, err)
	}
}

func TestLegacyResolutionIsExplicitAndPreservesBothScopes(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	themes, _ := NewThemeStore(db)
	logos, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	old := DefaultTheme(GlobalBrandID)
	old.BrandName = "Previously saved"
	if err := themes.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	seedLogo(t, ctx, db, GlobalBrandID, "small", "image/webp", []byte("legacy"), 1)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "resolve-bootstrap", SQL: `INSERT INTO managed_oauth_client_bootstrap(singleton,id) VALUES(1,'goauthy')`}); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewThemeHandler(themes, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, func(context.Context, string) error { return nil })
	request := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ResolveLegacy(w, httptest.NewRequest(http.MethodPost, "/auth/v1/branding/legacy/resolve", bytes.NewBufferString(body)))
		return w
	}
	if w := request(`{"copy_theme":true,"copy_logo":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing confirmation: %d", w.Code)
	}
	if w := request(`{"confirm_client_ownership":true,"copy_theme":true,"copy_logo":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("resolve: %d %s", w.Code, w.Body.String())
	}
	global, err := themes.GetGlobal(ctx)
	if err != nil || global.BrandName != old.BrandName {
		t.Fatalf("theme copy: %+v %v", global, err)
	}
	logo, err := logos.GetGlobal(ctx)
	if err != nil || string(logo.Data) != "legacy" {
		t.Fatalf("logo copy: %+v %v", logo, err)
	}
	clientTheme, err := themes.GetDefault(ctx, GlobalBrandID)
	if err != nil || clientTheme.BrandName != old.BrandName {
		t.Fatalf("resolved client theme: %+v %v", clientTheme, err)
	}
	clientLogo, err := logos.Find(ctx, GlobalBrandID, "small")
	if err != nil || string(clientLogo.Data) != "legacy" {
		t.Fatalf("resolved client logo: %+v %v", clientLogo, err)
	}
	old.BrandName = "Client changed"
	if err := themes.PutAuthorized(ctx, old, keys, nil); err != nil {
		t.Fatalf("client write after resolution: %v", err)
	}
	global, _ = themes.GetGlobal(ctx)
	if global.BrandName != "Previously saved" {
		t.Fatal("client write changed global data")
	}
	if w := request(`{"confirm_client_ownership":true,"copy_theme":false,"copy_logo":false}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("repeated resolution: %d", w.Code)
	}
}

func TestLegacyResolutionDoesNotOverwriteGlobalSettings(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	themes, _ := NewThemeStore(db)
	keys, _ := apikey.NewStore(db)
	legacy := DefaultTheme(GlobalBrandID)
	legacy.BrandName = "Legacy"
	if err := themes.Put(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	global := DefaultTheme(GlobalBrandID)
	global.BrandName = "Already configured"
	if err := themes.PutGlobalAuthorized(ctx, global, keys, nil); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewThemeHandler(themes, keys, func(http.ResponseWriter, *http.Request, bool) bool { return true }, func(context.Context, string) error { return nil })
	w := httptest.NewRecorder()
	handler.ResolveLegacy(w, httptest.NewRequest(http.MethodPost, "/auth/v1/branding/legacy/resolve", bytes.NewBufferString(`{"confirm_client_ownership":true,"copy_theme":true,"copy_logo":false}`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("conflicting resolution: %d", w.Code)
	}
	got, err := themes.GetGlobal(ctx)
	if err != nil || got.BrandName != global.BrandName {
		t.Fatalf("global changed: %+v %v", got, err)
	}
	status := httptest.NewRecorder()
	handler.LegacyStatus(status, httptest.NewRequest(http.MethodGet, "/auth/v1/branding/legacy", nil))
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"resolved":false`)) {
		t.Fatalf("resolution state: %d %s", status.Code, status.Body.String())
	}
}

func TestGoauthyClientBrandingWithoutLegacyRows(t *testing.T) {
	for _, first := range []string{"theme", "logo"} {
		t.Run(first, func(t *testing.T) {
			ctx, db := clientFaviconDB(t)
			themes, _ := NewThemeStore(db)
			logos, _ := NewClientLogoStore(db)
			keys, _ := apikey.NewStore(db)
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "fresh-branding-client", SQL: `INSERT INTO managed_oauth_client_bootstrap(singleton,id) VALUES(1,'goauthy')`}); err != nil {
				t.Fatal(err)
			}
			asset := LogoAsset{Resolution: "small", ContentType: "image/webp", Data: []byte("client logo")}
			theme := DefaultTheme(GlobalBrandID)
			theme.BrandName = "Client brand"
			putTheme := func() {
				t.Helper()
				if err := themes.PutAuthorized(ctx, theme, keys, nil); err != nil {
					t.Fatal(err)
				}
			}
			putLogo := func() {
				t.Helper()
				if err := logos.ReplaceAuthorized(ctx, GlobalBrandID, []LogoAsset{asset}, keys, nil); err != nil {
					t.Fatal(err)
				}
			}
			if first == "theme" {
				putTheme()
				putLogo()
			} else {
				putLogo()
				putTheme()
			}
			putTheme()
			putLogo()
			got, err := themes.GetDefault(ctx, GlobalBrandID)
			if err != nil || got.BrandName != theme.BrandName {
				t.Fatalf("theme: %+v %v", got, err)
			}
			logo, err := logos.Find(ctx, GlobalBrandID, "small")
			if err != nil || string(logo.Data) != "client logo" {
				t.Fatalf("logo: %+v %v", logo, err)
			}
		})
	}
}

func TestGoauthyFaviconWorksWithAmbiguousBranding(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	logos, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "favicon-client-ambiguous", Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO managed_oauth_client_bootstrap(singleton,id) VALUES(1,'goauthy')`}, {SQL: `INSERT INTO client_themes VALUES('goauthy',1,1,'{}')`}}}); err != nil {
		t.Fatal(err)
	}
	seedLogo(t, ctx, db, GlobalBrandID, "favicon", "image/webp", []byte("old favicon"), 1)
	got, err := logos.Find(ctx, GlobalBrandID, "favicon")
	if err != nil || string(got.Data) != "old favicon" {
		t.Fatalf("read favicon: %+v %v", got, err)
	}
	handler, _ := NewClientLogoHandler(logos, keys, nil)
	response := httptest.NewRecorder()
	handler.Favicon(response, clientLogoRequest(http.MethodGet, "/auth/v1/clients/goauthy/favicon", nil, GlobalBrandID))
	if response.Code != http.StatusOK || response.Body.String() != "old favicon" {
		t.Fatalf("favicon HTTP: %d %s", response.Code, response.Body.String())
	}
	asset := LogoAsset{Resolution: "favicon", ContentType: "image/webp", Data: []byte("new favicon")}
	if err := logos.ReplaceFaviconAuthorized(ctx, GlobalBrandID, asset, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, err = logos.Find(ctx, GlobalBrandID, "favicon")
	if err != nil || string(got.Data) != "new favicon" {
		t.Fatalf("replace favicon: %+v %v", got, err)
	}
	if err := logos.DeleteFaviconAuthorized(ctx, GlobalBrandID, keys, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := logos.Find(ctx, GlobalBrandID, "favicon"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("delete favicon: %v", err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM client_themes WHERE client_id='goauthy'), (SELECT COUNT(*) FROM branding_legacy_resolution)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || result.Rows[0][0] != int64(1) || result.Rows[0][1] != int64(0) {
		t.Fatalf("ambiguous data changed: %v %v", result.Rows, err)
	}
}
