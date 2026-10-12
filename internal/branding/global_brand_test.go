package branding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/rhiza"
)

func TestGlobalBrandThemeAuthorizedWithoutOAuthClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, _ := NewThemeStore(db)
	keys, _ := apikey.NewStore(db)
	allowed := true
	handler, _ := NewThemeHandler(store, keys, func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
		}
		return allowed
	}, func(context.Context, string) error { return clients.ErrNotFound })
	theme := DefaultTheme(GlobalBrandID)
	theme.BrandName = `GoAuthy ID "<operator>"`
	body, _ := json.Marshal(theme)
	for _, tc := range []struct {
		allowed bool
		id      string
		want    int
	}{{true, GlobalBrandID, 200}, {false, GlobalBrandID, 403}, {true, "missing", 404}} {
		allowed = tc.allowed
		theme.ClientID = tc.id
		body, _ = json.Marshal(theme)
		w := httptest.NewRecorder()
		handler.Theme(w, themeRequest(http.MethodPut, "/auth/v1/theme/"+tc.id, bytes.NewReader(body), tc.id, ""))
		if w.Code != tc.want {
			t.Fatalf("allowed=%v id=%s status=%d body=%s", allowed, tc.id, w.Code, w.Body.String())
		}
	}
	got, err := store.GetFallback(ctx, "app-a")
	if err != nil || got.ClientID != GlobalBrandID || got.BrandName != theme.BrandName {
		t.Fatalf("global fallback=%+v %v", got, err)
	}
	if err := store.PutAuthorized(ctx, DefaultTheme("missing"), keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("missing client=%v", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, tc := range []struct {
			allowed bool
			id      string
			want    int
			}{{false, GlobalBrandID, 403}, {true, "missing", 404}, {true, GlobalBrandID, 200}} {
			allowed = tc.allowed
			w := httptest.NewRecorder()
			handler.Theme(w, themeRequest(method, "/auth/v1/theme/"+tc.id, nil, tc.id, ""))
			if w.Code != tc.want {
				t.Fatalf("method=%s allowed=%v id=%s status=%d", method, allowed, tc.id, w.Code)
			}
		}
	}
	if err := store.DeleteAuthorized(ctx, "missing", keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("missing delete=%v", err)
	}
	got, err = store.GetFallback(ctx, "app-a")
	if err != nil || got.BrandName != "" {
		t.Fatalf("global reset=%+v %v", got, err)
	}
}

func TestGlobalBrandRuntimeInheritanceAndOverrides(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, _ := NewThemeStore(db)
	logos, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	global := DefaultTheme(GlobalBrandID)
	global.BrandName = `GoAuthy ID "<operator>"`
	global.Light.Action = []uint16{150, 50, 40}
	global.Login = &LoginAppearance{Copy: map[string]LoginCopy{"en": {Title: "One account"}}}
	if err := store.PutAuthorized(ctx, global, keys, nil); err != nil {
		t.Fatal(err)
	}
	asset := LogoAsset{Resolution: "small", ContentType: "image/webp", Data: []byte("global")}
	if err := logos.ReplaceAuthorized(ctx, GlobalBrandID, []LogoAsset{asset}, keys, nil); err != nil {
		t.Fatal(err)
	}
	second, _ := NewThemeStore(db)
	for _, id := range []string{GlobalBrandID, "app-a", "app-b"} {
		brand, err := second.Brand(ctx, logos, id)
		if err != nil || brand.Name != global.BrandName || brand.LogoURL == "" || brand.ThemeURL == "" {
			t.Fatalf("brand %s=%+v %v", id, brand, err)
		}
		theme, err := second.GetFallback(ctx, id)
		if err != nil || theme.Login.CopyFor("ko").Title != "One account" || theme.Light.Action[0] != 150 {
			t.Fatalf("inherited %s=%+v %v", id, theme, err)
		}
	}
	seedLogoClient(t, ctx, db, "app-b", false)
	override := DefaultTheme("app-b")
	override.Login = &LoginAppearance{Copy: map[string]LoginCopy{"en": {Title: "App B"}}}
	if err := store.PutAuthorized(ctx, override, keys, nil); err != nil {
		t.Fatal(err)
	}
	asset.Data = []byte("app-b")
	if err := logos.ReplaceAuthorized(ctx, "app-b", []LogoAsset{asset}, keys, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := second.GetFallback(ctx, "app-b")
	logo, _ := logos.GetFallback(ctx, "app-b")
	brand, _ := second.Brand(ctx, logos, "app-b")
	if got.Login.CopyFor("en").Title != "App B" || string(logo.Data) != "app-b" || brand.Name != global.BrandName {
		t.Fatalf("override theme=%+v logo=%+v brand=%+v", got, logo, brand)
	}
	if err := store.DeleteAuthorized(ctx, "app-b", keys, nil); err != nil {
		t.Fatal(err)
	}
	if err := logos.DeleteAuthorized(ctx, "app-b", keys, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = second.GetFallback(ctx, "app-b")
	logo, _ = logos.GetFallback(ctx, "app-b")
	if got.Login.CopyFor("en").Title != "One account" || string(logo.Data) != "global" {
		t.Fatal("deleting overrides did not restore inheritance")
	}
	if err := store.DeleteAuthorized(ctx, GlobalBrandID, keys, nil); err != nil {
		t.Fatal(err)
	}
	brand, _ = second.Brand(ctx, logos, GlobalBrandID)
	if brand.Name != "GoAuthy" || brand.LogoURL == "" {
		t.Fatalf("reset name/logo independence=%+v", brand)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM managed_oauth_clients WHERE id=? UNION ALL SELECT id FROM managed_oauth_client_bootstrap WHERE id=? UNION ALL SELECT client_id FROM dynamic_oauth_clients WHERE client_id=?`, Args: []any{GlobalBrandID, GlobalBrandID, GlobalBrandID}})
	if err != nil || len(result.Rows) != 0 {
		t.Fatalf("branding created an OAuth client: %+v %v", result, err)
	}
}

func TestGlobalBrandRevokedAPIKeyCannotMutate(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, _ := NewThemeStore(db)
	logos, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	_, token, err := keys.Create(ctx, nil, apikey.Request{Name: "global-brand-key", Access: []apikey.Access{{Group: "Clients", AccessRights: []apikey.Right{apikey.Read, apikey.Update, apikey.Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	principalValue, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	principal := &principalValue
	theme := DefaultTheme(GlobalBrandID)
	theme.BrandName = "Original"
	asset := LogoAsset{Resolution: "small", ContentType: "image/webp", Data: []byte("original")}
	if err := store.PutAuthorized(ctx, theme, keys, principal); err != nil {
		t.Fatal(err)
	}
	if err := logos.ReplaceAuthorized(ctx, GlobalBrandID, []LogoAsset{asset}, keys, principal); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(ctx, nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	theme.BrandName = "Denied"
	for _, err := range []error{store.PutAuthorized(ctx, theme, keys, principal), store.DeleteAuthorized(ctx, GlobalBrandID, keys, principal), logos.ReplaceAuthorized(ctx, GlobalBrandID, []LogoAsset{asset}, keys, principal), logos.DeleteAuthorized(ctx, GlobalBrandID, keys, principal)} {
		if !errors.Is(err, apikey.ErrForbidden) {
			t.Fatalf("revoked global mutation=%v", err)
		}
	}
	got, _ := store.GetDefault(ctx, GlobalBrandID)
	logo, _ := logos.GetFallback(ctx, GlobalBrandID)
	if got.BrandName != "Original" || string(logo.Data) != "original" {
		t.Fatal("revoked global mutation changed durable brand")
	}
}

func TestGlobalBrandNameValidation(t *testing.T) {
	theme := DefaultTheme(GlobalBrandID)
	for _, name := range []string{"", `GoAuthy ID "<operator>"`, "공통 계정"} {
		theme.BrandName = name
		if err := theme.Validate(); err != nil {
			t.Fatalf("valid name %q: %v", name, err)
		}
	}
	for _, name := range []string{"   ", "ID\nname", strings.Repeat("가", 121)} {
		theme.BrandName = name
		if !errors.Is(theme.Validate(), ErrInvalidTheme) {
			t.Fatalf("invalid name %q accepted", name)
		}
	}
}

func TestGlobalBrandLogoMutationWithoutOAuthClient(t *testing.T) {
	ctx, db := clientFaviconDB(t)
	store, _ := NewClientLogoStore(db)
	keys, _ := apikey.NewStore(db)
	asset := LogoAsset{Resolution: "svg", ContentType: "image/svg+xml", Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h10v10H0z"/></svg>`)}
	if err := store.ReplaceAuthorized(ctx, GlobalBrandID, []LogoAsset{asset}, keys, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAuthorized(ctx, "missing", []LogoAsset{asset}, keys, nil); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("missing client=%v", err)
	}
	logo, err := store.GetFallback(ctx, "app-b")
	if err != nil || !bytes.Equal(logo.Data, asset.Data) {
		t.Fatalf("global logo=%+v %v", logo, err)
	}
	if err := store.DeleteAuthorized(ctx, GlobalBrandID, keys, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetFallback(ctx, "app-b"); !errors.Is(err, ErrLogoNotFound) {
		t.Fatalf("global reset=%v", err)
	}
}

func TestLegacyBrandIDIsNotReserved(t *testing.T) {
	if GlobalBrandID != "goauthy" {
		t.Fatalf("canonical global brand=%q", GlobalBrandID)
	}
	condition, args := logoClientExists("rauthy")
	if condition == "1" || len(args) != 3 || args[0] != "rauthy" {
		t.Fatalf("legacy branding ID is reserved: condition=%q args=%v", condition, args)
	}
}
