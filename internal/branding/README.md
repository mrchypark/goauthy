# branding

## Overview
`internal/branding` manages global and per-client/per-provider visual branding: themes, CSS generation, sanitized SVG and rasterized PNG logos, favicons, brand resolution for HTML shells, browser error pages, and embedded static assets.

## Interface
- `./assets/README.md`: Embedded static fonts, CSS, SVG, and client-side `locale.js` i18n helper.
- `[assets.go:BrandAssetHandler]`, `[assets.go:DefaultFaviconHandler]`: Serves whitelisted files from embedded `assets/*`.
- `[brand.go:GlobalBrandID]`, `[brand.go:Brand]`, `[brand.go:ThemeStore.Brand]`: Resolves display-only `Brand` (`Name`, `LogoURL`, `ThemeURL`) for central account/admin/error shells.
- `[theme.go:ErrInvalidTheme]`, `[theme.go:ThemeCSS]`, `[theme.go:Theme]`, `[theme.go:LoginAppearance]`, `[theme.go:LoginCopy]`, `[theme.go:DefaultTheme]`: Theme/copy models, validation, and CSS/email-CSS rendering.
- `[theme_store.go:ThemeStore]`, `[theme_store.go:NewThemeStore]`, `[theme_store.go:ErrThemeConflict]`, `[theme_store.go:ThemeStore.GetDefault]`, `[theme_store.go:ThemeStore.GetFallback]`, `[theme_store.go:ThemeStore.GetGlobal]`, `[theme_store.go:ThemeStore.Put]`, `[theme_store.go:ThemeStore.Delete]`, `[theme_store.go:ThemeStore.PutAuthorized]`, `[theme_store.go:ThemeStore.PutIfAbsentAuthorized]`, `[theme_store.go:ThemeStore.PutGlobalAuthorized]`, `[theme_store.go:ThemeStore.DeleteAuthorized]`, `[theme_store.go:ThemeStore.DeleteGlobalAuthorized]`, `[theme_store.go:ThemeStore.StylesheetURL]`: Theme persistence in `*rhiza.DB` with API-key/admin authorization.
- `[theme_http.go:ThemeClientExists]`, `[theme_http.go:ThemeHandler]`, `[theme_http.go:NewThemeHandler]`, `[theme_http.go:ThemeHandler.Theme]`, `[theme_http.go:ThemeHandler.GlobalTheme]`: HTTP endpoints for client and global themes.
- `[logo_svg.go:ErrInvalidLogoSVG]`, `[logo_svg.go:SanitizedLogoSVG]`, `[logo_raster.go:LogoAsset]`, `[logo_raster.go:ProcessRasterLogo]`: SVG sanitization and multi-resolution raster logo/favicon processing.
- `[logo_store.go:StoredLogo]`, `[logo_store.go:ClientLogoStore]`, `[logo_store.go:NewClientLogoStore]`, `[logo_favicon_store.go]`, `[provider_logo_store.go:ErrProviderNotFound]`, `[provider_logo_store.go:ProviderLogoStore]`, `[provider_logo_store.go:NewProviderLogoStore]`: Logo and favicon persistence in `*rhiza.DB`.
- `[logo_http.go:ClientLogoHandler]`, `[logo_http.go:NewClientLogoHandler]`, `[logo_favicon_http.go]`, `[provider_logo_http.go:ProviderLogoHandler]`, `[provider_logo_http.go:NewProviderLogoHandler]`, `[favicon.go:LoadFile]`, `[favicon.go:NewAsset]`, `[favicon.go:NewHandler]`, `[global_css.go:GlobalCSSHandler]`, `[legacy_http.go]`: HTTP handlers and stores for client/provider/global logos, favicons, and global CSS.
- `[page_errors.go:BrowserPageErrors]`, `[page_errors.go:BrowserPageErrorsWithBrand]`: HTTP middleware rendering branded HTML error pages for browser requests.

## Invariants
- Strict SVG & CSS sanitization: `[logo_svg.go:SanitizedLogoSVG]` strips unsafe elements/attributes/scripts, and `[theme.go:Theme.Validate]` / `[theme.go:ThemeCSS.Validate]` validate colors, fonts, and layout tokens before CSS generation.
- Authorized mutations: `*Authorized` store methods require either a valid `apikey.Store` + `apikey.Principal` or browser-admin authorization via HTTP handlers.
- Embedded asset whitelist: `[assets.go:serveBrandAsset]` serves only an explicit map of embedded filenames with `X-Content-Type-Options: nosniff`.

## Side Effects
- Reads and mutates theme, logo, and favicon tables in `*rhiza.DB`.
- Writes HTTP responses, stylesheets, images, and branded HTML error pages.

## Verification
- Run: `go test ./internal/branding`
