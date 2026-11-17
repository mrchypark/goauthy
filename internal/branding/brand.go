package branding

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const GlobalBrandID = "goauthy"

// Brand contains display-only values for the central account and admin shells.
type Brand struct {
	Name, LogoURL, ThemeURL string
}

// ResolveOptional evaluates an optional brand resolver and guarantees a non-empty Name.
func ResolveOptional(ctx context.Context, resolve func(context.Context) (Brand, error)) Brand {
	brand := Brand{Name: "GoAuthy"}
	if resolve != nil {
		if resolved, err := resolve(ctx); err == nil {
			if strings.TrimSpace(resolved.Name) == "" {
				resolved.Name = "GoAuthy"
			}
			return resolved
		}
	}
	return brand
}

func (s *ThemeStore) Brand(ctx context.Context, logos *ClientLogoStore, clientID string) (Brand, error) {
	global, err := s.GetGlobal(ctx)
	if err != nil {
		return Brand{}, err
	}
	name := global.BrandName
	if name == "" {
		name = "GoAuthy"
	}
	brand := Brand{Name: name}
	brand.ThemeURL, err = s.StylesheetURL(ctx, clientID)
	if err != nil {
		return Brand{}, err
	}
	var asset StoredLogo
	if clientID == "" {
		asset, err = logos.GetGlobal(ctx)
	} else {
		asset, err = logos.GetFallback(ctx, clientID)
	}
	if err != nil && !errors.Is(err, ErrLogoNotFound) {
		return Brand{}, err
	}
	if err == nil {
		if clientID == "" {
			brand.LogoURL = "/auth/v1/branding/logo?updated=" + strconv.FormatInt(asset.Updated, 10)
		} else {
			brand.LogoURL = "/auth/v1/clients/" + url.PathEscape(clientID) + "/logo?updated=" + strconv.FormatInt(asset.Updated, 10)
		}
	}
	return brand, nil
}
