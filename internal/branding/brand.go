package branding

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

const GlobalBrandID = "goauthy"

// Brand contains display-only values for the central account and admin shells.
type Brand struct {
	Name, LogoURL, ThemeURL string
}

func (s *ThemeStore) Brand(ctx context.Context, logos *ClientLogoStore, clientID string) (Brand, error) {
	global, err := s.GetDefault(ctx, GlobalBrandID)
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
	asset, err := logos.GetFallback(ctx, clientID)
	if err != nil && !errors.Is(err, ErrLogoNotFound) {
		return Brand{}, err
	}
	if err == nil {
		brand.LogoURL = "/auth/v1/clients/" + url.PathEscape(clientID) + "/logo?updated=" + strconv.FormatInt(asset.Updated, 10)
	}
	return brand, nil
}
