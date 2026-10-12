package login

import (
	"context"
	"github.com/mrchypark/goauthy/internal/branding"
)

// LoginBranding is display-only data; authentication fields and actions remain server-owned.
type LoginBranding struct {
	Name            string
	LogoURL         string
	English, Korean branding.LoginCopy
}

func (h *Handler) SetLoginBrandingResolver(resolve func(context.Context, string) (LoginBranding, error)) {
	h.loginBrandingResolver = resolve
}

func (h *Handler) resolveBranding(ctx context.Context, id string) (LoginBranding, error) {
	if h.loginBrandingResolver == nil {
		return LoginBranding{Name: "GoAuthy"}, nil
	}
	return h.loginBrandingResolver(ctx, id)
}
