package login

import (
	"context"
	"github.com/mrchypark/goauthy/internal/branding"
)

// LoginBranding is display-only data; authentication fields and actions remain server-owned.
type LoginBranding struct {
	LogoURL         string
	English, Korean branding.LoginCopy
}

func (h *Handler) SetLoginBrandingResolver(resolve func(context.Context, string) (LoginBranding, error)) {
	h.loginBrandingResolver = resolve
}
