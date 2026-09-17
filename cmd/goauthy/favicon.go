package main

import (
	"github.com/mrchypark/goauthy/internal/branding"
)

func faviconFromEnv(getenv func(string) string) (*branding.Asset, error) {
	return branding.LoadFile(getenv("GOAUTHY_FAVICON_FILE"))
}
