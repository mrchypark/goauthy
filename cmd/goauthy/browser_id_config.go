package main

import (
	"fmt"
	"github.com/mrchypark/goauthy/internal/browser"
	"strconv"
	"strings"
)

func browserIDPolicyFromEnv(getenv func(string) string, issuer string) (*browser.BrowserIDPolicy, error) {
	mode := getenv("GOAUTHY_BROWSER_ID_COOKIE_MODE")
	if mode == "" {
		mode = browser.BrowserIDDangerInsecure
		if strings.HasPrefix(issuer, "https://") {
			mode = browser.BrowserIDHost
		}
	}
	setPath, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_BROWSER_ID_COOKIE_SET_PATH", "false"))
	if err != nil {
		return nil, fmt.Errorf("GOAUTHY_BROWSER_ID_COOKIE_SET_PATH: %w", err)
	}
	policy, err := browser.NewBrowserIDPolicy(mode, setPath)
	if err != nil {
		return nil, fmt.Errorf("GOAUTHY_BROWSER_ID_COOKIE_MODE: %w", err)
	}
	return policy, nil
}
