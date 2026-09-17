package login

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// authorizationFormCSP is used only after OAuth redirect registration validation.
// Do not pass a raw redirect_uri query value here. Query/state/code never enter
// the policy. Other login pages retain their self-only form policy.
func authorizationFormCSP(validatedRedirect string) string {
	action := "'self'"
	u, err := url.Parse(validatedRedirect)
	if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Opaque == "" {
		host := u.Host
		if !strings.HasPrefix(host, "[") {
			// Match the browser's ASCII serialization of registered IDN hosts.
			ascii, asciiErr := idna.Lookup.ToASCII(u.Hostname())
			if asciiErr != nil {
				host = ""
			} else {
				host = ascii
				if port := u.Port(); port != "" {
					host += ":" + port
				}
			}
		}
		// A CSP host source is not an arbitrary URL string. Exclude wildcards,
		// policy delimiters and non-ASCII host syntax rather than broadening it.
		if host != "" && strings.IndexFunc(host, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".-:[]", r))
		}) < 0 {
			action += " " + u.Scheme + "://" + host
		}
	}
	return "default-src 'none'; style-src 'self'; form-action " + action + "; frame-ancestors 'none'"
}

// authorizationFormCSPWithNonce returns the same policy as authorizationFormCSP
// but adds script-src with the given nonce and connect-src self so the login
// page may include a nonce-governed inline script that calls fetch.
func authorizationFormCSPWithNonce(validatedRedirect, nonce string) string {
	base := authorizationFormCSP(validatedRedirect)
	if nonce == "" {
		return base
	}
	return base + fmt.Sprintf("; script-src 'nonce-%s'; connect-src 'self'", nonce)
}
