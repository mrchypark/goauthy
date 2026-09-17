package browser

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	SessionCookieName       = "goauthy_session"
	secureSessionCookieName = "__Host-goauthy_session"
	FedCMSessionCookieName  = "__Host-goauthy_fedcm_session"
)

// SessionCookie builds the only browser-session cookie shape used by GoAuthy.
// HTTPS issuers receive Secure cookies; loopback HTTP development issuers do
// not. The issuer itself is validated by the OIDC bootstrap path.
func SessionCookie(issuer, token string, expiresAt time.Time) (*http.Cookie, error) {
	if _, err := tokenDigest(token); err != nil {
		return nil, ErrNotFound
	}
	name, secure, err := cookieShape(issuer)
	if err != nil {
		return nil, err
	}
	expiresAt = expiresAt.UTC()
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return nil, errors.New("browser cookie expiry must be in the future")
	}
	maxAge := int((remaining + time.Second - 1) / time.Second)
	return &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// CookieName returns the exact name used for issuer-aware request cookie
// lookup. HTTPS uses the browser-enforced __Host- prefix; only loopback HTTP
// development uses the unprefixed name.
func CookieName(issuer string) (string, error) {
	name, _, err := cookieShape(issuer)
	return name, err
}

// DeleteSessionCookie produces a cookie that removes the issuer's current
// session cookie without relaxing its security attributes.
func DeleteSessionCookie(issuer string) (*http.Cookie, error) {
	name, secure, err := cookieShape(issuer)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// FedCMSessionCookie builds the short-lived cross-site session cookie used by
// the FedCM boundary. It is deliberately separate from SessionCookie: the
// normal browser session remains SameSite=Lax.
func FedCMSessionCookie(issuer, token string, expiresAt time.Time) (*http.Cookie, error) {
	if _, err := tokenDigest(token); err != nil {
		return nil, ErrNotFound
	}
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, errors.New("invalid FedCM cookie issuer")
	}
	u, err := url.Parse(normalized)
	if err != nil || strings.ToLower(u.Scheme) != "https" {
		return nil, errors.New("FedCM cookie issuer must use HTTPS")
	}
	expiresAt = expiresAt.UTC()
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return nil, errors.New("FedCM cookie expiry must be in the future")
	}
	return &http.Cookie{
		Name: FedCMSessionCookieName, Value: token, Path: "/", Expires: expiresAt,
		MaxAge: int((remaining + time.Second - 1) / time.Second), HttpOnly: true,
		Secure: true, SameSite: http.SameSiteNoneMode,
	}, nil
}

// DeleteFedCMSessionCookie expires the separate FedCM session cookie.
func DeleteFedCMSessionCookie(issuer string) (*http.Cookie, error) {
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, errors.New("invalid FedCM cookie issuer")
	}
	u, err := url.Parse(normalized)
	if err != nil || strings.ToLower(u.Scheme) != "https" {
		return nil, errors.New("FedCM cookie issuer must use HTTPS")
	}
	return &http.Cookie{Name: FedCMSessionCookieName, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode}, nil
}

func cookieShape(issuer string) (string, bool, error) {
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return "", false, errors.New("invalid browser cookie issuer")
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", false, errors.New("invalid browser cookie issuer")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return secureSessionCookieName, true, nil
	case "http":
		host := u.Hostname()
		if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
			return "", false, errors.New("HTTP browser cookie issuer must be loopback")
		}
		return SessionCookieName, false, nil
	default:
		return "", false, errors.New("browser cookie issuer must use HTTP or HTTPS")
	}
}
