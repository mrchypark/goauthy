package browser

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
)

const (
	BrowserIDHost           = "host"
	BrowserIDSecure         = "secure"
	BrowserIDDangerInsecure = "danger-insecure"

	browserIDCookieName       = "rbid"
	browserIDCookieNameHost   = "__Host-rbid"
	browserIDCookieNameSecure = "__Secure-rbid"
)

var ErrInvalidBrowserIDMode = errors.New("invalid browser ID cookie mode")

// BrowserIDPolicy controls the per-instance BrowserId cookie mode and path.
type BrowserIDPolicy struct {
	Mode          string
	CookieSetPath bool
}

func NewBrowserIDPolicy(mode string, cookieSetPath bool) (*BrowserIDPolicy, error) {
	policy := &BrowserIDPolicy{Mode: mode, CookieSetPath: cookieSetPath}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return policy, nil
}

// BrowserIDCookie creates the persistent browser correlation cookie used by
// login-location checks. It does not authenticate a user or grant access.
func (p *BrowserIDPolicy) BrowserIDCookie(issuer string) (*http.Cookie, error) {
	name, secure, path, err := p.cookieShape(issuer)
	if err != nil {
		return nil, err
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var value [32]byte
	for i := range value {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return nil, err
		}
		value[i] = alphabet[n.Int64()]
	}
	return &http.Cookie{Name: name, Value: string(value[:]), Path: path, Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 5 * 365 * 24 * 60 * 60}, nil
}

// BrowserID returns only correlation metadata, never an authentication proof.
func (p *BrowserIDPolicy) BrowserID(r *http.Request, issuer string) (string, error) {
	name, _, _, err := p.cookieShape(issuer)
	if err != nil {
		return "", err
	}
	cookie, err := r.Cookie(name)
	if err == http.ErrNoCookie {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// BrowserIDCookie preserves the existing issuer-derived defaults.
func BrowserIDCookie(issuer string) (*http.Cookie, error) {
	policy, err := defaultBrowserIDPolicy(issuer)
	if err != nil {
		return nil, err
	}
	return policy.BrowserIDCookie(issuer)
}

// BrowserID preserves the existing issuer-derived defaults.
func BrowserID(r *http.Request, issuer string) (string, error) {
	policy, err := defaultBrowserIDPolicy(issuer)
	if err != nil {
		return "", err
	}
	return policy.BrowserID(r, issuer)
}

func defaultBrowserIDPolicy(issuer string) (*BrowserIDPolicy, error) {
	_, secure, err := cookieShape(issuer)
	if err != nil {
		return nil, err
	}
	mode := BrowserIDDangerInsecure
	if secure {
		mode = BrowserIDHost
	}
	return &BrowserIDPolicy{Mode: mode}, nil
}

func (p *BrowserIDPolicy) cookieShape(issuer string) (string, bool, string, error) {
	if err := p.validate(); err != nil {
		return "", false, "", err
	}
	if _, _, err := cookieShape(issuer); err != nil {
		return "", false, "", err
	}
	switch p.Mode {
	case BrowserIDHost:
		return browserIDCookieNameHost, true, "/", nil
	case BrowserIDSecure:
		return browserIDCookieNameSecure, true, browserIDCookiePath(p.CookieSetPath), nil
	case BrowserIDDangerInsecure:
		return browserIDCookieName, false, browserIDCookiePath(p.CookieSetPath), nil
	default:
		return "", false, "", ErrInvalidBrowserIDMode
	}
}

func (p *BrowserIDPolicy) validate() error {
	if p == nil || p.Mode != BrowserIDHost && p.Mode != BrowserIDSecure && p.Mode != BrowserIDDangerInsecure {
		return ErrInvalidBrowserIDMode
	}
	return nil
}

func browserIDCookiePath(cookieSetPath bool) string {
	if cookieSetPath {
		return "/auth"
	}
	return "/"
}
