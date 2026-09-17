package login

import (
	"errors"
	"fmt"
	"github.com/mrchypark/goauthy/internal/browser"
	"net/http"
)

var errLoginLocation = errors.New("login location lookup failed")

// SetLoginLocationObserver attaches location lookup and notification scheduling.
// Lookup errors stop the response; the observer may send notifications asynchronously.
// The browser ID is correlation metadata, not authentication authority.
func (h *Handler) SetLoginLocationObserver(observer func(*http.Request, string, string, string, string) error) {
	h.onLoginLocation = observer
}

func (h *Handler) recordLoginLocation(w http.ResponseWriter, r *http.Request, subject, ip string) error {
	if h.onLoginLocation == nil {
		return nil
	}
	id, err := h.browserID(r)
	if err != nil {
		return err
	}

	if err := h.onLoginLocation(r, subject, id, ip, r.UserAgent()); err != nil {
		return fmt.Errorf("%w: %w", errLoginLocation, err)
	}
	return nil
}

func (h *Handler) setBrowserIDCookie(w http.ResponseWriter, r *http.Request) error {
	if h.onLoginLocation == nil {
		return nil
	}
	id, err := h.browserID(r)
	if err != nil || id != "" {
		return err
	}
	makeCookie := browser.BrowserIDCookie
	if h.browserIDPolicy != nil {
		makeCookie = h.browserIDPolicy.BrowserIDCookie
	}
	cookie, err := makeCookie(h.issuer)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

// SetBrowserIDPolicy configures correlation cookies before serving requests.
func (h *Handler) SetBrowserIDPolicy(policy *browser.BrowserIDPolicy) { h.browserIDPolicy = policy }

func (h *Handler) browserID(r *http.Request) (string, error) {
	if h.browserIDPolicy != nil {
		return h.browserIDPolicy.BrowserID(r, h.issuer)
	}
	return browser.BrowserID(r, h.issuer)
}
