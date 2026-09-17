package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/security"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func loginLocationObserver(db *rhiza.DB, users *identity.Store, keyring *oidc.Keyring, sender *recovery.SMTPSender, issuer, subjectPrefix string, lookup func(netip.Addr) (*string, error)) func(context.Context, string, string, string, string) error {
	return func(ctx context.Context, subject, browserID, ip, userAgent string) error {
		address, err := netip.ParseAddr(ip)
		if err != nil || address.Zone() != "" {
			return fosite.ErrInvalidRequest
		}
		var location *string
		if lookup != nil {
			location, err = lookup(address)
			if err != nil {
				return err
			}
		}
		// Upstream notifications are best effort and must not delay login completion.
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			fresh, err := users.RecordBrowserLoginLocation(ctx, subject, browserID, ip, userAgent, location)
			if err != nil {
				slog.Error("login location recording failed")
				return
			}
			if !fresh {
				return
			}
			profile, err := users.ProfileClaimsBySubject(ctx, subject)
			if err != nil || profile.Email == nil {
				return
			}
			operationID := "new-login-location/" + rand.Text()
			event, err := eventlog.NewLoginLocation(operationID, *profile.Email, userAgent, address, location, time.Now()).Statement("1=1")
			if err == nil {
				_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: operationID, Statements: []rhiza.SQLStatement{event}})
			}
			if err != nil {
				slog.Error("new login location event failed")
			}
			code, err := users.FindOrCreateLoginRevokeCode(ctx, keyring, subject)
			if err != nil {
				slog.Error("login revoke code issuance failed")
				return
			}
			if sender == nil {
				return
			}
			var emailTheme *branding.Theme
			themes, themeErr := branding.NewThemeStore(db)
			if themeErr == nil {
				if theme, err := themes.GetFallback(ctx, "rauthy"); err == nil {
					emailTheme = &theme
				}
			}
			language := "en"
			if profile.Language != nil {
				language = *profile.Language
			}
			base := strings.TrimRight(issuer, "/")
			link := base + "/auth/v1/users/" + url.PathEscape(subject) + "/revoke/" + code + "?" + url.Values{"ip": {address.String()}}.Encode()
			if err := sender.SendLoginLocation(ctx, recovery.LoginLocationMessage{Theme: emailTheme, SubjectPrefix: subjectPrefix, To: *profile.Email, Language: language, IP: address.String(), UserAgent: userAgent, Location: location, RevokeURL: link, AccountURL: base + "/auth/v1/account"}); err != nil {
				slog.Error("login location email delivery failed")
			}
		}()
		return nil
	}
}

// Password grants retain IP-only matching when the request has no browser cookie.
func passwordLoginLocationObserver(issuer string, policy *browser.BrowserIDPolicy, notify func(*http.Request, string, string, string, string) error) func(http.ResponseWriter, *http.Request, string) error {
	return func(_ http.ResponseWriter, r *http.Request, subject string) error {
		ip := browser.PeerIPFromContext(r.Context())
		address, err := netip.ParseAddr(ip)
		if err != nil || address.Zone() != "" || !security.ValidHeaderText(r.UserAgent()) {
			return fosite.ErrInvalidRequest
		}
		readID := browser.BrowserID
		if policy != nil {
			readID = policy.BrowserID
		}
		id, err := readID(r, issuer)
		if err != nil {
			return fosite.ErrServerError
		}
		return notify(r, subject, id, address.String(), r.UserAgent())
	}
}
