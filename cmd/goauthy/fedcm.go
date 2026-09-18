package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/fedcm"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/login"
	"github.com/mrchypark/goauthy/internal/logout"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

const (
	maxFedCMConfigFileSize = 16 << 10
	maxFedCMClients        = 16
	fedCMLandingBodyLimit  = 8 << 10
)

type fedcmFileConfig struct {
	ClientOrigins     map[string]string `json:"client_origins"`
	LoginURL          string            `json:"login_url"`
	PrivacyPolicyURL  string            `json:"privacy_policy_url,omitempty"`
	TermsOfServiceURL string            `json:"terms_of_service_url,omitempty"`
}

// fedcmRuntime contains the opt-in provider and its same-issuer account-login
// landing path. main.go mounts both only after constructing the landing.
type fedcmRuntime struct {
	handler  *fedcm.Handler
	loginURL string
}

func validateFedCMLandingPath(path string) error {
	switch path {
	case "/auth/login", "/auth/v1/account":
		return nil
	}
	return errors.New("FedCM login_url must be /auth/login or /auth/v1/account")
}

// fedCMAwareLogin preserves the existing OAuth POST route when deployments
// choose /auth/login as the FedCM landing path. The explicit marker is part of
// the rendered FedCM form, so malformed or ordinary OAuth forms retain their
// existing parser and error behavior.
func fedCMAwareLogin(landing http.Handler, legacy http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if landing == nil {
			legacy(w, r)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, fedCMLandingBodyLimit+1))
		if err != nil {
			http.Error(w, "Invalid login request", http.StatusBadRequest)
			return
		}
		if len(data) > fedCMLandingBodyLimit {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		values, parseErr := url.ParseQuery(string(data))
		if parseErr == nil && values.Get("fedcm") == "1" {
			landing.ServeHTTP(w, r)
			return
		}
		legacy(w, r)
	}
}

func fedcmRuntimeFromEnv(getenv func(string) string, db *rhiza.DB, keyring *oidc.Keyring, issuer string, browserStore *browser.Store, identities *identity.Store) (*fedcmRuntime, error) {
	if getenv == nil {
		return nil, errors.New("FedCM environment loader is not configured")
	}
	path := getenv("GOAUTHY_FEDCM_CONFIG_FILE")
	if path == "" {
		return nil, nil
	}
	if db == nil || keyring == nil || browserStore == nil || identities == nil {
		return nil, errors.New("FedCM requires Rhiza, browser, identity, and signing-key stores")
	}
	issuer, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	config, err := loadFedCMConfig(path)
	if err != nil {
		return nil, err
	}
	if err := validateFedCMLoginURL(config.LoginURL); err != nil {
		return nil, err
	}
	if err := validateFedCMLandingPath(config.LoginURL); err != nil {
		return nil, err
	}
	handler, err := fedcm.NewHandler(fedcm.Config{
		Issuer: issuer, Enabled: true, ClientOrigins: config.ClientOrigins,
		LoginURL: config.LoginURL, PrivacyPolicyURL: config.PrivacyPolicyURL,
		TermsOfServiceURL: config.TermsOfServiceURL,
		ResolveCurrent: func(ctx context.Context, r *http.Request) (fedcm.Account, error) {
			return resolveFedCMCurrent(ctx, r, browserStore, identities)
		},
		ResolveAccount: func(ctx context.Context, subject string) (fedcm.Account, error) {
			return resolveFedCMSubject(ctx, subject, identities)
		},
		LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) {
			return oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure FedCM: %w", err)
	}
	return &fedcmRuntime{handler: handler, loginURL: config.LoginURL}, nil
}

func (r *fedcmRuntime) enableBrowserCookies(loginHandler *login.Handler, logoutHandler *logout.Handler) error {
	if r == nil || r.handler == nil || loginHandler == nil || logoutHandler == nil {
		return errors.New("FedCM runtime is not configured")
	}
	if err := loginHandler.EnableFedCM(true); err != nil {
		return err
	}
	if err := logoutHandler.EnableFedCM(true); err != nil {
		_ = loginHandler.EnableFedCM(false)
		return err
	}
	return nil
}

func loadFedCMConfig(path string) (fedcmFileConfig, error) {
	if path == "" {
		return fedcmFileConfig{}, errors.New("FedCM config file path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return fedcmFileConfig{}, fmt.Errorf("open FedCM config file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFedCMConfigFileSize+1))
	if err != nil {
		return fedcmFileConfig{}, fmt.Errorf("read FedCM config file: %w", err)
	}
	if len(data) > maxFedCMConfigFileSize {
		return fedcmFileConfig{}, fmt.Errorf("FedCM config file exceeds %d bytes", maxFedCMConfigFileSize)
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return fedcmFileConfig{}, errors.New("FedCM config file contains duplicate JSON fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config fedcmFileConfig
	if err := decoder.Decode(&config); err != nil {
		return fedcmFileConfig{}, fmt.Errorf("decode FedCM config file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fedcmFileConfig{}, errors.New("FedCM config file must contain exactly one JSON object")
	}
	if len(config.ClientOrigins) == 0 || len(config.ClientOrigins) > maxFedCMClients {
		return fedcmFileConfig{}, fmt.Errorf("FedCM client_origins must contain 1 to %d clients", maxFedCMClients)
	}
	for clientID, origin := range config.ClientOrigins {
		if !fedCMClientID(clientID) || !fedCMOrigin(origin) {
			return fedcmFileConfig{}, errors.New("FedCM client_origins contains an invalid client binding")
		}
	}
	if err := validateFedCMLoginURL(config.LoginURL); err != nil {
		return fedcmFileConfig{}, err
	}
	if len(config.PrivacyPolicyURL) > 2048 || len(config.TermsOfServiceURL) > 2048 {
		return fedcmFileConfig{}, errors.New("FedCM policy URL is too long")
	}
	return config, nil
}

func validateFedCMLoginURL(raw string) error {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return errors.New("FedCM login_url must be an explicit same-issuer path")
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") {
		return errors.New("FedCM login_url must be an explicit same-issuer path")
	}
	for _, segment := range strings.Split(u.Path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("FedCM login_url path is not canonical")
		}
	}
	return nil
}

func resolveFedCMCurrent(ctx context.Context, r *http.Request, sessions *browser.Store, identities *identity.Store) (fedcm.Account, error) {
	if r == nil || sessions == nil || identities == nil || browser.PeerIPFromContext(ctx) == "" {
		return fedcm.Account{}, errors.New("FedCM session unavailable")
	}
	cookie, ok := fedCMSessionCookie(r)
	if !ok {
		return fedcm.Account{}, errors.New("FedCM session unavailable")
	}
	session, err := sessions.LoadSessionReadOnlyForPeer(ctx, cookie.Value, browser.PeerIPFromContext(ctx))
	// FedCM is a cross-site credential boundary. Legacy sessions created before
	// peer binding (empty PeerIP) must never be promoted into that boundary,
	// even though the general browser session compatibility path accepts them.
	if err != nil || session.PeerIP == "" || !session.Authenticated() {
		return fedcm.Account{}, errors.New("FedCM session unavailable")
	}
	return resolveFedCMSubject(ctx, session.Subject, identities)
}

func fedCMSessionCookie(r *http.Request) (*http.Cookie, bool) {
	if r == nil {
		return nil, false
	}
	var found *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != browser.FedCMSessionCookieName {
			continue
		}
		if found != nil || cookie.Value == "" {
			return nil, false
		}
		found = cookie
	}
	return found, found != nil
}

func resolveFedCMSubject(ctx context.Context, subject string, identities *identity.Store) (fedcm.Account, error) {
	if identities == nil {
		return fedcm.Account{}, errors.New("FedCM account unavailable")
	}
	profile, err := identities.AccountProfileBySubject(ctx, subject)
	if err != nil || profile.Email == "" {
		return fedcm.Account{}, errors.New("FedCM account unavailable")
	}
	name := profile.PreferredUsername
	if name == "" {
		name = profile.Username
	}
	if !fedCMText(name) || !fedCMText(profile.Email) || !fedCMText(profile.Subject) ||
		(profile.GivenName != "" && !fedCMText(profile.GivenName)) {
		return fedcm.Account{}, errors.New("FedCM account unavailable")
	}
	return fedcm.Account{ID: profile.Subject, Name: name, Email: profile.Email, GivenName: profile.GivenName}, nil
}

func fedCMClientID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}

func fedCMOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func fedCMText(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}
