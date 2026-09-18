// Package logout validates the RP-initiated logout request before a HTTP
// handler mutates a browser session or token state.
package logout

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

var (
	ErrInvalidRequest = errors.New("invalid logout request")
	ErrInvalidHint    = errors.New("invalid ID token hint")
)

const (
	maxStateLength = 2048
	maxHintLength  = 4096
)

type Action uint8

const (
	ActionLogout Action = iota + 1
	ActionConfirm
	ActionRootRedirect
)

// Client is the small part of a registered RP required by logout.
type Client struct {
	ID                     string
	PostLogoutRedirectURIs []string
}

type Config struct {
	Issuer  string
	Keys    jose.JSONWebKeySet
	Clients []Client
	Now     func() time.Time
}

type Request struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	CurrentSubject        string
	CurrentSessionID      string
}

// Decision is safe for a handler to act on. RedirectURI already has state
// appended only after exact registered-URI validation.
type Decision struct {
	Action      Action
	ClientID    string
	Subject     string
	SessionID   string
	RedirectURI string
}

type Engine struct {
	issuer  string
	keys    jose.JSONWebKeySet
	clients map[string]map[string]struct{}
	now     func() time.Time
}

func New(config Config) (*Engine, error) {
	issuer, err := oidc.NormalizeIssuer(config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("logout issuer: %w", err)
	}
	if len(config.Keys.Keys) == 0 {
		return nil, fmt.Errorf("logout keys are required")
	}
	clients, err := validateClients(config.Clients)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Engine{issuer: issuer, keys: config.Keys, clients: clients, now: config.Now}, nil
}

func validateClients(configured []Client) (map[string]map[string]struct{}, error) {
	clients := make(map[string]map[string]struct{}, len(configured))
	for _, client := range configured {
		if client.ID == "" || clients[client.ID] != nil {
			return nil, fmt.Errorf("invalid logout client")
		}
		redirects := make(map[string]struct{}, len(client.PostLogoutRedirectURIs))
		for _, raw := range client.PostLogoutRedirectURIs {
			if !validRedirectURI(raw) {
				return nil, fmt.Errorf("invalid post logout redirect URI")
			}
			if _, exists := redirects[raw]; exists {
				return nil, fmt.Errorf("duplicate post logout redirect URI")
			}
			redirects[raw] = struct{}{}
		}
		clients[client.ID] = redirects
	}
	return clients, nil
}

// Plan applies Rauthy's logout entry rules without changing state. A valid
// hint auto-logs out when no browser session is present or it is bound to that
// session; a different browser session needs confirmation.
func (e *Engine) Plan(request Request) (Decision, error) {
	if e == nil || len(request.State) > maxStateLength || len(request.IDTokenHint) > maxHintLength || (request.CurrentSubject == "") != (request.CurrentSessionID == "") {
		return Decision{}, ErrInvalidRequest
	}
	hasSession := request.CurrentSubject != ""
	if request.IDTokenHint == "" {
		if request.ClientID != "" && e.clients[request.ClientID] == nil {
			return Decision{}, ErrInvalidRequest
		}
		if !hasSession {
			return Decision{Action: ActionRootRedirect, RedirectURI: e.issuer + "/"}, nil
		}
		redirect, err := e.redirect(request.ClientID, request.PostLogoutRedirectURI, request.State)
		if err != nil {
			return Decision{}, err
		}
		return Decision{Action: ActionConfirm, ClientID: request.ClientID, RedirectURI: redirect}, nil
	}

	clientID, claims, err := e.verifyHint(request.IDTokenHint, request.ClientID)
	if err != nil {
		return Decision{}, err
	}
	redirect, err := e.redirect(clientID, request.PostLogoutRedirectURI, request.State)
	if err != nil {
		return Decision{}, err
	}
	if hasSession && (claims.Subject != request.CurrentSubject || claims.SessionID != request.CurrentSessionID) {
		return Decision{Action: ActionConfirm, ClientID: clientID, RedirectURI: redirect}, nil
	}
	return Decision{Action: ActionLogout, ClientID: clientID, Subject: claims.Subject, SessionID: claims.SessionID, RedirectURI: redirect}, nil
}

func (e *Engine) verifyHint(hint, requestedClient string) (string, oidc.IDTokenClaims, error) {
	if requestedClient != "" && e.clients[requestedClient] == nil {
		return "", oidc.IDTokenClaims{}, ErrInvalidRequest
	}
	for clientID := range e.clients {
		if requestedClient != "" && clientID != requestedClient {
			continue
		}
		claims, err := oidc.VerifyLogoutIDToken(hint, e.keys, e.issuer, clientID, e.now().UTC())
		if err == nil && validLogoutSessionID(claims.SessionID) && claims.AuthorizedParty == clientID {
			return clientID, claims, nil
		}
	}
	return "", oidc.IDTokenClaims{}, ErrInvalidHint
}

func validLogoutSessionID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == id
}

func (e *Engine) redirect(clientID, raw, state string) (string, error) {
	if raw == "" {
		if state != "" {
			return "", ErrInvalidRequest
		}
		return "", nil
	}
	if clientID == "" || e.clients[clientID] == nil {
		return "", ErrInvalidRequest
	}
	if _, ok := e.clients[clientID][raw]; !ok {
		return "", ErrInvalidRequest
	}
	if state == "" {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrInvalidRequest
	}
	query := u.Query()
	query.Set("state", state)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func validRedirectURI(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "\r\n#") {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
