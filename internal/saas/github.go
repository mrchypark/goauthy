package saas

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubAPIURL       = "https://api.github.com"
	githubAPIVersion   = "2022-11-28"
	githubAccept       = "application/vnd.github+json"
	githubMaxBody      = 1 << 20
	maxInput           = 2048
)

var (
	errGitHubConfig   = errors.New("github: invalid configuration")
	errGitHubInput    = errors.New("github: invalid input")
	errGitHubRequest  = errors.New("github: request failed")
	errGitHubResponse = errors.New("github: invalid response")
	errGitHubRedirect = errors.New("github: redirect rejected")
)

type GitHub struct {
	clientID, clientSecret string
	oauth                  *OAuth2
	client                 *http.Client
}

type GitHubUser struct {
	ID string `json:"id"`
}

func NewGitHub(clientID, clientSecret, callbackURI string) (*GitHub, error) {
	if !validText(clientID) || !validText(clientSecret) || !validCallback(callbackURI) {
		return nil, errGitHubConfig
	}
	oauth, err := NewOAuth2(OAuth2Config{
		ClientID: clientID, AuthorizationURL: githubAuthorizeURL,
		TokenURL: githubTokenURL, CallbackURL: callbackURI,
		Scopes: []string{"read:user", "offline_access"}, AuthStyle: oauth2.AuthStyleInParams,
	}, clientSecret)
	if err != nil {
		return nil, errGitHubConfig
	}
	return &GitHub{clientID: clientID, clientSecret: clientSecret, oauth: oauth, client: oauth.client}, nil
}

func (g *GitHub) AuthorizationURL(state, verifier string) (string, error) {
	if g == nil || !validState(state) || !validVerifier(verifier) {
		return "", errGitHubInput
	}
	return g.oauth.AuthorizationURL(state, verifier)
}

func (g *GitHub) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if g == nil || !validText(code) || !validVerifier(verifier) {
		return nil, errGitHubInput
	}
	ctx = nonNilContext(ctx)
	t, err := g.oauth.Exchange(ctx, code, verifier)
	if err != nil {
		return nil, githubErr(ctx, err)
	}
	if !validToken(t) {
		return nil, errGitHubResponse
	}
	return t, nil
}

func (g *GitHub) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if g == nil || !validText(refreshToken) {
		return nil, errGitHubInput
	}
	ctx = nonNilContext(ctx)
	t, err := g.oauth.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, githubErr(ctx, err)
	}
	if !validToken(t) {
		return nil, errGitHubResponse
	}
	return t, nil
}

func (g *GitHub) User(ctx context.Context, accessToken string) (GitHubUser, error) {
	if g == nil || !validText(accessToken) {
		return GitHubUser{}, errGitHubInput
	}
	ctx = nonNilContext(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIURL+"/user", nil)
	if err != nil {
		return GitHubUser{}, errGitHubRequest
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", githubAccept)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	resp, err := g.client.Do(req)
	if err != nil {
		return GitHubUser{}, githubErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return GitHubUser{}, errGitHubResponse
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, githubMaxBody+1))
	if err != nil || len(body) > githubMaxBody {
		return GitHubUser{}, errGitHubResponse
	}
	id, ok := parseUserID(body)
	if !ok {
		return GitHubUser{}, errGitHubResponse
	}
	return GitHubUser{ID: id}, nil
}

func (g *GitHub) Revoke(ctx context.Context, accessToken string) error {
	if g == nil || !validText(accessToken) {
		return errGitHubInput
	}
	ctx = nonNilContext(ctx)
	u := githubAPIURL + "/applications/" + url.PathEscape(g.clientID) + "/token"
	payload, err := json.Marshal(map[string]string{"access_token": accessToken})
	if err != nil {
		return errGitHubInput
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, strings.NewReader(string(payload)))
	if err != nil {
		return errGitHubRequest
	}
	req.SetBasicAuth(g.clientID, g.clientSecret)
	req.Header.Set("Accept", githubAccept)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return githubErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errGitHubResponse
	}
	return nil
}

func githubErr(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errGitHubRequest
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func validText(s string) bool {
	return s != "" && len(s) <= maxInput && !strings.ContainsAny(s, "\r\n")
}
func validState(s string) bool { return len(s) >= 1 && len(s) <= 512 && validText(s) }
func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 || !validText(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !verifierChar(s[i]) {
			return false
		}
	}
	return true
}

func verifierChar(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))
}

func validCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validToken(t *oauth2.Token) bool {
	if t == nil || !validText(t.AccessToken) || !strings.EqualFold(t.TokenType, "bearer") || !hasScope(t.Extra("scope")) {
		return false
	}
	return t.Expiry.IsZero() || t.Expiry.After(time.Now())
}
func hasScope(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if p == "read:user" {
			return true
		}
	}
	return false
}
func canonicalID(raw []byte) bool {
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for _, b := range raw[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return len(raw) <= 128
}

func parseUserID(body []byte) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", false
	}
	var id []byte
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "", false
		}
		name, ok := key.(string)
		if !ok {
			return "", false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", false
		}
		if name == "id" {
			if id != nil || !canonicalID(value) {
				return "", false
			}
			id = append([]byte(nil), value...)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') || id == nil {
		return "", false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return "", false
	}
	return string(id), true
}
