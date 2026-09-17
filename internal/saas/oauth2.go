package saas

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

var ErrOAuth2Config = errors.New("saas: invalid OAuth2 configuration")
var ErrOAuth2Exchange = errors.New("saas: OAuth2 exchange failed")

// OAuth2Config describes a trusted administrator-configured provider, not a
// user-supplied proxy destination. Secrets are supplied separately.
type OAuth2Config struct {
	ClientID         string
	AuthorizationURL string
	TokenURL         string
	CallbackURL      string
	Scopes           []string
	AuthStyle        oauth2.AuthStyle
	IdentityEndpoint string
	SubjectField     string
}

// OAuth2 performs protocol exchanges only. Callers must persist consent/state,
// verify callback binding, and coordinate refresh ownership before calling it.
// Returned tokens must be committed before use; no automatic refresh client is exposed.
type OAuth2 struct {
	config           oauth2.Config
	identityEndpoint string
	subjectField     string
	client           *http.Client
}

func NewOAuth2(cfg OAuth2Config, clientSecret string) (*OAuth2, error) {
	if !validText(cfg.ClientID) || !validText(clientSecret) || !validCallback(cfg.CallbackURL) || !oauthEndpoint(cfg.AuthorizationURL) || !oauthEndpoint(cfg.TokenURL) || len(cfg.Scopes) == 0 || len(cfg.Scopes) > 64 {
		return nil, ErrOAuth2Config
	}
	if (cfg.IdentityEndpoint == "") != (cfg.SubjectField == "") || cfg.IdentityEndpoint != "" && (!oauthEndpoint(cfg.IdentityEndpoint) || !validSubjectField(cfg.SubjectField)) {
		return nil, ErrOAuth2Config
	}
	// Auto-detection can retry a consumed authorization code. Require explicit auth.
	if cfg.AuthStyle != oauth2.AuthStyleInHeader && cfg.AuthStyle != oauth2.AuthStyleInParams {
		return nil, ErrOAuth2Config
	}
	seen := map[string]bool{}
	for _, scope := range cfg.Scopes {
		if scope == "" || len(scope) > 256 || seen[scope] {
			return nil, ErrOAuth2Config
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return nil, ErrOAuth2Config
			}
		}
		seen[scope] = true
	}
	return &OAuth2{config: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: clientSecret, RedirectURL: cfg.CallbackURL, Scopes: append([]string(nil), cfg.Scopes...), Endpoint: oauth2.Endpoint{AuthURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, AuthStyle: cfg.AuthStyle}}, identityEndpoint: cfg.IdentityEndpoint, subjectField: cfg.SubjectField, client: newSaaSHTTPClient()}, nil
}

func validSubjectField(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func oauthEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= maxInput && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
}

func withHTTPClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func (o *OAuth2) AuthorizationURL(state, verifier string) (string, error) {
	if o == nil || !validState(state) || !validVerifier(verifier) {
		return "", ErrOAuth2Exchange
	}
	return o.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

func (o *OAuth2) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if o == nil || ctx == nil || !validText(code) || !validVerifier(verifier) {
		return nil, ErrOAuth2Exchange
	}
	token, err := o.config.Exchange(withHTTPClient(ctx, o.client), code, oauth2.VerifierOption(verifier))
	return oauthResult(ctx, token, err)
}

// Refresh makes one explicit refresh attempt. It must only be called after a
// durable claim; timeout/unknown outcome does not authorize another attempt.
func (o *OAuth2) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if o == nil || ctx == nil || !validText(refreshToken) {
		return nil, ErrOAuth2Exchange
	}
	token, err := o.config.TokenSource(withHTTPClient(ctx, o.client), &oauth2.Token{RefreshToken: refreshToken}).Token()
	return oauthResult(ctx, token, err)
}

func oauthResult(ctx context.Context, token *oauth2.Token, err error) (*oauth2.Token, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || token == nil || !validText(token.AccessToken) || !strings.EqualFold(token.TokenType, "Bearer") {
		return nil, ErrOAuth2Exchange
	}
	return token, nil
}
