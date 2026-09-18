package upstreamprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	json "github.com/go-json-experiment/json"
)

const userinfoMaxBytes = 64 << 10 // 64 KiB

// exchangeOAuthUserInfo exchanges an access token for a userinfo-subject
// via the provider's UserInfoEndpoint. It is used exclusively by the
// ProviderKindOAuthUserInfo flow and ignores any id_token in the token
// response.
func (e *OAuth2TokenExchanger) exchangeOAuthUserInfo(ctx context.Context, providerID string, cfg Config, accessToken string) (*TokenExchangeResult, error) {
	if accessToken == "" {
		return nil, errTokenExchange
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserInfoEndpoint, nil)
	if err != nil {
		return nil, errTokenExchange
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTokenExchange
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errTokenExchange
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, userinfoMaxBytes+1))
	if err != nil || len(body) > userinfoMaxBytes {
		return nil, errTokenExchange
	}
	if !utf8.Valid(body) {
		return nil, errTokenExchange
	}
	sub, err := parseUserInfoSub(body)
	if err != nil {
		return nil, errTokenExchange
	}
	subject := SubjectResult{ProviderID: providerID, Subject: sub}
	if err := subject.Validate(); err != nil {
		return nil, errTokenExchange
	}
	return &TokenExchangeResult{Subject: &subject}, nil
}

// userinfoSub is the strict JSON target for userinfo responses.
// The json package rejects duplicate names, invalid UTF-8, trailing
// data, and unpaired UTF-16 surrogate escapes by default (RFC 7493).
type userinfoSub struct {
	Sub string `json:"sub"`
}

// parseUserInfoSub extracts a unique non-empty "sub" string from a single
// JSON object. It uses the go-json-experiment/json decoder which enforces
// RFC 7493: rejects invalid UTF-8, duplicate object names, trailing data,
// and unpaired UTF-16 surrogate escapes.
func parseUserInfoSub(body []byte) (string, error) {
	var v userinfoSub
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	if v.Sub == "" {
		return "", errors.New("missing or empty sub in userinfo")
	}
	return v.Sub, nil
}
