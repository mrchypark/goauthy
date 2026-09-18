package saas

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var ErrOAuth2Identity = errors.New("saas: OAuth2 identity lookup failed")

func (o *OAuth2) Identity(ctx context.Context, accessToken string) (string, error) {
	if o == nil || ctx == nil || !validText(accessToken) || o.identityEndpoint == "" || o.subjectField == "" {
		return "", ErrOAuth2Identity
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.identityEndpoint, nil)
	if err != nil {
		return "", ErrOAuth2Identity
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", ErrOAuth2Identity
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !jsonMediaType(resp.Header.Get("Content-Type")) {
		return "", ErrOAuth2Identity
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(body) > 64<<10 {
		return "", ErrOAuth2Identity
	}
	values, err := decodeAPIKeyObject(body)
	if err != nil {
		return "", ErrOAuth2Identity
	}
	raw, ok := values[o.subjectField]
	if !ok {
		return "", ErrOAuth2Identity
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return "", ErrOAuth2Identity
	}
	if raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) != nil || value == "" || !validText(value) {
			return "", ErrOAuth2Identity
		}
		return value, nil
	}
	if (raw[0] >= '0' && raw[0] <= '9') || raw[0] == '-' {
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(raw) {
			return "", ErrOAuth2Identity
		}
		return string(raw), nil
	}
	return "", ErrOAuth2Identity
}
