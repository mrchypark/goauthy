package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

var ErrAPIKeyRequest = errors.New("saas: API-key request failed")

const (
	maxAPIKeyResponseBody = 64 << 10
	maxAPIKeyString       = 4096
)

func (c *APIKeyConnector) request(ctx context.Context, operation string, value credential) (map[string]json.RawMessage, error) {
	if ctx == nil || c == nil || !validCredential(value) || !validateAPIKey(value.APIKey) || value.ConnectorDigest == "" || value.ConnectorDigest != c.digest {
		return nil, ErrAPIKeyRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	op, ok := c.operations[operation]
	if !ok || c.client == nil {
		return nil, ErrAPIKeyRequest
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, op.URL, nil)
	if err != nil {
		return nil, ErrAPIKeyRequest
	}
	req.Header.Set(c.header, c.prefix+value.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GoAuthy-SaaS/0.1")
	resp, err := c.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrAPIKeyRequest
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !jsonMediaType(resp.Header.Get("Content-Type")) {
		return nil, ErrAPIKeyRequest
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIKeyResponseBody+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrAPIKeyRequest
	}
	if len(body) > maxAPIKeyResponseBody {
		return nil, ErrAPIKeyRequest
	}
	values, err := decodeAPIKeyObject(body)
	if err != nil {
		return nil, ErrAPIKeyRequest
	}
	out := make(map[string]json.RawMessage, len(op.ResponseFields))
	for name, typ := range op.ResponseFields {
		raw, ok := values[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, ErrAPIKeyRequest
		}
		clean, err := validateAPIKeyResponseValue(raw, typ, value.APIKey)
		if err != nil {
			return nil, ErrAPIKeyRequest
		}
		out[name] = clean
	}
	return out, nil
}

func jsonMediaType(header string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

func decodeAPIKeyObject(body []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("not an object")
	}
	values := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid field")
		}
		if _, exists := values[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		values[name] = raw
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON")
		}
		return nil, err
	}
	return values, nil
}

func validateAPIKeyResponseValue(raw json.RawMessage, typ, key string) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	switch typ {
	case "string":
		var value string
		if len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(trimmed, &value) != nil || len([]byte(value)) > maxAPIKeyString || strings.Contains(value, key) {
			return nil, errors.New("invalid string")
		}
		return json.Marshal(value)
	case "integer":
		if len(trimmed) == 0 || (trimmed[0] == '-' && len(trimmed) == 1) {
			return nil, errors.New("invalid integer")
		}
		for i, b := range trimmed {
			if (b < '0' || b > '9') && !(i == 0 && b == '-') {
				return nil, errors.New("invalid integer")
			}
		}
		if len(trimmed) > 1 && trimmed[0] == '0' || len(trimmed) > 2 && trimmed[0] == '-' && trimmed[1] == '0' {
			return nil, errors.New("invalid integer")
		}
		value, err := strconv.ParseInt(string(trimmed), 10, 64)
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatInt(value, 10)), nil
	case "boolean":
		if bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false")) {
			return append(json.RawMessage(nil), trimmed...), nil
		}
	}
	return nil, errors.New("invalid type")
}
