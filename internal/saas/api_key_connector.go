package saas

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

var ErrAPIKeyConnectorConfig = errors.New("saas: invalid API-key connector configuration")

type APIKeyConnectorConfig struct {
	ID         string                  `json:"id"`
	Header     string                  `json:"header"`
	Prefix     string                  `json:"prefix"`
	Operations []APIKeyOperationConfig `json:"operations"`
}

type APIKeyOperationConfig struct {
	ID             string            `json:"id"`
	URL            string            `json:"url"`
	ResponseFields map[string]string `json:"response_fields"`
}

type APIKeyConnector struct {
	id         string
	header     string
	prefix     string
	operations map[string]APIKeyOperationConfig
	digest     string
	client     *http.Client
}

// APIKeyConnectorInfo is the credential-free contract displayed for owner consent.
// It describes this immutable connector, not whether runtime policy enables it.
type APIKeyConnectorInfo struct {
	ID         string                `json:"id"`
	Digest     string                `json:"digest"`
	Header     string                `json:"header"`
	Prefix     string                `json:"prefix"`
	Operations []APIKeyOperationInfo `json:"operations"`
}

type APIKeyOperationInfo struct {
	ID             string            `json:"id"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	ResponseFields map[string]string `json:"response_fields"`
}

// Info returns a detached copy so presentation cannot change execution or consent.
func (c *APIKeyConnector) Info() APIKeyConnectorInfo {
	if c == nil {
		return APIKeyConnectorInfo{}
	}
	info := APIKeyConnectorInfo{ID: c.id, Digest: c.digest, Header: c.header, Prefix: c.prefix,
		Operations: make([]APIKeyOperationInfo, 0, len(c.operations))}
	for _, op := range c.operations {
		info.Operations = append(info.Operations, APIKeyOperationInfo{ID: op.ID, Method: http.MethodGet, URL: op.URL, ResponseFields: maps.Clone(op.ResponseFields)})
	}
	slices.SortFunc(info.Operations, func(a, b APIKeyOperationInfo) int { return cmp.Compare(a.ID, b.ID) })
	return info
}

func NewAPIKeyConnector(cfg APIKeyConnectorConfig) (*APIKeyConnector, error) {
	if !validConnectorID(cfg.ID) || !validHeader(cfg.Header) || !validPrefix(cfg.Header, cfg.Prefix) || len(cfg.Operations) < 1 || len(cfg.Operations) > 32 {
		return nil, ErrAPIKeyConnectorConfig
	}
	ops := make(map[string]APIKeyOperationConfig, len(cfg.Operations))
	for _, op := range cfg.Operations {
		if !validConnectorID(op.ID) || !validHTTPSURL(op.URL) || len(op.ResponseFields) < 1 || len(op.ResponseFields) > 32 || ops[op.ID].ID != "" {
			return nil, ErrAPIKeyConnectorConfig
		}
		fields := make(map[string]string, len(op.ResponseFields))
		for name, typ := range op.ResponseFields {
			if !validFieldID(name) || (typ != "string" && typ != "integer" && typ != "boolean") {
				return nil, ErrAPIKeyConnectorConfig
			}
			fields[name] = typ
		}
		ops[op.ID] = APIKeyOperationConfig{ID: op.ID, URL: op.URL, ResponseFields: fields}
	}

	canonical := make([]canonicalAPIKeyOperation, 0, len(ops))
	for _, op := range ops {
		fields := make([]canonicalAPIKeyField, 0, len(op.ResponseFields))
		for name, typ := range op.ResponseFields {
			fields = append(fields, canonicalAPIKeyField{Name: name, Type: typ})
		}
		slices.SortFunc(fields, func(a, b canonicalAPIKeyField) int { return cmp.Compare(a.Name, b.Name) })
		canonical = append(canonical, canonicalAPIKeyOperation{ID: op.ID, Method: http.MethodGet, URL: op.URL, Fields: fields})
	}
	slices.SortFunc(canonical, func(a, b canonicalAPIKeyOperation) int { return cmp.Compare(a.ID, b.ID) })
	b, _ := json.Marshal(struct {
		Version string                     `json:"version"`
		Purpose string                     `json:"purpose"`
		ID      string                     `json:"id"`
		Header  string                     `json:"header"`
		Prefix  string                     `json:"prefix"`
		Ops     []canonicalAPIKeyOperation `json:"operations"`
	}{"v1", "saas-api-key-connector", cfg.ID, canonicalHeader(cfg.Header), cfg.Prefix, canonical})
	sum := sha256.Sum256(b)
	return &APIKeyConnector{id: cfg.ID, header: canonicalHeader(cfg.Header), prefix: cfg.Prefix, operations: ops, digest: base64.RawURLEncoding.EncodeToString(sum[:]), client: newSaaSHTTPClient()}, nil
}

func (c *APIKeyConnector) Digest() string {
	if c == nil {
		return ""
	}
	return c.digest
}

type canonicalAPIKeyField struct{ Name, Type string }
type canonicalAPIKeyOperation struct {
	ID, Method, URL string
	Fields          []canonicalAPIKeyField `json:"response_fields"`
}

func validConnectorID(s string) bool {
	if len(s) == 0 || len(s) > 64 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
		return false
	}
	for _, b := range []byte(s[1:]) {
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func validFieldID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, b := range []byte(s) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_') {
			return false
		}
	}
	return true
}

func canonicalHeader(s string) string {
	if strings.EqualFold(s, "authorization") {
		return "Authorization"
	}
	return "X-API-Key"
}
func validHeader(s string) bool {
	return strings.EqualFold(s, "authorization") || strings.EqualFold(s, "x-api-key")
}
func validPrefix(header, prefix string) bool {
	if strings.EqualFold(header, "x-api-key") {
		return prefix == ""
	}
	return prefix == "" || prefix == "Bearer " || prefix == "Token "
}

func validHTTPSURL(raw string) bool {
	if len(raw) == 0 || len(raw) > maxInput || strings.ContainsAny(raw, "\r\n#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" || u.Host != strings.ToLower(u.Host) {
		return false
	}
	if u.Port() != "" {
		return false
	} // explicit :443 is rejected to keep one canonical spelling
	host := u.Hostname()
	if u.Host != host || net.ParseIP(host) != nil || !validDNSName(host) {
		return false
	}
	return true
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') {
				return false
			}
		}
	}
	return true
}
