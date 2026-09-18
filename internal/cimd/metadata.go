// Package cimd validates OAuth Client ID Metadata Documents (CIMD).
package cimd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxListEntries = 32
	maxValueLength = 2048
)

var errInvalidMetadata = errors.New("invalid client metadata document")

// Metadata is the deliberately narrow public-client subset accepted from a
// Client ID Metadata Document. Its slices are copied before leaving Fetch.
type Metadata struct {
	ID           string
	Name         string
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []string
	// AllowedResources is the optional per-client RFC 8707 allow-list. A
	// non-nil empty slice means the document explicitly denies all resources.
	AllowedResources        []string
	AllowedResourcesPresent bool
}

var knownGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"client_credentials": {},
	"password":           {},
	"refresh_token":      {},
	"urn:ietf:params:oauth:grant-type:device_code":    {},
	"urn:ietf:params:oauth:grant-type:token-exchange": {},
}

type target struct {
	raw  string
	url  *url.URL
	host string
	port string
}

func parseTarget(raw string) (target, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > maxValueLength || strings.Contains(raw, "#") {
		return target{}, errInvalidMetadata
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return target{}, errInvalidMetadata
	}
	if hasDotSegment(u.Path) || strings.Contains(u.Path, "\\") {
		return target{}, errInvalidMetadata
	}
	host := u.Hostname()
	if !validHost(host) {
		return target{}, errInvalidMetadata
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n != 443 {
			return target{}, errInvalidMetadata
		}
	}
	return target{raw: raw, url: u, host: strings.ToLower(host), port: port}, nil
}

func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func validHost(host string) bool {
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") || !ascii(host) {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if strings.HasPrefix(strings.ToLower(host), "0x") || numericDots(host) || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func ascii(value string) bool {
	for _, c := range value {
		if c > 0x7f {
			return false
		}
	}
	return true
}

func numericDots(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func decodeMetadata(raw []byte, client target) (Metadata, error) {
	return decodeMetadataWithPolicy(raw, client, Policy{})
}

func decodeMetadataWithPolicy(raw []byte, client target, policy Policy) (Metadata, error) {
	if len(raw) == 0 || !utf8.Valid(raw) || duplicateJSONKeys(raw) {
		return Metadata{}, errInvalidMetadata
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil || decoder.Decode(new(any)) != io.EOF {
		return Metadata{}, errInvalidMetadata
	}
	for key := range fields {
		switch key {
		case "client_id", "client_name", "redirect_uris", "scope", "grant_types", "response_types", "token_endpoint_auth_method", "allowed_resources":
		default:
			return Metadata{}, errInvalidMetadata
		}
	}
	id, ok := jsonString(fields, "client_id", true)
	if !ok || id != client.raw {
		return Metadata{}, errInvalidMetadata
	}
	name, ok := jsonString(fields, "client_name", false)
	if !ok || (name != "" && !validName(name)) {
		return Metadata{}, errInvalidMetadata
	}
	redirects, ok := jsonStrings(fields, "redirect_uris", true)
	if !ok || !validRedirects(redirects, client) {
		return Metadata{}, errInvalidMetadata
	}
	grants, ok := jsonStrings(fields, "grant_types", false)
	grantPresent := hasField(fields, "grant_types")
	if !ok || grantPresent && (len(grants) == 0 || !validFlowValues(grants)) {
		return Metadata{}, errInvalidMetadata
	}
	grants, ok = sanitizeGrantTypes(grants, grantPresent, policy.IgnoreUnknownAuthFlows)
	if !ok {
		return Metadata{}, errInvalidMetadata
	}
	responses, ok := jsonStrings(fields, "response_types", false)
	responsePresent := hasField(fields, "response_types")
	if !ok || responsePresent && (len(responses) != 1 || !validFlowValues(responses) || responses[0] != "code") {
		return Metadata{}, errInvalidMetadata
	}
	method, ok := jsonString(fields, "token_endpoint_auth_method", false)
	methodPresent := hasField(fields, "token_endpoint_auth_method")
	if !ok || methodPresent && (method == "" || !validFlowValue(method) || method != "none") {
		return Metadata{}, errInvalidMetadata
	}
	scope, ok := jsonString(fields, "scope", false)
	if !ok {
		return Metadata{}, errInvalidMetadata
	}
	scopes := strings.Fields(scope)
	if !validScopes(scopes) {
		return Metadata{}, errInvalidMetadata
	}
	allowedResources, ok := jsonStrings(fields, "allowed_resources", false)
	if !ok || !validAllowedResources(allowedResources) {
		return Metadata{}, errInvalidMetadata
	}
	if name == "" {
		name = id
	}
	if allowedResources != nil {
		allowedResources = append([]string{}, allowedResources...)
	}
	return Metadata{ID: id, Name: name, RedirectURIs: append([]string(nil), redirects...), Scopes: append([]string(nil), scopes...), GrantTypes: append([]string(nil), grants...), AllowedResources: allowedResources, AllowedResourcesPresent: hasField(fields, "allowed_resources")}, nil
}

func hasField(fields map[string]json.RawMessage, key string) bool {
	_, ok := fields[key]
	return ok
}

func validFlowValues(values []string) bool {
	if len(values) > maxListEntries {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validFlowValue(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validFlowValue(value string) bool {
	if value == "" || len(value) > maxValueLength || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

// sanitizeGrantTypes is intentionally the only lenient CIMD flow handling.
// Known Rauthy grants are retained for metadata fidelity, while Go's
// effective ephemeral client still narrows execution to authorization_code.
func sanitizeGrantTypes(values []string, present bool, ignore bool) ([]string, bool) {
	if !present {
		return nil, true
	}
	if !ignore {
		return values, len(values) == 1 && values[0] == "authorization_code"
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if _, known := knownGrantTypes[value]; known {
			kept = append(kept, value)
		}
	}
	return kept, containsString(kept, "authorization_code")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func jsonString(fields map[string]json.RawMessage, key string, required bool) (string, bool) {
	raw, exists := fields[key]
	if !exists {
		return "", !required
	}
	var value string
	return value, json.Unmarshal(raw, &value) == nil && string(raw) != "null"
}

func jsonStrings(fields map[string]json.RawMessage, key string, required bool) ([]string, bool) {
	raw, exists := fields[key]
	if !exists {
		return nil, !required
	}
	var values []string
	return values, json.Unmarshal(raw, &values) == nil && string(raw) != "null"
}

func validName(value string) bool {
	return value != "" && len(value) <= maxValueLength && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func validRedirects(values []string, client target) bool {
	if len(values) == 0 || len(values) > maxListEntries {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		redirect, err := parseTarget(value)
		if err != nil || redirect.host != client.host || effectivePort(redirect.port) != effectivePort(client.port) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func effectivePort(port string) string {
	if port == "" {
		return "443"
	}
	return port
}

func validScopes(values []string) bool {
	if len(values) > maxListEntries {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) == 0 || len(value) > maxValueLength {
			return false
		}
		for _, c := range value {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-') {
				return false
			}
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validAllowedResources(values []string) bool {
	if len(values) > maxListEntries {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		u, err := url.ParseRequestURI(value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !validHost(u.Hostname()) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// duplicateJSONKeys rejects duplicate object keys at every JSON depth.
func duplicateJSONKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	if duplicateJSONValue(d) != nil {
		return true
	}
	return d.Decode(new(any)) != io.EOF
}

func duplicateJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid key")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate key")
			}
			seen[name] = struct{}{}
			if err := duplicateJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := duplicateJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	return errors.New("invalid delimiter")
}
