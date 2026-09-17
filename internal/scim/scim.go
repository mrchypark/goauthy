// Package scim contains the small, stateless outbound SCIM user boundary.
//
// It deliberately does not own local identity storage or an outbox. The
// integration layer must serialize and durably deduplicate create work before
// retrying it; full scans and durable retry/coalescing need that layer too.
package scim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultResponseLimit = 64 << 10
	defaultTimeout       = 10 * time.Second
	maxIdentifierBytes   = 512
	usersPath            = "/Users"
	userSchema           = "urn:ietf:params:scim:schemas:core:2.0:User"
	listResponseSchema   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
)

var (
	ErrInvalidConfig = errors.New("scim: invalid client configuration")
	ErrInvalidUser   = errors.New("scim: invalid user")
	ErrProtocol      = errors.New("scim: invalid response")
	// ErrRetryable is a sanitized transport/status failure that the durable
	// outbox may retry. TLS certificate failures are retryable too: a corrected
	// trust bundle or rotated provider certificate can make the same job valid.
	ErrRetryable         = errors.New("scim: retryable remote failure")
	ErrAmbiguous         = errors.New("scim: ambiguous user match")
	ErrIdentifierChanged = errors.New("scim: immutable externalId changed")
)

// User is the intentionally narrow SCIM User projection used by the core.
// ExternalID and UserName are exact, case-sensitive identifiers.
type User struct {
	Schemas    []string `json:"schemas,omitempty"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId"`
	UserName   string   `json:"userName"`
	Active     bool     `json:"active"`
}

// DeletePolicy controls what a delete request does to a matched remote user.
type DeletePolicy uint8

const (
	DeleteRemote DeletePolicy = iota + 1
	UnlinkRemote
)

// Request describes one reconciliation operation. Set Delete for a local
// deletion; User still supplies the immutable identity used to find the
// remote record. Create retries must be serialized and deduplicated by the
// caller because SCIM POST has no idempotency key here.
type Request struct {
	User         User
	Group        Group
	Delete       bool
	DeletePolicy DeletePolicy
	remoteID     string // set only from the provider-scoped mapping store
}

// Action is the externally observable result of one reconciliation attempt.
type Action string

const (
	ActionCreated   Action = "created"
	ActionUpdated   Action = "updated"
	ActionUnchanged Action = "unchanged"
	ActionDeleted   Action = "deleted"
	ActionUnlinked  Action = "unlinked"
	ActionNoop      Action = "noop"
)

// Result is explicit so callers do not infer state from an error or HTTP
// status. RemoteID is set when the provider supplied one.
type Result struct {
	Action   Action
	RemoteID string
}

// Config configures an outbound SCIM client. HTTPClient is cloned and never
// mutated. RootCAs optionally replaces the TLS root pool on the cloned secure
// transport. A nil HTTPClient gets a transport with proxy use disabled. A
// custom non-*http.Transport RoundTripper is retained as a trusted
// operator/test seam only when RootCAs is unset; the default transport owns
// the proxy/TLS policy.
type Config struct {
	BaseURL          string
	Token            string
	HTTPClient       *http.Client
	RootCAs          *x509.CertPool
	MaxResponseBytes int
}

// Client performs bounded user-only SCIM operations.
type Client struct {
	baseURL          *url.URL
	httpClient       *http.Client
	token            string
	maxResponseBytes int
}

// New creates a client with HTTPS, no-redirect, and bounded-response policy.
func New(cfg Config) (*Client, error) {
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil || !validToken(cfg.Token) {
		return nil, ErrInvalidConfig
	}
	limit := cfg.MaxResponseBytes
	if limit == 0 {
		limit = defaultResponseLimit
	}
	if limit < 1 || limit > 1<<20 {
		return nil, ErrInvalidConfig
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: secureTransport(cfg.RootCAs), Timeout: defaultTimeout}
	} else {
		copy := *hc
		hc = &copy
		if hc.Transport == nil {
			hc.Transport = secureTransport(cfg.RootCAs)
		} else if transport, ok := hc.Transport.(*http.Transport); ok {
			if transport.DialTLS != nil || transport.DialTLSContext != nil {
				return nil, ErrInvalidConfig
			}
			hc.Transport = secureTransportFrom(transport, cfg.RootCAs)
		} else if cfg.RootCAs != nil {
			return nil, ErrInvalidConfig
		}
		if hc.Timeout == 0 || hc.Timeout > defaultTimeout {
			hc.Timeout = defaultTimeout
		}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{baseURL: base, httpClient: hc, token: cfg.Token, maxResponseBytes: limit}, nil
}

func secureTransport(rootCAs *x509.CertPool) *http.Transport {
	return secureTransportFrom(http.DefaultTransport.(*http.Transport), rootCAs)
}

func secureTransportFrom(source *http.Transport, rootCAs *x509.CertPool) *http.Transport {
	transport := source.Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig.InsecureSkipVerify = false
	transport.TLSClientConfig.ServerName = ""
	if rootCAs != nil {
		transport.TLSClientConfig.RootCAs = rootCAs.Clone()
	}
	return transport
}

// NewClient is the compact constructor for callers that do not need Config.
func NewClient(baseURL, token string, httpClient *http.Client) (*Client, error) {
	return New(Config{BaseURL: baseURL, Token: token, HTTPClient: httpClient})
}

// SyncUser reconciles one desired user (create, update, or unchanged).
func (c *Client) SyncUser(ctx context.Context, user User) (Result, error) {
	return c.Reconcile(ctx, Request{User: user})
}

// DeleteUser reconciles one deletion under an explicit delete-or-unlink
// policy. Unlink is a stateless outcome: no remote record is deleted.
func (c *Client) DeleteUser(ctx context.Context, user User, policy DeletePolicy) (Result, error) {
	return c.Reconcile(ctx, Request{User: user, Delete: true, DeletePolicy: policy})
}

// Reconcile performs one stateless operation. It first searches by
// externalId and only then uses an exact userName filter as a safe fallback.
func (c *Client) Reconcile(ctx context.Context, req Request) (Result, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return Result{}, ErrInvalidConfig
	}
	if req.Group.ExternalID != "" {
		return c.ReconcileGroup(ctx, GroupRequest{Group: req.Group, Delete: req.Delete, DeletePolicy: req.DeletePolicy})
	}
	if err := validateUser(req.User); err != nil {
		return Result{}, err
	}
	if req.Delete && req.DeletePolicy != DeleteRemote && req.DeletePolicy != UnlinkRemote {
		return Result{}, ErrInvalidConfig
	}
	var remote User
	var found bool
	var err error
	if req.remoteID != "" {
		remote, found, err = c.getUser(ctx, req.remoteID)
		if err == nil && found && remote.ExternalID != req.User.ExternalID {
			return Result{}, ErrIdentifierChanged
		}
	} else {
		remote, found, err = c.find(ctx, req.User)
	}
	if err != nil {
		return Result{}, err
	}
	if req.Delete {
		if !found {
			return Result{Action: ActionNoop}, nil
		}
		if req.DeletePolicy == UnlinkRemote {
			missing, err := c.unlinkUser(ctx, remote.ID)
			if err != nil {
				return Result{}, err
			}
			if missing {
				return Result{Action: ActionNoop}, nil
			}
			return Result{Action: ActionUnlinked, RemoteID: remote.ID}, nil
		}
		missing, err := c.deleteUser(ctx, remote.ID)
		if err != nil {
			return Result{}, err
		}
		if missing {
			return Result{Action: ActionNoop}, nil
		}
		return Result{Action: ActionDeleted, RemoteID: remote.ID}, nil
	}
	if !found {
		created, err := c.doUser(ctx, http.MethodPost, "", req.User)
		if err != nil {
			return Result{}, err
		}
		return Result{Action: ActionCreated, RemoteID: created.ID}, nil
	}
	if sameUser(remote, req.User) {
		return Result{Action: ActionUnchanged, RemoteID: remote.ID}, nil
	}
	updated, err := c.doUser(ctx, http.MethodPut, remote.ID, req.User)
	if err != nil {
		return Result{}, err
	}
	if updated.ExternalID != "" && updated.ExternalID != req.User.ExternalID {
		return Result{}, ErrIdentifierChanged
	}
	if updated.ID != "" && updated.ID != remote.ID {
		return Result{}, ErrIdentifierChanged
	}
	return Result{Action: ActionUpdated, RemoteID: remote.ID}, nil
}

func (c *Client) getUser(ctx context.Context, id string) (User, bool, error) {
	if err := validRemoteID(id); err != nil {
		return User{}, false, err
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + usersPath + "/" + id
	u.RawPath = ""
	resp, err := c.request(ctx, http.MethodGet, &u, nil)
	if err != nil {
		return User{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return User{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return User{}, false, responseStatusError(resp.StatusCode)
	}
	if !jsonContentType(resp.Header.Get("Content-Type")) {
		return User{}, false, ErrProtocol
	}
	body, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return User{}, false, err
	}
	var user User
	if err := decodeJSON(body, &user); err != nil || validateRemoteUser(user) != nil || user.ID != id {
		return User{}, false, ErrProtocol
	}
	return user, true, nil
}

func (c *Client) unlinkUser(ctx context.Context, id string) (bool, error) {
	body, err := json.Marshal(struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op   string `json:"op"`
			Path string `json:"path"`
		} `json:"Operations"`
	}{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, Operations: []struct {
		Op   string `json:"op"`
		Path string `json:"path"`
	}{{Op: "remove", Path: "externalId"}}})
	if err != nil {
		return false, ErrProtocol
	}
	return c.deleteOrUnlink(ctx, http.MethodPatch, id, body)
}

func (c *Client) deleteUser(ctx context.Context, id string) (bool, error) {
	return c.deleteOrUnlink(ctx, http.MethodDelete, id, nil)
}

// deleteOrUnlink returns missing when the provider confirms that the target
// disappeared between lookup and mutation.
func (c *Client) deleteOrUnlink(ctx context.Context, method, id string, body []byte) (bool, error) {
	if err := validRemoteID(id); err != nil {
		return false, err
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + usersPath + "/" + id
	u.RawPath = ""
	resp, err := c.request(ctx, method, &u, body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}
	if method == http.MethodDelete {
		if resp.StatusCode != http.StatusNoContent {
			return false, responseStatusError(resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return false, responseStatusError(resp.StatusCode)
	}
	data, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return false, err
	}
	if !validOptionalJSON(data, resp.Header.Get("Content-Type")) {
		return false, ErrProtocol
	}
	if method == http.MethodPatch && len(data) != 0 {
		var user User
		if err := decodeJSON(data, &user); err != nil || user.ID != id || user.ExternalID != "" || user.UserName == "" {
			return false, ErrProtocol
		}
	}
	return false, nil
}

func (c *Client) find(ctx context.Context, user User) (User, bool, error) {
	resources, err := c.list(ctx, "externalId", user.ExternalID)
	if err != nil {
		return User{}, false, err
	}
	if len(resources) > 1 {
		return User{}, false, ErrAmbiguous
	}
	if len(resources) == 1 {
		if resources[0].ExternalID != user.ExternalID {
			return User{}, false, ErrIdentifierChanged
		}
		return resources[0], true, nil
	}
	resources, err = c.list(ctx, "userName", user.UserName)
	if err != nil {
		return User{}, false, err
	}
	if len(resources) > 1 {
		return User{}, false, ErrAmbiguous
	}
	if len(resources) == 0 {
		return User{}, false, nil
	}
	if resources[0].UserName != user.UserName || resources[0].ExternalID != user.ExternalID {
		return User{}, false, ErrIdentifierChanged
	}
	return resources[0], true, nil
}

func (c *Client) list(ctx context.Context, field, value string) ([]User, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + usersPath
	u.RawPath = ""
	q := u.Query()
	q.Set("filter", field+` eq "`+escapeFilter(value)+`"`)
	q.Set("startIndex", "1")
	q.Set("count", "100")
	u.RawQuery = q.Encode()
	resp, err := c.request(ctx, http.MethodGet, &u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, responseStatusError(resp.StatusCode)
	}
	if !jsonContentType(resp.Header.Get("Content-Type")) {
		return nil, ErrProtocol
	}
	body, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return nil, err
	}
	var page listResponse
	if err := decodeJSON(body, &page); err != nil || !hasSchema(page.Schemas, listResponseSchema) || page.TotalResults == nil || *page.TotalResults < 0 {
		return nil, ErrProtocol
	}
	if page.StartIndex != nil && *page.StartIndex != 1 {
		return nil, ErrProtocol
	}
	if page.ItemsPerPage != nil && *page.ItemsPerPage < 0 {
		return nil, ErrProtocol
	}
	if *page.TotalResults == 0 && len(page.Resources) != 0 {
		return nil, ErrProtocol
	}
	if *page.TotalResults == 1 && len(page.Resources) != 1 {
		return nil, ErrProtocol
	}
	if page.ItemsPerPage != nil && *page.TotalResults <= 1 && *page.ItemsPerPage != len(page.Resources) {
		return nil, ErrProtocol
	}
	if *page.TotalResults > 1 {
		return nil, ErrAmbiguous
	}
	for i := range page.Resources {
		if err := validateRemoteUser(page.Resources[i]); err != nil {
			return nil, err
		}
	}
	return page.Resources, nil
}

type listResponse struct {
	Schemas      []string `json:"schemas"`
	Resources    []User   `json:"Resources"`
	TotalResults *int     `json:"totalResults"`
	StartIndex   *int     `json:"startIndex"`
	ItemsPerPage *int     `json:"itemsPerPage"`
}

func (c *Client) doUser(ctx context.Context, method, id string, user User) (User, error) {
	body, err := json.Marshal(struct {
		Schemas    []string `json:"schemas"`
		ExternalID string   `json:"externalId"`
		UserName   string   `json:"userName"`
		Active     bool     `json:"active"`
	}{[]string{userSchema}, user.ExternalID, user.UserName, user.Active})
	if err != nil {
		return User{}, ErrInvalidUser
	}
	resp, err := c.do(ctx, method, id, body)
	if err != nil {
		return User{}, err
	}
	if method == http.MethodPost {
		if resp.ExternalID == "" && resp.UserName == "" {
			if resp.ID == "" {
				return User{}, ErrProtocol
			}
			return resp, nil // bodyless 201 derives the ID from Location
		}
		if resp.ExternalID != user.ExternalID || resp.UserName != user.UserName {
			return User{}, ErrIdentifierChanged
		}
		if resp.Active != user.Active {
			return User{}, ErrProtocol
		}
		return resp, nil
	}
	if resp.ID == id && resp.ExternalID == "" && resp.UserName == "" {
		return resp, nil // bodyless 204 is a valid update acknowledgement
	}
	if resp.ID != id || resp.ExternalID != user.ExternalID || resp.UserName != user.UserName {
		return User{}, ErrIdentifierChanged
	}
	if resp.Active != user.Active {
		return User{}, ErrProtocol
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, method, id string, body []byte) (User, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + usersPath
	if id != "" {
		if err := validRemoteID(id); err != nil {
			return User{}, err
		}
		u.Path += "/" + id
	}
	u.RawPath = ""
	resp, err := c.request(ctx, method, &u, body)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()
	if method == http.MethodDelete {
		if resp.StatusCode != http.StatusNoContent {
			return User{}, responseStatusError(resp.StatusCode)
		}
		data, err := boundedBody(resp.Body, c.maxResponseBytes)
		if err != nil {
			return User{}, err
		}
		if !validOptionalJSON(data, resp.Header.Get("Content-Type")) {
			return User{}, ErrProtocol
		}
		return User{}, nil
	}
	if method == http.MethodPost {
		if resp.StatusCode != http.StatusCreated {
			return User{}, responseStatusError(resp.StatusCode)
		}
	} else if method == http.MethodPut && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return User{}, responseStatusError(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNoContent {
		data, err := boundedBody(resp.Body, c.maxResponseBytes)
		if err != nil {
			return User{}, err
		}
		if !validOptionalJSON(data, resp.Header.Get("Content-Type")) {
			return User{}, ErrProtocol
		}
		if len(data) > 0 {
			var user User
			if err := decodeJSON(data, &user); err != nil || validateRemoteUser(user) != nil {
				return User{}, ErrProtocol
			}
			return user, nil
		}
		return User{ID: id}, nil
	}
	data, err := boundedBody(resp.Body, c.maxResponseBytes)
	if err != nil {
		return User{}, err
	}
	if len(data) == 0 && method == http.MethodPost {
		id, err := c.locationID(resp.Header.Get("Location"))
		if err != nil {
			return User{}, err
		}
		return User{ID: id}, nil
	}
	if !jsonContentType(resp.Header.Get("Content-Type")) {
		return User{}, ErrProtocol
	}
	var user User
	if err := decodeJSON(data, &user); err != nil || validateRemoteUser(user) != nil {
		return User{}, ErrProtocol
	}
	return user, nil
}

func (c *Client) request(ctx context.Context, method string, u *url.URL, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, ErrProtocol
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrRetryable
	}
	return resp, nil
}

func responseStatusError(status int) error {
	if status == http.StatusTooManyRequests || status >= 500 && status <= 599 {
		return ErrRetryable
	}
	return ErrProtocol
}

func (c *Client) locationID(raw string) (string, error) {
	location, err := url.Parse(raw)
	if err != nil || raw == "" || !location.IsAbs() || location.Scheme != c.baseURL.Scheme || location.Host != c.baseURL.Host || location.User != nil || location.RawQuery != "" || location.Fragment != "" || location.RawPath != "" {
		return "", ErrProtocol
	}
	prefix := strings.TrimRight(c.baseURL.Path, "/") + usersPath + "/"
	if !strings.HasPrefix(location.Path, prefix) {
		return "", ErrProtocol
	}
	id := strings.TrimPrefix(location.Path, prefix)
	if validRemoteID(id) != nil {
		return "", ErrProtocol
	}
	return id, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, ErrInvalidConfig
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	return u, nil
}

func validToken(token string) bool {
	return token != "" && len(token) <= 4096 && strings.TrimSpace(token) == token && !strings.ContainsAny(token, "\r\n")
}

func validateUser(user User) error {
	if user.ID != "" || !validIdentifier(user.ExternalID) || !validIdentifier(user.UserName) {
		return ErrInvalidUser
	}
	return nil
}

func validateRemoteUser(user User) error {
	if validRemoteID(user.ID) != nil || !hasSchema(user.Schemas, userSchema) || !validIdentifier(user.ExternalID) || !validIdentifier(user.UserName) {
		return ErrProtocol
	}
	return nil
}

func validRemoteID(id string) error {
	if !validIdentifier(id) || strings.Contains(id, "/") || id == "." || id == ".." {
		return ErrProtocol
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > maxIdentifierBytes || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func hasSchema(schemas []string, want string) bool {
	for _, schema := range schemas {
		if schema == want {
			return true
		}
	}
	return false
}

func sameUser(a, b User) bool {
	return a.ExternalID == b.ExternalID && a.UserName == b.UserName && a.Active == b.Active
}

func escapeFilter(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
}

func jsonContentType(value string) bool {
	media, _, err := mime.ParseMediaType(value)
	return err == nil && (media == "application/json" || media == "application/scim+json" || (strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")))
}

func validOptionalJSON(data []byte, contentType string) bool {
	if len(data) == 0 {
		return true
	}
	var value any
	return jsonContentType(contentType) && decodeJSON(data, &value) == nil
}

func boundedBody(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, ErrRetryable
	}
	if len(b) > limit {
		return nil, ErrProtocol
	}
	return b, nil
}

func decodeJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
