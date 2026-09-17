package cimd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	maxDocumentBytes = 5 << 10
	minCacheLifetime = 10 * time.Minute
	maxCacheLifetime = time.Hour
	fetchTimeout     = 10 * time.Second
)

var (
	errUnsafeAddress = errors.New("client metadata address is not permitted")
	errFetch         = errors.New("client metadata fetch failed")
)

type lookupFunc func(context.Context, string) ([]netip.Addr, error)
type dialFunc func(context.Context, string, string) (net.Conn, error)

// Fetcher fetches one validated CIMD document. Rhiza storage owns the shared
// cache; its internal function fields are deterministic test seams.
type Fetcher struct {
	now    func() time.Time
	lookup lookupFunc
	dial   dialFunc
	roots  *x509.CertPool
	policy Policy
}

// Policy controls CIMD admission behavior. The zero value is strict:
// unsupported advertised grants and unlisted ephemeral resource indicators
// are rejected.
type Policy struct {
	IgnoreUnknownAuthFlows         bool
	DangerAllowUnvalidatedResource bool
}

// NewFetcher constructs the production fetcher. It bypasses proxy environment
// variables and uses the host's root certificate store.
func NewFetcher() *Fetcher {
	return NewFetcherWithPolicy(Policy{})
}

// NewFetcherWithPolicy constructs a fetcher with an explicit CIMD policy.
// Unknown advertised grant values can only be ignored when the policy enables
// it; response types and token authentication remain strict, and the
// effective client remains public authorization-code/S256 only. Ephemeral
// resource indicators remain deny-by-default unless the explicit danger
// policy is enabled and the document has no allow-list.
func NewFetcherWithPolicy(policy Policy) *Fetcher {
	dialer := &net.Dialer{}
	return &Fetcher{
		now: time.Now,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial:   dialer.DialContext,
		policy: policy,
	}
}

// Fetch returns a fully validated public authorization-code client document
// and its cache expiry. An expiry is always returned for a successful fetch.
func (f *Fetcher) Fetch(ctx context.Context, rawClientID string) (Metadata, time.Time, error) {
	if f == nil || f.now == nil || f.lookup == nil || f.dial == nil {
		return Metadata{}, time.Time{}, errFetch
	}
	target, err := parseTarget(rawClientID)
	if err != nil {
		return Metadata{}, time.Time{}, err
	}
	now := f.now().UTC()
	requestCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	address, err := f.resolve(requestCtx, target)
	if err != nil {
		return Metadata{}, time.Time{}, err
	}
	transport := f.transport(target, address)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target.raw, nil)
	if err != nil {
		return Metadata{}, time.Time{}, errFetch
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Metadata{}, time.Time{}, errFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !jsonContentType(resp.Header.Get("Content-Type")) || resp.ContentLength > maxDocumentBytes {
		return Metadata{}, time.Time{}, errFetch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil || len(body) > maxDocumentBytes {
		return Metadata{}, time.Time{}, errFetch
	}
	metadata, err := decodeMetadataWithPolicy(body, target, f.policy)
	if err != nil {
		return Metadata{}, time.Time{}, err
	}
	expires, err := cacheExpiry(resp.Header, now)
	if err != nil {
		return Metadata{}, time.Time{}, err
	}
	return copyMetadata(metadata), expires, nil
}

func copyMetadata(value Metadata) Metadata {
	value.RedirectURIs = append([]string(nil), value.RedirectURIs...)
	value.Scopes = append([]string(nil), value.Scopes...)
	value.GrantTypes = append([]string(nil), value.GrantTypes...)
	value.AllowedResources = cloneStringSlice(value.AllowedResources)
	return value
}

func (f *Fetcher) resolve(ctx context.Context, target target) (netip.Addr, error) {
	if literal, err := netip.ParseAddr(target.host); err == nil {
		if !safeAddress(literal) {
			return netip.Addr{}, errUnsafeAddress
		}
		return literal, nil
	}
	addresses, err := f.lookup(ctx, target.host)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, errFetch
	}
	for i, address := range addresses {
		address = address.Unmap()
		if !safeAddress(address) {
			return netip.Addr{}, errUnsafeAddress
		}
		addresses[i] = address
	}
	return addresses[0], nil
}

func (f *Fetcher) transport(target target, address netip.Addr) *http.Transport {
	port := target.port
	if port == "" {
		port = "443"
	}
	pinned := net.JoinHostPort(address.String(), port)
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return f.dial(ctx, "tcp", pinned) },
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.host, RootCAs: f.roots},
		TLSHandshakeTimeout:    fetchTimeout,
		ResponseHeaderTimeout:  fetchTimeout,
		MaxResponseHeaderBytes: 8 << 10,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
	}
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && (mediaType == "application/json" || (strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")))
}

func cacheExpiry(header http.Header, now time.Time) (time.Time, error) {
	lifetime := minCacheLifetime
	cacheControl := header.Values("Cache-Control")
	for _, value := range cacheControl {
		for _, directive := range strings.Split(value, ",") {
			name, parameter, hasParameter := strings.Cut(strings.TrimSpace(directive), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			switch name {
			case "no-store", "no-cache", "private":
				return time.Time{}, errFetch
			case "max-age":
				if !hasParameter {
					return time.Time{}, errFetch
				}
				seconds, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(parameter), "\""), 10, 64)
				if err != nil || seconds < 0 {
					return time.Time{}, errFetch
				}
				lifetime = secondsDuration(seconds)
			}
		}
	}
	if lifetime < minCacheLifetime {
		lifetime = minCacheLifetime
	}
	if lifetime > maxCacheLifetime {
		lifetime = maxCacheLifetime
	}
	if age := header.Get("Age"); age != "" {
		seconds, err := strconv.ParseInt(strings.TrimSpace(age), 10, 64)
		if err != nil || seconds < 0 {
			return time.Time{}, errFetch
		}
		ageDuration := secondsDuration(seconds)
		if ageDuration >= lifetime {
			return now, nil
		}
		lifetime -= ageDuration
	}
	return now.Add(lifetime), nil
}

func secondsDuration(seconds int64) time.Duration {
	if seconds >= int64(maxCacheLifetime/time.Second) {
		return maxCacheLifetime
	}
	return time.Duration(seconds) * time.Second
}

func safeAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("100:0:0:1::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:3::/32"), netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:30::/28"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
}
