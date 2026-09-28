package saas

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

var (
	errSaaSUnsafeAddress = errors.New("saas: unsafe outbound address")
	errSaaSHTTP          = errors.New("saas: outbound request failed")
)

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type restrictedTransport struct {
	base     *http.Transport
	resolver ipResolver
	dial     func(context.Context, string, string) (net.Conn, error)
	mu       sync.Mutex
	entries  []*httpPoolEntry
	closed   bool
}

func newSaaSHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &restrictedTransport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errSaaSHTTP },
	}
}

func (t *restrictedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTrip(req, providerHTTPBinding{})
}
func cloneURL(src *url.URL, host string) *url.URL {
	u := *src
	u.Host = host
	return &u
}

func allowedOutboundIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() || !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:3::/32"), netip.MustParsePrefix("2001:4:112::/48"), netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("2001:30::/28"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
}
