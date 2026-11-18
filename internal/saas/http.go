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

	"github.com/mrchypark/goauthy/internal/netsec"
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
	return !ip.Is4In6() && netsec.AllowedAddr(ip, false)
}
