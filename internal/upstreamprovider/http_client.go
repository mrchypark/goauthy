package upstreamprovider

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/mrchypark/goauthy/internal/netsec"
)

var errUnsafeUpstreamHost = errors.New("upstream provider host resolves to unsafe IP address")

func newSafeHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			ip = ip.Unmap()
			if !netsec.AllowedAddr(ip, allowPrivate) {
				return nil, errUnsafeUpstreamHost
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = errUnsafeUpstreamHost
			}
			return nil, err
		}
		for _, ip := range ips {
			if !netsec.AllowedAddr(ip.Unmap(), allowPrivate) {
				return nil, errUnsafeUpstreamHost
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
