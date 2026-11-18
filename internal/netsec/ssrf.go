// Package netsec provides shared network security helpers such as SSRF IP filtering.
package netsec

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrUnsafeHost is returned when an outbound target resolves to a disallowed IP address.
var ErrUnsafeHost = errors.New("outbound host resolves to unsafe IP address")

// SafeDialContext returns a DialContext function that validates literal or
// DNS-resolved IP addresses with AllowedAddr and dials the pinned IP directly
// to prevent DNS rebinding.
func SafeDialContext(timeout time.Duration, allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			ip = ip.Unmap()
			if !AllowedAddr(ip, allowPrivate) {
				return nil, ErrUnsafeHost
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = ErrUnsafeHost
			}
			return nil, err
		}
		for _, ip := range ips {
			if !AllowedAddr(ip.Unmap(), allowPrivate) {
				return nil, ErrUnsafeHost
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
	}
}

// NewSafeHTTPClient builds an HTTP client that disables proxy/redirect/compression
// bypasses, enforces TLS 1.2+, and pins DNS-resolved IPs validated by AllowedAddr.
func NewSafeHTTPClient(timeout time.Duration, allowPrivate bool, tlsConfig *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	} else if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.DialContext = SafeDialContext(timeout, allowPrivate)
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
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

// AllowedAddr reports whether addr is safe for outbound server-initiated requests.
// Link-local (including cloud metadata 169.254.0.0/16) and IANA special-use
// ranges are always rejected, even when allowPrivate is true.
func AllowedAddr(addr netip.Addr, allowPrivate bool) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || isCGNAT(addr) {
		return allowPrivate
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return addr.IsGlobalUnicast()
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(addr netip.Addr) bool {
	return cgnatPrefix.Contains(addr)
}
