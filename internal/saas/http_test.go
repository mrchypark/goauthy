package saas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type testResolver struct {
	addrs []netip.Addr
	err   error
}

func (r testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addrs, r.err
}

func TestRestrictedTransportPinsApprovedIPAndPreservesTLSHost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("Host = %q", r.Host)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	var gotSNI string
	server.TLS.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		gotSNI = info.ServerName
		return nil, nil
	}
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	tr := &restrictedTransport{
		base:     base,
		resolver: testResolver{addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "8.8.8.8:443" {
				t.Errorf("dial address = %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if gotSNI != "example.com" {
		t.Fatalf("SNI = %q", gotSNI)
	}
}

func TestRestrictedTransportRejectsUnsafeResolvedAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1", "::1", "fc00::1", "fe80::1", "100:0:0:1::1", "2001:db8::1", "64:ff9b::7f00:1"} {
		ip := netip.MustParseAddr(raw)
		tr := &restrictedTransport{resolver: testResolver{addrs: []netip.Addr{ip}}}
		req := httptest.NewRequest(http.MethodGet, "https://provider.example/", nil)
		if _, err := tr.RoundTrip(req); err != errSaaSUnsafeAddress {
			t.Errorf("%s: err = %v", raw, err)
		}
		if allowedOutboundIP(ip) {
			t.Errorf("%s unexpectedly allowed", raw)
		}
	}
}

func TestAllowedOutboundIPAcceptsGlobalAddress(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if !allowedOutboundIP(netip.MustParseAddr(raw)) {
			t.Errorf("%s rejected", raw)
		}
	}
}
