package geoblock

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRequestLocationTrustedHeaderAndFallback(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	wantIP := netip.MustParseAddr("198.51.100.7")
	for _, test := range []struct {
		name       string
		remote     string
		header     []string
		configured string
		lookup     bool
		want       string
		wantLookup bool
	}{
		{name: "trusted raw display header", remote: "10.0.0.2:443", header: []string{"KR, South Korea, Seoul"}, configured: "X-Location", want: "KR, South Korea, Seoul"},
		{name: "non ASCII falls back", remote: "10.0.0.2:443", header: []string{"서울"}, configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "control byte falls back", remote: "10.0.0.2:443", header: []string{"KR\x7f"}, configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "horizontal tab allowed", remote: "10.0.0.2:443", header: []string{"KR\tSeoul"}, configured: "X-Location", want: "KR\tSeoul"},
		{name: "untrusted peer falls back", remote: "203.0.113.2:443", header: []string{"spoofed"}, configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "missing header falls back", remote: "10.0.0.2:443", configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "empty header falls back", remote: "10.0.0.2:443", header: []string{""}, configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "repeated header uses first", remote: "10.0.0.2:443", header: []string{"one", "two"}, configured: "X-Location", want: "one"},
		{name: "malformed peer falls back", remote: "not-an-ip:443", header: []string{"ignored"}, configured: "X-Location", lookup: true, want: "DB Location", wantLookup: true},
		{name: "unconfigured header falls back", remote: "10.0.0.2:443", header: []string{"ignored"}, lookup: true, want: "DB Location", wantLookup: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = test.remote
			for _, value := range test.header {
				r.Header.Add(test.configured, value)
			}
			var gotIP netip.Addr
			lookup := func(ip netip.Addr) (*string, error) {
				gotIP = ip
				location := "DB Location"
				return &location, nil
			}
			var callback func(netip.Addr) (*string, error)
			if test.lookup {
				callback = lookup
			}
			got, err := RequestLocation(r, test.configured, trusted, wantIP, callback)
			if err != nil {
				t.Fatalf("RequestLocation() error=%v", err)
			}
			if (got == nil) != (test.want == "") || got != nil && *got != test.want {
				t.Fatalf("RequestLocation()=%v want %q", got, test.want)
			}
			if gotIP.IsValid() != test.wantLookup || test.wantLookup && gotIP != wantIP {
				t.Fatalf("lookup IP=%s want called=%t with %s", gotIP, test.wantLookup, wantIP)
			}
		})
	}
}

func TestRequestLocationNilLookupAndLookupFailure(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.2:443"
	ip := netip.MustParseAddr("198.51.100.7")
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if got, err := RequestLocation(r, "X-Location", trusted, ip, nil); got != nil || err != nil {
		t.Fatalf("nil lookup returned %v, %v", got, err)
	}
	got, err := RequestLocation(r, "X-Location", trusted, ip, func(netip.Addr) (*string, error) {
		return nil, errors.New("lookup failed")
	})
	if got != nil || err == nil || err.Error() != "lookup failed" {
		t.Fatalf("failed lookup returned %v, %v", got, err)
	}
}
