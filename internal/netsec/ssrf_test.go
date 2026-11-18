package netsec

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestAllowedAddr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr         string
		allowPrivate bool
		want         bool
	}{
		{"93.184.216.34", false, true},
		{"2606:2800:220:1:248:1893:25c8:1946", false, true},
		{"127.0.0.1", false, false},
		{"127.0.0.1", true, true},
		{"::1", false, false},
		{"::1", true, true},
		{"10.0.0.1", false, false},
		{"10.0.0.1", true, true},
		{"172.16.0.1", false, false},
		{"172.16.0.1", true, true},
		{"192.168.1.1", false, false},
		{"192.168.1.1", true, true},
		{"100.64.0.1", false, false},
		{"100.64.0.1", true, true},
		{"169.254.169.254", false, false},
		{"169.254.169.254", true, false},
		{"fe80::1", true, false},
		{"::ffff:127.0.0.1", false, false},
		{"::ffff:127.0.0.1", true, true},
		{"::ffff:169.254.169.254", true, false},
		{"0.0.0.0", true, false},
		{"224.0.0.1", true, false},
		{"192.0.2.1", true, false},
		{"2001:db8::1", true, false},
		{"2001:db8::1%eth0", false, false},
		{"2001:db8::1%eth0", true, false},
		{"64:ff9b::127.0.0.1%eth0", false, false},
		{"64:ff9b::127.0.0.1%eth0", true, false},
		{"::%eth0", false, false},
		{"::%eth0", true, false},
		{"::1%lo0", false, false},
		{"::1%lo0", true, false},
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.addr)
		if got := AllowedAddr(ip, tc.allowPrivate); got != tc.want {
			t.Errorf("AllowedAddr(%s, %t) = %t, want %t", tc.addr, tc.allowPrivate, got, tc.want)
		}
	}
	if AllowedAddr(netip.Addr{}, true) {
		t.Fatal("expected invalid Addr to be rejected")
	}
}

func TestSafeDialContextAndNewSafeHTTPClient(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	blockedDial := SafeDialContext(time.Second, false)
	if conn, err := blockedDial(context.Background(), "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("expected SafeDialContext(allowPrivate=false) to reject loopback")
	} else if !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("expected ErrUnsafeHost, got %v", err)
	}

	allowedDial := SafeDialContext(time.Second, true)
	conn, err := allowedDial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected SafeDialContext(allowPrivate=true) to succeed: %v", err)
	}
	conn.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewSafeHTTPClient(time.Second, false, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("expected NewSafeHTTPClient(allowPrivate=false) to block loopback")
	} else if !errors.Is(err, ErrUnsafeHost) {
		t.Fatalf("expected ErrUnsafeHost, got %v", err)
	}

	allowClient := NewSafeHTTPClient(time.Second, true, &tls.Config{InsecureSkipVerify: true})
	resp, err := allowClient.Do(req)
	if err != nil {
		t.Fatalf("expected NewSafeHTTPClient(allowPrivate=true) to succeed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=200", resp.StatusCode)
	}
}
