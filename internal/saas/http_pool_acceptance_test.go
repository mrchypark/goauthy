package saas

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSaaSPoolWarmDNSRejection(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	private := netip.MustParseAddr("127.0.0.1")
	for _, tc := range []struct {
		name string
		ips  []netip.Addr
		err  error
	}{
		{"unsafe", []netip.Addr{private}, nil},
		{"mixed", []netip.Addr{public, private}, nil},
		{"empty", nil, nil},
		{"error-with-address", []netip.Addr{public}, errors.New("partial answer")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = io.WriteString(w, "ok") }))
			defer server.Close()
			owner := &restrictedTransport{}
			counts := configurePoolTLS(t, owner, server)
			var reject atomic.Bool
			owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				if reject.Load() {
					return tc.ips, tc.err
				}
				return []netip.Addr{public}, nil
			})
			poolRequest(t, owner, "https://example.com/warm")
			reject.Store(true)
			req, _ := http.NewRequest("POST", "https://example.com/token", strings.NewReader("refresh_token=once"))
			if _, err := owner.RoundTrip(req); err == nil {
				t.Fatal("warm DNS rejection accepted")
			}
			// Reaping requires the idle raw connection to have actually closed, not
			// just a terminal flag or an empty idle list in the stdlib transport.
			waitPoolEmpty(t, owner)
			if requests.Load() != 1 || counts.tcp.Load() != 1 {
				t.Fatalf("requests=%d tcp=%d", requests.Load(), counts.tcp.Load())
			}
			reject.Store(false)
			poolRequest(t, owner, "https://example.com/recover")
			if requests.Load() != 2 || counts.tcp.Load() != 2 || counts.tls.Load() != 2 {
				t.Fatalf("requests=%d tcp=%d tls=%d", requests.Load(), counts.tcp.Load(), counts.tls.Load())
			}
		})
	}
	t.Run("unsafe-dial-answer", func(t *testing.T) {
		owner := &restrictedTransport{}
		var dns, dials atomic.Int64
		owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			if dns.Add(1) == 1 {
				return []netip.Addr{public}, nil
			}
			return []netip.Addr{public, private}, nil
		})
		owner.dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		}
		defer owner.Close()
		req, _ := http.NewRequest("POST", "https://example.com/token", strings.NewReader("refresh_token=once"))
		if _, err := owner.RoundTrip(req); err == nil {
			t.Fatal("unsafe dial answer accepted")
		}
		waitPoolEmpty(t, owner)
		if dns.Load() != 2 || dials.Load() != 0 {
			t.Fatalf("dns=%d dials=%d", dns.Load(), dials.Load())
		}
	})
}

func TestSaaSPoolStalledTCPFallback(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	owner := &restrictedTransport{}
	configurePoolTLS(t, owner, server)
	owner.resolver = testResolver{addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}}
	var attempts atomic.Int64
	var expired atomic.Bool
	owner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts.Add(1)
		if address == "1.1.1.1:443" {
			<-ctx.Done()
			expired.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
			return nil, ctx.Err()
		}
		if !expired.Load() {
			t.Error("fallback preceded first attempt expiry")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://example.com/token", strings.NewReader("refresh_token=once"))
	resp, err := owner.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || !expired.Load() || attempts.Load() != 2 || requests.Load() != 1 {
		t.Fatalf("ctx=%v expired=%v attempts=%d requests=%d", ctx.Err(), expired.Load(), attempts.Load(), requests.Load())
	}
}

// Stall only after the first TLS/HTTP exchange. Closing the raw connection is
// the only way to unblock this injected write, as with a full socket buffer.
type stalledPoolWrite struct {
	net.Conn
	stall   *atomic.Bool
	closed  chan struct{}
	once    sync.Once
	entered chan struct{}
}

func (c *stalledPoolWrite) Write(p []byte) (int, error) {
	if c.stall.Load() {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}
func (c *stalledPoolWrite) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestSaaSPoolCallerDeadlineStages(t *testing.T) {
	for _, stage := range []string{"preflight-dns", "dial-dns", "write", "headers"} {
		t.Run(stage, func(t *testing.T) {
			var requests, dns, dials atomic.Int64
			entered := make(chan struct{}, 1)
			var stall atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if stage == "headers" && r.URL.Path == "/token" {
					_, _ = io.Copy(io.Discard, r.Body)
					entered <- struct{}{}
					<-r.Context().Done()
					return
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			owner := &restrictedTransport{}
			configurePoolTLS(t, owner, server)
			owner.resolver = poolResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				n := dns.Add(1)
				if stage == "preflight-dns" || stage == "dial-dns" && n == 2 {
					entered <- struct{}{}
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			})
			owner.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials.Add(1)
				conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return &stalledPoolWrite{Conn: conn, stall: &stall, closed: make(chan struct{}), entered: entered}, nil
			}
			if stage == "write" {
				poolRequest(t, owner, "https://example.com/warm")
				stall.Store(true)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://example.com/token", strings.NewReader("refresh_token=once"))
			started := time.Now()
			if resp, err := owner.RoundTrip(req); err == nil {
				_ = resp.Body.Close()
				t.Fatal("stalled request succeeded")
			}
			if time.Since(started) > time.Second {
				t.Fatal("caller deadline not enforced")
			}
			select {
			case <-entered:
			default:
				t.Fatal("fault stage not reached")
			}
			// Do not call owner.Close to make cleanup pass: cancellation itself must
			// release every lease, detached dial and tracked socket.
			deadline := time.Now().Add(time.Second)
			for {
				owner.mu.Lock()
				leases, activeDials, conns := 0, 0, 0
				for _, e := range owner.entries {
					leases += len(e.leases)
					activeDials += e.dials
					conns += len(e.connections)
				}
				owner.mu.Unlock()
				if leases == 0 && activeDials == 0 && conns == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("leases=%d dials=%d conns=%d", leases, activeDials, conns)
				}
				time.Sleep(time.Millisecond)
			}
			wantRequests, wantDials := int64(0), int64(0)
			if stage == "write" || stage == "headers" {
				wantRequests, wantDials = 1, 1
			}
			if requests.Load() != wantRequests || dials.Load() != wantDials {
				t.Fatalf("requests=%d dials=%d", requests.Load(), dials.Load())
			}
		})
	}
}
