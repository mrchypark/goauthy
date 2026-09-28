package saas

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type poolResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f poolResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type poolCounts struct{ dns, tcp, tls atomic.Int64 }

// Inject only DNS, raw TCP routing, and roots. Every test still uses the real
// restricted wrapper and stdlib TLS/HTTP transport (no fixture RoundTripper).
func configurePoolTLS(t testing.TB, owner *restrictedTransport, server *httptest.Server) *poolCounts {
	t.Helper()
	counts := &poolCounts{}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	owner.base = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		counts.dns.Add(1)
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	owner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		if err == nil {
			counts.tcp.Add(1)
		}
		return conn, err
	}
	// Set before the first connection; the server has already started but no
	// handler/handshake can read this field until a test dispatches a request.
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { counts.tls.Add(1); return nil, nil }
	t.Cleanup(owner.Close)
	return counts
}

func poolRequest(t testing.TB, owner *restrictedTransport, target string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := owner.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func waitPoolEmpty(t testing.TB, owner *restrictedTransport) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		owner.mu.Lock()
		n := len(owner.entries)
		owner.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d charged entries did not drain", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSaaSPoolReuseCanonicalDNSAndExpiry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("protocol=%s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	owner := &restrictedTransport{}
	counts := configurePoolTLS(t, owner, server)
	var dns atomic.Int64
	owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		a, b := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")
		if dns.Add(1)%2 == 0 {
			return []netip.Addr{a, b, a}, nil
		}
		return []netip.Addr{b, a}, nil
	})
	poolRequest(t, owner, "https://EXAMPLE.com./a")
	poolRequest(t, owner, "https://example.com:443/b")
	if counts.tcp.Load() != 1 || counts.tls.Load() != 1 || dns.Load() != 3 {
		t.Fatalf("tcp=%d tls=%d dns=%d", counts.tcp.Load(), counts.tls.Load(), dns.Load())
	}
	owner.mu.Lock()
	owner.entries[0].created = time.Now().Add(-saasPoolLifetime)
	owner.mu.Unlock()
	poolRequest(t, owner, "https://example.com/c")
	if counts.tcp.Load() != 2 {
		t.Fatal("expired generation reused")
	}
	owner.Close()
	waitPoolEmpty(t, owner)
}

func TestSaaSPoolAddressChangeAndDialRebinding(t *testing.T) {
	for _, duringDial := range []bool{false, true} {
		t.Run(map[bool]string{false: "preflight", true: "dial"}[duringDial], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
			defer server.Close()
			owner := &restrictedTransport{}
			counts := configurePoolTLS(t, owner, server)
			var calls atomic.Int64
			owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				n := calls.Add(1)
				ip := "8.8.8.8"
				if n > 2 || duringDial && n > 1 {
					ip = "1.1.1.1"
				}
				return []netip.Addr{netip.MustParseAddr(ip)}, nil
			})
			if duringDial {
				req, _ := http.NewRequest("POST", "https://example.com/token", strings.NewReader("code=one-use"))
				if _, err := owner.RoundTrip(req); err == nil {
					t.Fatal("dial rebinding accepted")
				}
				if counts.tcp.Load() != 0 {
					t.Fatal("changed address was dialed")
				}
			} else {
				poolRequest(t, owner, "https://example.com/a")
				poolRequest(t, owner, "https://example.com/b")
				if counts.tcp.Load() != 2 {
					t.Fatal("old address generation reused")
				}
			}
		})
	}
}

func TestSaaSPoolRejectsFullDNSAnswer(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	private := netip.MustParseAddr("::1")
	for _, ips := range [][]netip.Addr{nil, {public, private}, {private, public}, {netip.MustParseAddr("::ffff:127.0.0.1")}} {
		owner := &restrictedTransport{resolver: testResolver{addrs: ips}, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("unsafe dial")
			return nil, errSaaSHTTP
		}}
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		if _, err := owner.RoundTrip(req); err == nil {
			t.Fatalf("accepted %v", ips)
		}
		owner.Close()
	}
	owner := &restrictedTransport{resolver: testResolver{addrs: []netip.Addr{public}, err: errors.New("partial DNS result")}}
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if _, err := owner.RoundTrip(req); err == nil {
		t.Fatal("accepted DNS error with addresses")
	}
	req.Host = "other.example.com"
	owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("Host mismatch reached DNS")
		return nil, errSaaSUnsafeAddress
	})
	if _, err := owner.RoundTrip(req); err != errSaaSUnsafeAddress {
		t.Fatal("cross-origin Host override accepted")
	}
}

func TestSaaSPoolTCPFallbackAndTLSFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	owner := &restrictedTransport{}
	configurePoolTLS(t, owner, server)
	owner.resolver = testResolver{addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}}
	var dials []string
	owner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials = append(dials, address)
		if address == "1.1.1.1:443" {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > saasHTTPTimeout/2 {
				t.Error("first address can consume the whole connection budget")
			}
			return nil, errors.New("connect refused")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	poolRequest(t, owner, "https://example.com/a")
	if len(dials) != 2 {
		t.Fatalf("dials=%v", dials)
	}
	// A different TLS identity is neither shared nor bypassed, and TLS errors
	// don't trigger another TCP fallback or another HTTP delegation.
	req, _ := http.NewRequest("GET", "https://wrong.example/a", nil)
	if _, err := owner.RoundTrip(req); err == nil {
		t.Fatal("wrong TLS certificate accepted")
	}
	if len(dials) != 4 {
		t.Fatalf("unexpected TLS retry: %v", dials)
	}
}

type closeObservedBody struct{ closed atomic.Bool }

func (*closeObservedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *closeObservedBody) Close() error           { b.closed.Store(true); return nil }

func TestSaaSPoolBoundsPreflightAndRetiredEntries(t *testing.T) {
	started := make(chan struct{}, saasPoolEntries*saasPoolLeases)
	unblock := make(chan struct{})
	owner := &restrictedTransport{resolver: poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		started <- struct{}{}
		<-unblock
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})}
	defer owner.Close()
	var wg sync.WaitGroup
	for i := 0; i < saasPoolLeases; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			_, _ = owner.RoundTrip(req)
		}()
	}
	<-started
	// Wait until all four reservations (including gate waiters) are charged.
	deadline := time.Now().Add(time.Second)
	for {
		owner.mu.Lock()
		n := len(owner.entries[0].leases)
		owner.mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing leases")
		}
		time.Sleep(time.Millisecond)
	}
	body := &closeObservedBody{}
	req, _ := http.NewRequest("POST", "https://example.com/", body)
	if _, err := owner.RoundTrip(req); err == nil || !body.closed.Load() {
		t.Fatal("saturation must reject and close request body")
	}
	owner.Close()
	owner.mu.Lock()
	n := len(owner.entries)
	owner.mu.Unlock()
	if n != 1 {
		t.Fatal("retired preflight released its charged slot early")
	}
	close(unblock)
	wg.Wait()
	waitPoolEmpty(t, owner)
}

func TestSaaSPoolEntryBudgetAndEviction(t *testing.T) {
	owner := &restrictedTransport{}
	var leases []*httpLease
	for i := 0; i < saasPoolEntries; i++ {
		l, err := owner.reserve(httpPoolKey{origin: net.JoinHostPort("example.com", strconv.Itoa(10000+i))}, func() {})
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if _, err := owner.reserve(httpPoolKey{origin: "other:443"}, func() {}); err == nil {
		t.Fatal("uncharged overflow entry")
	}
	owner.retire(leases[0].entry)
	if _, err := owner.reserve(httpPoolKey{origin: "other:443"}, func() {}); err == nil {
		t.Fatal("retired busy slot escaped budget")
	}
	leases[0].release()
	l, err := owner.reserve(httpPoolKey{origin: "other:443"}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	l.release()
	for _, l := range leases {
		l.release()
	}
	// A quiescent active entry is evictable; the budget isn't a lifetime quota.
	l, err = owner.reserve(httpPoolKey{origin: "new:443"}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	l.release()
	owner.Close()
	waitPoolEmpty(t, owner)
}

func TestSaaSPoolLateDialAndAbandonedBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	owner := &restrictedTransport{}
	configurePoolTLS(t, owner, server)
	started, unblock := make(chan struct{}), make(chan struct{})
	owner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > saasHTTPTimeout {
			t.Error("detached dial lost its absolute deadline")
		}
		close(started)
		<-unblock
		return (&net.Dialer{}).DialContext(context.Background(), network, server.Listener.Addr().String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	done := make(chan error, 1)
	go func() { _, err := owner.RoundTrip(req); done <- err }()
	<-started
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled request succeeded")
	}
	owner.Close()
	owner.mu.Lock()
	n := len(owner.entries)
	owner.mu.Unlock()
	if n != 1 {
		t.Fatal("detached dial not charged")
	}
	close(unblock)
	waitPoolEmpty(t, owner)

	other := &restrictedTransport{}
	configurePoolTLS(t, other, server)
	ctx, cancel = context.WithCancel(context.Background())
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	resp, err := other.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel() // Caller abandons resp.Body without Close; cleanup must still run.
	other.Close()
	waitPoolEmpty(t, other)
	_ = resp.Body.Close() // Idempotent release after cancellation/shutdown.
}

type poolWriteFailure struct {
	net.Conn
	fail    *atomic.Bool
	partial bool
}

func (c *poolWriteFailure) Write(p []byte) (int, error) {
	if c.fail.Swap(false) {
		if c.partial {
			n, _ := c.Conn.Write(p[:len(p)/2])
			return n, io.ErrUnexpectedEOF
		}
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func TestSaaSPoolMutationNeverReplays(t *testing.T) {
	for _, method := range []string{"POST", "DELETE"} {
		for _, mode := range []string{"zero-write", "partial-write", "lost-response"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				var mutations atomic.Int64
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "GET" {
						mutations.Add(1)
						_, _ = io.Copy(io.Discard, r.Body)
						if mode == "lost-response" {
							c, _, _ := w.(http.Hijacker).Hijack()
							_ = c.Close()
							return
						}
					}
					_, _ = io.WriteString(w, "ok")
				}))
				defer server.Close()
				owner := &restrictedTransport{}
				counts := configurePoolTLS(t, owner, server)
				var fail atomic.Bool
				original := owner.dial
				owner.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
					c, e := original(ctx, n, a)
					if e != nil {
						return nil, e
					}
					return &poolWriteFailure{Conn: c, fail: &fail, partial: mode == "partial-write"}, nil
				}
				poolRequest(t, owner, "https://example.com/warm")
				if mode != "lost-response" {
					fail.Store(true)
				}
				req, _ := http.NewRequest(method, "https://example.com/token", strings.NewReader("token=one-use"))
				if req.GetBody == nil {
					t.Fatal("fixture isn't rewindable")
				}
				if _, err := owner.RoundTrip(req); err == nil {
					t.Fatal("mutation unexpectedly succeeded")
				}
				if req.GetBody == nil {
					t.Fatal("caller request mutated")
				}
				want := int64(0)
				if mode == "lost-response" {
					want = 1
				}
				if counts.tcp.Load() != 1 || mutations.Load() != want {
					t.Fatalf("tcp=%d mutations=%d want=%d", counts.tcp.Load(), mutations.Load(), want)
				}
			})
		}
	}
}

func TestSaaSPoolLateDNSCannotReplaceNewGeneration(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	owner := &restrictedTransport{}
	counts := configurePoolTLS(t, owner, server)
	started, unblock := make(chan struct{}), make(chan struct{})
	var lookups atomic.Int64
	owner.resolver = poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			close(started)
			<-unblock
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		_, err := owner.RoundTrip(req)
		done <- err
	}()
	<-started
	owner.invalidate("")
	poolRequest(t, owner, "https://example.com/new")
	close(unblock)
	if err := <-done; err == nil {
		t.Fatal("late DNS resurrected retired generation")
	}
	poolRequest(t, owner, "https://example.com/reused")
	if counts.tcp.Load() != 1 {
		t.Fatal("late DNS replaced current pool")
	}
}

func TestSaaSPoolBodyDeadlineAndReadOnlyRecovery(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	owner := &restrictedTransport{}
	counts := configurePoolTLS(t, owner, server)
	var fail atomic.Bool
	dial := owner.dial
	owner.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		c, err := dial(ctx, n, a)
		if err != nil {
			return nil, err
		}
		return &poolWriteFailure{Conn: c, fail: &fail}, nil
	}
	poolRequest(t, owner, "https://example.com/warm")
	fail.Store(true)
	poolRequest(t, owner, "https://example.com/read-only")
	if counts.tcp.Load() != 2 {
		t.Fatal("expected stdlib GET recovery within one admission")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/stall", nil)
	resp, err := owner.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	// The real default budget is installed by the wrapper, not just the client.
	deadline, ok := resp.Request.Context().Deadline()
	if !ok || time.Until(deadline) > saasHTTPTimeout {
		t.Fatal("missing operation deadline")
	}
	<-ctx.Done() // Deliberately never read/close the body until cleanup completed.
	limit := time.After(time.Second)
	for {
		owner.mu.Lock()
		busy := 0
		for _, e := range owner.entries {
			busy += len(e.leases)
		}
		owner.mu.Unlock()
		if busy == 0 {
			break
		}
		select {
		case <-limit:
			t.Fatal("abandoned body retained lease")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	_ = resp.Body.Close()
}

func TestSaaSPoolRealEntryBudget(t *testing.T) {
	started, unblock := make(chan struct{}, saasPoolEntries), make(chan struct{})
	owner := &restrictedTransport{resolver: poolResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		started <- struct{}{}
		<-unblock
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < saasPoolEntries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://example.com:"+strconv.Itoa(10000+i), nil)
			_, _ = owner.RoundTrip(req)
		}()
	}
	for i := 0; i < saasPoolEntries; i++ {
		<-started
	}
	req, _ := http.NewRequest("GET", "https://example.com:20000", nil)
	if _, err := owner.RoundTrip(req); err == nil {
		t.Fatal("overflow admission")
	}
	owner.Close()
	owner.mu.Lock()
	charged := len(owner.entries)
	owner.mu.Unlock()
	if charged != saasPoolEntries {
		t.Fatal("retiring validation work escaped accounting")
	}
	close(unblock)
	wg.Wait()
	waitPoolEmpty(t, owner)
}

func TestSaaSPoolPrivateTransportAndRedirect(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 1 {
			t.Error("alternate protocol used")
		}
		http.Redirect(w, r, "https://127.0.0.1/private", http.StatusFound)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	owner := &restrictedTransport{}
	counts := configurePoolTLS(t, owner, server)
	owner.base.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("TLS bypass inherited")
		return nil, errSaaSHTTP
	}
	owner.base.Proxy = func(*http.Request) (*url.URL, error) { t.Error("proxy inherited"); return nil, errSaaSHTTP }
	owner.base.Protocols = &http.Protocols{}
	owner.base.Protocols.SetHTTP2(true)
	client := newSaaSHTTPClient()
	client.Transport = owner
	if _, err := client.Get("https://example.com/"); err == nil {
		t.Fatal("redirect accepted")
	}
	if requests.Load() != 1 || counts.tcp.Load() != 1 {
		t.Fatal("redirect dispatched twice")
	}
	// Root trust is the only template field admitted; insecure verification is
	// deliberately not inherited even when a caller supplies it in a test base.
	other := &restrictedTransport{base: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, resolver: owner.resolver, dial: owner.dial}
	defer other.Close()
	req, _ := http.NewRequest("GET", "https://wrong.example/", nil)
	if _, err := other.RoundTrip(req); err == nil {
		t.Fatal("insecure TLS policy inherited")
	}
}

func TestSaaSPoolBodiesHoldFourLeases(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	owner := &restrictedTransport{}
	counts := configurePoolTLS(t, owner, server)
	var bodies []io.ReadCloser
	for i := 0; i < saasPoolLeases; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/stall", nil)
		started := time.Now()
		resp, err := owner.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		deadline, ok := resp.Request.Context().Deadline()
		if !ok || deadline.Before(started.Add(saasHTTPTimeout)) || deadline.After(time.Now().Add(saasHTTPTimeout)) {
			t.Fatal("default 15-second body budget was not retained")
		}
		bodies = append(bodies, resp.Body)
	}
	req, _ := http.NewRequest("GET", "https://example.com/overflow", nil)
	if _, err := owner.RoundTrip(req); err == nil {
		t.Fatal("released admission at response headers")
	}
	if counts.tcp.Load() != 4 {
		t.Fatalf("connections=%d", counts.tcp.Load())
	}
	owner.Close()
	waitPoolEmpty(t, owner)
	for _, body := range bodies {
		_ = body.Close()
	}
}

func TestSaaSPoolActualMutationCallers(t *testing.T) {
	// Give the fixture the real GitHub names so Revoke exercises its unmodified
	// URL and normal certificate verification, not a rewriting RoundTripper.
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := *seed.Certificate()
	key := seed.TLS.Certificates[0].PrivateKey
	seed.Close()
	certificate.DNSNames = []string{"example.com", "api.github.com", "github.com"}
	der, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, certificate.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"exchange", "refresh", "github-revoke"} {
		for _, mode := range []string{"zero-write", "partial-write", "lost-response"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				var sent atomic.Int64
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "GET" {
						sent.Add(1)
						_, _ = io.Copy(io.Discard, r.Body)
						conn, _, _ := w.(http.Hijacker).Hijack()
						_ = conn.Close()
						return
					}
					_, _ = io.WriteString(w, "ok")
				}))
				server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
				server.StartTLS()
				defer server.Close()
				var client *http.Client
				var mutate func() error
				warmURL := "https://example.com/warm"
				if operation == "github-revoke" {
					g, err := NewGitHub("client", "secret", "https://app.example/callback")
					if err != nil {
						t.Fatal(err)
					}
					client, warmURL = g.client, "https://api.github.com/warm"
					mutate = func() error { return g.Revoke(context.Background(), "one-use") }
				} else {
					o, err := NewOAuth2(OAuth2Config{ClientID: "client", AuthorizationURL: "https://example.com/auth", TokenURL: "https://example.com/token", CallbackURL: "https://app.example/callback", Scopes: []string{"read"}, AuthStyle: oauth2.AuthStyleInHeader}, "secret")
					if err != nil {
						t.Fatal(err)
					}
					client = o.client
					mutate = func() error {
						if operation == "refresh" {
							_, err := o.Refresh(context.Background(), "one-use")
							return err
						}
						_, err := o.Exchange(context.Background(), "one-use", strings.Repeat("a", 43))
						return err
					}
				}
				owner := client.Transport.(*restrictedTransport)
				counts := configurePoolTLS(t, owner, server)
				var fail atomic.Bool
				dial := owner.dial
				owner.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
					conn, err := dial(ctx, n, a)
					if err != nil {
						return nil, err
					}
					return &poolWriteFailure{Conn: conn, fail: &fail, partial: mode == "partial-write"}, nil
				}
				resp, err := client.Get(warmURL)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				fail.Store(mode != "lost-response")
				if err := mutate(); err == nil {
					t.Fatal("mutation unexpectedly succeeded")
				}
				want := int64(0)
				if mode == "lost-response" {
					want = 1
				}
				if sent.Load() != want || counts.tcp.Load() != 1 {
					t.Fatalf("sent=%d tcp=%d", sent.Load(), counts.tcp.Load())
				}
			})
		}
	}
}

func TestSaaSPoolDetachedTLSHasAbsoluteDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Consume the ClientHello but never send a TLS reply.
		_, _ = io.Copy(io.Discard, conn)
	}()
	owner := &restrictedTransport{resolver: testResolver{addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}}
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	if _, err := owner.RoundTrip(req); err == nil {
		t.Fatal("stalled TLS succeeded")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("TLS continued on detached context past the absolute deadline")
	}
	limit := time.Now().Add(time.Second)
	for {
		owner.mu.Lock()
		live := 0
		for _, entry := range owner.entries {
			live += len(entry.connections)
		}
		owner.mu.Unlock()
		if live == 0 {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("TLS socket retained after timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

type observeWriteDeadline struct {
	net.Conn
	observed chan time.Time
}

func (c *observeWriteDeadline) SetWriteDeadline(deadline time.Time) error {
	select {
	case c.observed <- deadline:
	default:
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestSaaSPoolRetirementDoesNotWaitForTLSCloseNotify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	owner := &restrictedTransport{}
	configurePoolTLS(t, owner, server)
	observed := make(chan time.Time, 2)
	dial := owner.dial
	owner.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		conn, err := dial(ctx, n, a)
		if err != nil {
			return nil, err
		}
		return &observeWriteDeadline{Conn: conn, observed: observed}, nil
	}
	poolRequest(t, owner, "https://example.com/")
	owner.invalidate("")
	select {
	case deadline := <-observed:
		if deadline.After(time.Now()) {
			t.Fatal("retirement inherited TLS's extra close_notify budget")
		}
	default:
		t.Fatal("TLS close path not exercised")
	}
	waitPoolEmpty(t, owner)
}
