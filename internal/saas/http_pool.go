package saas

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	saasHTTPTimeout  = 15 * time.Second
	saasPoolLifetime = 5 * time.Minute
	saasPoolEntries  = 32
	saasPoolLeases   = 4
)

type httpPoolKey struct {
	provider string
	revision int64
	origin   string
}

// An entry owns only immutable transport policy and resource accounting, never
// an adapter, secret, or caller authority. The pointer is its generation token.
type httpPoolEntry struct {
	key         httpPoolKey
	created     time.Time
	retired     bool
	gate        chan struct{}
	addresses   []netip.Addr
	transport   *http.Transport
	leases      map[*httpLease]struct{}
	dials       int
	connections map[*poolConn]struct{}
	ctx         context.Context
	cancel      context.CancelFunc
}

type httpLease struct {
	owner  *restrictedTransport
	entry  *httpPoolEntry
	cancel context.CancelFunc
	once   sync.Once
}

type dialDeadlineKey struct{}

// Go performs TLS using its detached dial context too. A native socket
// deadline bounds that handshake. GotConn identifies the exact verified
// connection, even when a speculative dial outlives its originating request.
func acquiredTLSConnection(info httptrace.GotConnInfo, deadline time.Time) {
	tlsConn, ok := info.Conn.(*tls.Conn)
	if !ok {
		_ = info.Conn.Close()
		return
	}
	c, ok := tlsConn.NetConn().(*poolConn)
	if !ok {
		_ = tlsConn.Close()
		return
	}
	c.owner.mu.Lock()
	retired := c.entry.retired || c.owner.closed
	c.deadline = deadline
	c.owner.mu.Unlock()
	if retired || !time.Now().Before(deadline) {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
}

func canonicalOrigin(req *http.Request) (string, error) {
	if req == nil || req.URL == nil || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return "", errSaaSUnsafeAddress
	}
	origin, err := canonicalAuthority(req.URL.Host)
	if err != nil {
		return "", err
	}
	if req.Host != "" {
		headerOrigin, err := canonicalAuthority(req.Host)
		if err != nil || headerOrigin != origin {
			return "", errSaaSUnsafeAddress
		}
	}
	return origin, nil
}

func canonicalAuthority(authority string) (string, error) {
	u := &url.URL{Host: authority}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || strings.ContainsAny(host, "%\\ \t\r\n") {
		return "", errSaaSUnsafeAddress
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	port := 443
	if raw := u.Port(); raw != "" {
		var err error
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return "", errSaaSUnsafeAddress
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (t *restrictedTransport) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	r := t.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addresses, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errSaaSUnsafeAddress
	}
	addresses = slices.Clone(addresses)
	for i, ip := range addresses {
		addresses[i] = ip.Unmap()
		if !allowedOutboundIP(addresses[i]) {
			return nil, errSaaSUnsafeAddress
		}
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addresses), nil
}

// reapLocked releases charged slots only after all work and sockets are gone.
func (t *restrictedTransport) reapLocked() {
	t.entries = slices.DeleteFunc(t.entries, func(e *httpPoolEntry) bool {
		return e.retired && len(e.leases) == 0 && e.dials == 0 && len(e.connections) == 0
	})
}

func (t *restrictedTransport) retire(e *httpPoolEntry) {
	t.mu.Lock()
	e.retired = true
	e.cancel()
	tr := e.transport
	t.reapLocked()
	t.mu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

func (t *restrictedTransport) reserve(key httpPoolKey, cancel context.CancelFunc) (*httpLease, error) {
	for {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, errSaaSHTTP
		}
		t.reapLocked()
		var found, evict *httpPoolEntry
		for _, e := range t.entries {
			if !e.retired && e.key == key {
				found = e
				break
			}
			if !e.retired && len(e.leases) == 0 && e.dials == 0 {
				evict = e
			}
		}
		if found != nil && time.Since(found.created) >= saasPoolLifetime {
			found.retired = true
			found.cancel()
			t.mu.Unlock()
			t.retire(found)
			continue
		}
		if found == nil {
			if len(t.entries) >= saasPoolEntries {
				if evict != nil {
					evict.retired = true
					evict.cancel()
				}
				t.mu.Unlock()
				if evict == nil {
					return nil, errSaaSHTTP
				}
				t.retire(evict)
				continue
			}
			ctx, stop := context.WithCancel(context.Background())
			found = &httpPoolEntry{key: key, created: time.Now(), gate: make(chan struct{}, 1), leases: make(map[*httpLease]struct{}), connections: make(map[*poolConn]struct{}), ctx: ctx, cancel: stop}
			t.entries = append(t.entries, found)
		}
		if len(found.leases) >= saasPoolLeases {
			t.mu.Unlock()
			return nil, errSaaSHTTP
		}
		lease := &httpLease{owner: t, entry: found, cancel: cancel}
		found.leases[lease] = struct{}{}
		t.mu.Unlock()
		return lease, nil
	}
}

func (l *httpLease) release() {
	l.once.Do(func() {
		t, e := l.owner, l.entry
		t.mu.Lock()
		delete(e.leases, l)
		retired, tr := e.retired, e.transport
		t.reapLocked()
		t.mu.Unlock()
		if retired && tr != nil {
			tr.CloseIdleConnections()
		}
	})
}

func (t *restrictedTransport) roundTrip(req *http.Request, binding providerHTTPBinding) (*http.Response, error) {
	delegated := false
	defer func() {
		if !delegated && req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	origin, err := canonicalOrigin(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), saasHTTPTimeout)
	keepBody := false
	defer func() {
		if !keepBody {
			cancel()
		}
	}()
	deadline, _ := ctx.Deadline()
	ctx = context.WithValue(ctx, dialDeadlineKey{}, deadline)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { acquiredTLSConnection(info, deadline) }})
	host, _, _ := net.SplitHostPort(origin)
	key := httpPoolKey{provider: binding.id, revision: binding.revision, origin: origin}
	// A changed preflight answer can select a fresh generation before delegation.
	// There is no retry after the single Transport.RoundTrip below.
	for attempt := 0; attempt < 2; attempt++ {
		lease, err := t.reserve(key, cancel)
		if err != nil {
			return nil, err
		}
		e := lease.entry
		select {
		case e.gate <- struct{}{}:
		case <-ctx.Done():
			lease.release()
			return nil, ctx.Err()
		}
		if err = binding.check(ctx); err != nil {
			t.retire(e)
			<-e.gate
			lease.release()
			return nil, errSaaSHTTP
		}
		if binding.id != "" {
			t.invalidateBefore(binding.id, binding.revision)
		}
		addresses, err := t.resolve(ctx, host)
		if err != nil {
			t.retire(e)
			<-e.gate
			lease.release()
			return nil, err
		}
		t.mu.Lock()
		stale := e.retired || t.closed || ctx.Err() != nil
		changed := e.addresses != nil && !slices.Equal(e.addresses, addresses)
		if !stale && !changed && e.transport == nil {
			e.addresses = addresses
			e.transport = t.newTransport(e, host)
		}
		tr := e.transport
		t.mu.Unlock()
		if changed || stale {
			t.retire(e)
			<-e.gate
			lease.release()
			if stale {
				return nil, errSaaSHTTP
			}
			continue
		}
		// Admission commits while holding the validation gate. Subsequent retirement
		// permits this operation to drain, but never permits another admission.
		<-e.gate
		clone := req.Clone(ctx)
		clone.URL = cloneURL(req.URL, origin)
		clone.Host = req.Host
		if clone.Host == "" {
			clone.Host = req.URL.Host
		}
		clone.GetBody = nil // Nonempty OAuth POST and GitHub DELETE cannot rewind.
		delegated = true
		resp, err := tr.RoundTrip(clone)
		if err != nil {
			lease.release()
			return nil, errSaaSHTTP
		}
		body := &poolBody{ReadCloser: resp.Body, lease: lease, cancel: cancel}
		// Install the callback under the same mutex used by Close, including when
		// the context has already expired before AfterFunc returns.
		body.mu.Lock()
		body.stop = context.AfterFunc(ctx, func() { _ = body.Close() })
		body.mu.Unlock()
		resp.Body = body
		keepBody = true
		return resp, nil
	}
	return nil, errSaaSHTTP
}

func (t *restrictedTransport) newTransport(e *httpPoolEntry, host string) *http.Transport {
	policy := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	// Only roots are injectable. Never inherit proxy, TLS dial, verification,
	// alternate-protocol or retry behavior from the test transport template.
	if t.base != nil && t.base.TLSClientConfig != nil && t.base.TLSClientConfig.RootCAs != nil {
		policy.RootCAs = t.base.TLSClientConfig.RootCAs.Clone()
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	return &http.Transport{Protocols: protocols, TLSClientConfig: policy, DisableCompression: true,
		MaxConnsPerHost: 4, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: saasHTTPTimeout, ResponseHeaderTimeout: saasHTTPTimeout, MaxResponseHeaderBytes: 8 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return t.dialEntry(ctx, e, network, address)
		},
	}
}

func (t *restrictedTransport) dialEntry(ctx context.Context, e *httpPoolEntry, network, address string) (net.Conn, error) {
	t.mu.Lock()
	if e.retired || t.closed || address != e.key.origin {
		t.mu.Unlock()
		return nil, errSaaSHTTP
	}
	e.dials++
	t.mu.Unlock()
	defer func() { t.mu.Lock(); e.dials--; t.reapLocked(); t.mu.Unlock() }()
	deadline, ok := ctx.Value(dialDeadlineKey{}).(time.Time)
	if !ok {
		return nil, errSaaSHTTP
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(e.ctx, cancel)
	defer stop()
	select {
	case e.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	host, port, _ := net.SplitHostPort(address)
	addresses, err := t.resolve(ctx, host)
	t.mu.Lock()
	stale := e.retired || !slices.Equal(addresses, e.addresses)
	t.mu.Unlock()
	if err != nil || stale {
		t.retire(e)
		<-e.gate
		return nil, errSaaSUnsafeAddress
	}
	<-e.gate
	dial := t.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	for i, ip := range addresses {
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			break
		}
		attempt, stop := context.WithTimeout(ctx, remaining/time.Duration(len(addresses)-i))
		conn, err := dial(attempt, network, net.JoinHostPort(ip.String(), port))
		stop()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, errSaaSHTTP
		}
		t.mu.Lock()
		if e.retired || t.closed || ctx.Err() != nil {
			t.mu.Unlock()
			_ = conn.Close()
			return nil, errSaaSHTTP
		}
		tracked := &poolConn{Conn: conn, owner: t, entry: e, deadline: deadline}
		e.connections[tracked] = struct{}{}
		t.mu.Unlock()
		return tracked, nil
	}
	return nil, errSaaSHTTP
}

type poolConn struct {
	net.Conn
	owner    *restrictedTransport
	entry    *httpPoolEntry
	deadline time.Time // guarded by owner.mu; refreshed on each GotConn
	once     sync.Once
}

// TLS Close installs its own five-second close_notify write deadline. Don't
// let that extend an operation's deadline or block retirement of idle sockets.
func (c *poolConn) SetWriteDeadline(deadline time.Time) error {
	c.owner.mu.Lock()
	if c.entry.retired || c.owner.closed {
		deadline = time.Now()
	} else if deadline.IsZero() || deadline.After(c.deadline) {
		deadline = c.deadline
	}
	c.owner.mu.Unlock()
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *poolConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.entry.connections, c)
		c.owner.reapLocked()
		c.owner.mu.Unlock()
	})
	return err
}

type poolBody struct {
	io.ReadCloser
	lease  *httpLease
	cancel context.CancelFunc
	mu     sync.Mutex
	stop   func() bool
	once   sync.Once
}

func (b *poolBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}

func (b *poolBody) Close() error {
	var err error
	b.once.Do(func() {
		b.mu.Lock()
		if b.stop != nil {
			b.stop()
		}
		b.mu.Unlock()
		err = b.ReadCloser.Close()
		b.cancel()
		b.lease.release()
	})
	return err
}

func (t *restrictedTransport) invalidate(id string) {
	t.invalidateBefore(id, 0)
}

// Provider revisions only increase (deleted IDs cannot be recreated). An old
// successful read therefore cannot retire a newer observation's generation.
func (t *restrictedTransport) invalidateBefore(id string, revision int64) {
	t.mu.Lock()
	entries := slices.Clone(t.entries)
	// Mark all matching generations atomically before closing idle sockets.
	for _, e := range entries {
		if e.key.provider == id && (revision == 0 || e.key.revision < revision) {
			e.retired = true
			e.cancel()
		}
	}
	t.mu.Unlock()
	for _, e := range entries {
		if e.key.provider == id && (revision == 0 || e.key.revision < revision) {
			t.retire(e)
		}
	}
}

// Close is terminal and idempotent; unlike CloseIdleConnections it also seals
// admission, cancels request bodies/dials, and closes outstanding sockets.
func (t *restrictedTransport) Close() {
	t.mu.Lock()
	t.closed = true
	entries := slices.Clone(t.entries)
	var connections []*poolConn
	for _, e := range entries {
		e.retired = true
		e.cancel()
		for l := range e.leases {
			l.cancel()
		}
		for c := range e.connections {
			connections = append(connections, c)
		}
	}
	t.mu.Unlock()
	for _, e := range entries {
		t.retire(e)
	}
	for _, c := range connections {
		_ = c.Close()
	}
}
