package saas

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func registeredPoolFixture(t testing.TB) (*ProviderStore, ProviderInput, *poolCounts, *httptest.Server) {
	t.Helper()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	in := providerInputForTest("secret")
	in.TokenURL = "https://example.com/token"
	in.IdentityEndpoint = "https://example.com/identity"
	in.SubjectField = "sub"
	if _, err := store.Create(ctx, in, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			if r.Method != "POST" || r.Header.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" {
				t.Error("wrong token request credentials")
			}
			_, _ = io.WriteString(w, `{"access_token":"access","token_type":"Bearer","refresh_token":"next","scope":"read:user","expires_in":3600}`)
		} else {
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Error("wrong identity request credentials")
			}
			_, _ = io.WriteString(w, `{"sub":"account"}`)
		}
	}))
	t.Cleanup(server.Close)
	counts := configurePoolTLS(t, &store.http, server)
	return store, in, counts, server
}

func TestSaaSPoolRegisteredOAuthReconstructionAndStaleAdapter(t *testing.T) {
	store, in, counts, _ := registeredPoolFixture(t)
	ctx := context.Background()
	var stale *OAuth2
	for i := 0; i < 3; i++ {
		o, err := store.LoadOAuth2(ctx, in.ID, credentialAuthority())
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			stale = o
			if len(store.http.entries) != 0 {
				t.Fatal("metadata load allocated entries")
			}
		}
		token, err := o.Refresh(ctx, "refresh")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = o.Identity(ctx, token.AccessToken); err != nil {
			t.Fatal(err)
		}
	}
	if counts.tcp.Load() != 1 || counts.tls.Load() != 1 || counts.dns.Load() != 7 {
		t.Fatalf("tcp=%d tls=%d dns=%d", counts.tcp.Load(), counts.tls.Load(), counts.dns.Load())
	}
	in.Name = "new revision"
	if _, err := store.Update(ctx, in.ID, 1, in, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Refresh(ctx, "refresh"); err == nil {
		t.Fatal("stale adapter used evicted pool")
	}
	if counts.tcp.Load() != 1 {
		t.Fatal("stale adapter dialed")
	}
	fresh, err := store.LoadOAuth2(ctx, in.ID, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.Refresh(ctx, "refresh"); err != nil {
		t.Fatal(err)
	}
	if counts.tcp.Load() != 2 {
		t.Fatal("revision reused old transport")
	}
	// Simulate a mutation committed by a different process: no local callback.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "remote-disable", SQL: `UPDATE saas_providers SET enabled=0,revision=revision+1 WHERE id=?`, Args: []any{in.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.Identity(ctx, "access"); err == nil {
		t.Fatal("identity bypassed fresh dispatch check")
	}
	store.http.invalidate(in.ID)
	if _, err = fresh.Refresh(ctx, "refresh"); err == nil {
		t.Fatal("cache miss bypassed provider check")
	}
	if counts.tcp.Load() != 2 {
		t.Fatal("disabled provider dialed")
	}
}

func TestSaaSPoolRegisteredAPIKeyProvenanceAndInvalidation(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	providers, err := NewProviderStore(db, store.keys)
	if err != nil {
		t.Fatal(err)
	}
	providers.OnPolicyChange = store.InvalidateProviderConnections
	defer providers.CloseConnections()
	cfg := validAPIKeyConnectorConfig()
	for i := range cfg.Operations {
		cfg.Operations[i].URL = strings.ReplaceAll(cfg.Operations[i].URL, "api.example.com", "example.com")
	}
	in := ProviderInput{ID: cfg.ID, Name: "Billing", Kind: "api_key", Enabled: true, Connector: &cfg}
	if _, err := providers.Create(ctx, in, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "pool-api-collection", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='["billing"]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Error("wrong API key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"account","active":true}`)
	}))
	defer server.Close()
	counts := configurePoolTLS(t, &store.http, server)
	var stale *APIKeyConnector
	for i := 0; i < 2; i++ {
		connector, err := store.APIKeyConnector(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			stale = connector
			if len(store.http.entries) != 0 {
				t.Fatal("connector metadata allocated entries")
			}
			if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-key", connector, connector.Digest(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.CallAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, connector, "account", credentialAuthority()); err != nil {
			t.Fatal(err)
		}
	}
	if counts.tcp.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("tcp=%d calls=%d", counts.tcp.Load(), calls.Load())
	}
	direct, err := NewAPIKeyConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CallAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, direct, "account", credentialAuthority()); err == nil {
		t.Fatal("digest-only direct adapter accepted registered credential")
	}
	// Remove the reference so the ordinary provider update API can commit.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "pool-api-detach", SQL: `UPDATE auth_collection_definitions SET providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	in.Name = "revised"
	if _, err := providers.Update(ctx, in.ID, 1, in, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	waitPoolEmpty(t, &store.http) // ProviderStore mutation invalidated sibling owner.
	if _, err := stale.request(ctx, "account", credential{APIKey: "synthetic-key", ConnectorDigest: stale.Digest()}); err == nil {
		t.Fatal("stale retained connector accepted")
	}
	if calls.Load() != 2 {
		t.Fatal("rejected adapter reached provider")
	}
}

func TestSaaSPoolRefreshFailureRemainsUncertain(t *testing.T) {
	f := newRefreshFixture(t, "account-1")
	configurePoolTLS(t, &f.p.http, f.server)
	f.mode.Store("http-failure")
	// Use the public loader path, never f.o's fixture replacement transport.
	if _, err := f.s.RefreshOAuth2(f.ctx, f.p, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, 1, credentialAuthority()); err != errRefreshUncertain {
		t.Fatalf("refresh=%v", err)
	}
	if _, err := f.s.RefreshOAuth2(f.ctx, f.p, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, 1, credentialAuthority()); err == nil {
		t.Fatal("uncertain refresh replayed")
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatalf("token calls=%d", f.tokenCalls.Load())
	}
}

func TestSaaSPoolProviderOriginAndOwnerIsolation(t *testing.T) {
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		in := providerInputForTest("secret")
		in.ID = id
		if _, err := store.Create(ctx, in, credentialAuthority()); err != nil {
			t.Fatal(err)
		}
	}
	headers := make(chan string, 6)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("Authorization")
		if r.TLS.ServerName != strings.Split(r.Host, ":")[0] {
			t.Error("logical Host/SNI mismatch")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	counts := configurePoolTLS(t, &store.http, server)
	for i, target := range []struct{ id, url string }{
		{"first", "https://example.com/"}, {"first", "https://example.com/"},
		{"second", "https://example.com/"}, {"first", "https://other.example.com/"},
		{"first", "https://example.com:444/"},
	} {
		o, err := store.LoadOAuth2(ctx, target.id, credentialAuthority())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", target.url, nil)
		req.Header.Set("Authorization", "Bearer user-"+string(rune('a'+i)))
		resp, err := o.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if <-headers != req.Header.Get("Authorization") {
			t.Fatal("pool retained previous caller credentials")
		}
	}
	if counts.tcp.Load() != 4 || counts.tls.Load() != 4 {
		t.Fatalf("tcp=%d tls=%d", counts.tcp.Load(), counts.tls.Load())
	}
	other, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	otherCounts := configurePoolTLS(t, &other.http, server)
	o, err := other.LoadOAuth2(ctx, "first", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp, err := o.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if otherCounts.tcp.Load() != 1 {
		t.Fatal("owners shared connections")
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "remote-revision", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id='first'`}); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.LoadOAuth2(ctx, "first", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	resp, err = fresh.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	store.http.mu.Lock()
	for _, entry := range store.http.entries {
		if entry.key.provider == "first" && entry.key.revision < 2 && !entry.retired {
			t.Error("remote revision left old origin reusable")
		}
	}
	store.http.mu.Unlock()
}

func TestSaaSPoolProviderReadErrorFailsClosed(t *testing.T) {
	store, in, counts, _ := registeredPoolFixture(t)
	o, err := store.LoadOAuth2(context.Background(), in.ID, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Refresh(context.Background(), "refresh"); err == nil {
		t.Fatal("provider read error fell back to cached policy")
	}
	if counts.tcp.Load() != 0 {
		t.Fatal("unverified provider dialed")
	}
}

// Reproduce the original transport policy only for the measured baseline:
// one DNS lookup, first approved address, a fresh non-keepalive transport.
type noReuseBaseline struct{ owner *restrictedTransport }

func (b noReuseBaseline) RoundTrip(req *http.Request) (*http.Response, error) {
	origin, err := canonicalOrigin(req)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(origin)
	addresses, err := b.owner.resolve(req.Context(), host)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: b.owner.base.TLSClientConfig.RootCAs}, DialContext: b.owner.dial}
	clone := req.Clone(req.Context())
	clone.URL = cloneURL(req.URL, net.JoinHostPort(addresses[0].String(), port))
	clone.Host = req.URL.Host
	return tr.RoundTrip(clone)
}

func BenchmarkSaaSRegisteredRefreshPool(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		b.Run(map[bool]string{false: "before-no-reuse", true: "pooled"}[reuse], func(b *testing.B) {
			store, in, counts, server := registeredPoolFixture(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				o, err := store.LoadOAuth2(context.Background(), in.ID, credentialAuthority())
				if err != nil {
					b.Fatal(err)
				}
				if !reuse {
					o.client.Transport = noReuseBaseline{owner: &store.http}
				}
				if _, err = o.Refresh(context.Background(), "refresh"); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			store.CloseConnections()
			server.Close()
			waitPoolEmpty(b, &store.http)
			b.ReportMetric(float64(counts.dns.Load())/float64(b.N), "DNS/op")
			b.ReportMetric(float64(counts.tcp.Load())/float64(b.N), "TCP/op")
			b.ReportMetric(float64(counts.tls.Load())/float64(b.N), "TLS/op")
		})
	}
}

func BenchmarkSaaSRegisteredRefreshPoolConcurrent(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		b.Run(map[bool]string{false: "before-no-reuse", true: "pooled"}[reuse], func(b *testing.B) {
			store, in, counts, server := registeredPoolFixture(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i += saasPoolLeases {
				var wg sync.WaitGroup
				for j := i; j < min(i+saasPoolLeases, b.N); j++ {
					wg.Go(func() {
						o, err := store.LoadOAuth2(context.Background(), in.ID, credentialAuthority())
						if err != nil {
							b.Error(err)
							return
						}
						if !reuse {
							o.client.Transport = noReuseBaseline{owner: &store.http}
						}
						if _, err = o.Refresh(context.Background(), "refresh"); err != nil {
							b.Error(err)
						}
					})
				}
				wg.Wait()
			}
			b.StopTimer()
			store.CloseConnections()
			server.Close()
			waitPoolEmpty(b, &store.http)
			b.ReportMetric(float64(counts.dns.Load())/float64(b.N), "DNS/op")
			b.ReportMetric(float64(counts.tcp.Load())/float64(b.N), "TCP/op")
			b.ReportMetric(float64(counts.tls.Load())/float64(b.N), "TLS/op")
		})
	}
}
