package cimd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testClientID = "https://metadata.example/client.json"

func TestParseTargetRejectsAmbiguousClientIDs(t *testing.T) {
	for _, raw := range []string{
		" http://metadata.example/client.json", "http://metadata.example/client.json", "https://user@metadata.example/client.json",
		"https://metadata.example/client.json?x=1", "https://metadata.example/client.json#x", "https://metadata.example/a/../client.json",
		"https://metadata.example/%2e%2e/client.json", "https://métadata.example/client.json", "https://127.1/client.json",
		"https://2130706433/client.json", "https://0x7f000001/client.json", "https://[fe80::1%25en0]/client.json", "https://8.8.8.8:8443/client.json",
	} {
		if _, err := parseTarget(raw); err == nil {
			t.Errorf("parseTarget(%q) succeeded", raw)
		}
	}
	if got, err := parseTarget(testClientID); err != nil || got.raw != testClientID || got.host != "metadata.example" {
		t.Fatalf("public target=%#v err=%v", got, err)
	}
	if _, err := parseTarget("https://metadata.example:443/client.json"); err != nil {
		t.Fatalf("explicit HTTPS port rejected: %v", err)
	}
}

func TestSafeAddressRejectsSpecialUse(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.2.1",
		"192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.0.1", "192.175.48.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "::ffff:8.8.8.8",
		"64:ff9b::1", "64:ff9b:1::1", "100::1", "2001:2::1", "2001:3::1", "2001:4:112::1",
		"2001:20::1", "2001:30::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if safeAddress(netip.MustParseAddr(raw)) {
			t.Errorf("safeAddress(%s)=true", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !safeAddress(netip.MustParseAddr(raw)) {
			t.Errorf("safeAddress(%s)=false", raw)
		}
	}
}

func TestResolveRejectsMixedDNSWithoutDial(t *testing.T) {
	f := NewFetcher()
	f.now = fixedNow
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	dialed := false
	f.dial = func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, errFetch }
	_, _, err := f.Fetch(context.Background(), testClientID)
	if !errorsIs(err, errUnsafeAddress) || dialed {
		t.Fatalf("err=%v dialed=%v", err, dialed)
	}
}

func TestResolveUnmapsHostsIPv4AnswersBeforeAddressPolicy(t *testing.T) {
	f := NewFetcher()
	f.now = fixedNow
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")}, nil
	}
	address, err := f.resolve(context.Background(), mustTarget(t, testClientID))
	if err != nil || address != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("address=%v err=%v", address, err)
	}

	dialed := false
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil
	}
	f.dial = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errFetch
	}
	if _, _, err := f.Fetch(context.Background(), testClientID); !errorsIs(err, errUnsafeAddress) || dialed {
		t.Fatalf("err=%v dialed=%v", err, dialed)
	}
}

func TestFetchPinsDNSDisablesProxyAndPreservesSNI(t *testing.T) {
	var gotHost, gotSNI, gotDial string
	server, roots := testTLSServer(t, "metadata.example", func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testDocument(t, testClientID))
	}, func(name string) { gotSNI = name })
	defer server.Close()
	f := newTestFetcher(roots, server.Listener.Addr().String())
	f.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		gotDial = address
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	metadata, _, err := f.Fetch(context.Background(), testClientID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID != testClientID || gotDial != "8.8.8.8:443" || gotHost != "metadata.example" || gotSNI != "metadata.example" {
		t.Fatalf("metadata=%#v dial=%q host=%q sni=%q", metadata, gotDial, gotHost, gotSNI)
	}
	if transport := f.transport(mustTarget(t, testClientID), netip.MustParseAddr("8.8.8.8")); transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("unsafe transport configuration")
	}
}

func TestFetchRejectsRedirectAndOversize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   []byte
		ct     string
	}{
		{"redirect", http.StatusFound, nil, "application/json"},
		{"html", http.StatusOK, testDocument(t, testClientID), "text/html"},
		{"too-large", http.StatusOK, make([]byte, maxDocumentBytes+1), "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			server, roots := testTLSServer(t, "metadata.example", func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Content-Type", tc.ct)
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "https://127.0.0.1/private")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}, nil)
			defer server.Close()
			f := newTestFetcher(roots, server.Listener.Addr().String())
			if _, _, err := f.Fetch(context.Background(), testClientID); err == nil || hits != 1 {
				t.Fatalf("err=%v hits=%d", err, hits)
			}
		})
	}
}

func TestFetchRejectsChunkedOversize(t *testing.T) {
	server, roots := testTLSServer(t, "metadata.example", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // retain chunked framing: no Content-Length fast path.
		_, _ = w.Write(make([]byte, maxDocumentBytes+1))
	}, nil)
	defer server.Close()
	f := newTestFetcher(roots, server.Listener.Addr().String())
	if _, _, err := f.Fetch(context.Background(), testClientID); err == nil {
		t.Fatal("chunked oversized response accepted")
	}
}

func TestDecodeMetadataStrictAndOptionalDefaults(t *testing.T) {
	target := mustTarget(t, testClientID)
	minimum := []byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`)
	metadata, err := decodeMetadata(minimum, target)
	if err != nil || metadata.Name != testClientID || len(metadata.RedirectURIs) != 1 {
		t.Fatalf("minimum=%#v err=%v", metadata, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"client_id":"https://metadata.example/client.json","client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`),
		[]byte(`{"client_id":"https://other.example/client.json","redirect_uris":["https://metadata.example/callback"]}`),
		[]byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://other.example/callback"]}`),
		[]byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"],"grant_types":["client_credentials"]}`),
		[]byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"],"grant_types":["authorization_code","refresh_token"]}`),
		[]byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example:8443/callback"]}`),
		[]byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"],"jwks_uri":"https://metadata.example/jwks"}`),
	} {
		if _, err := decodeMetadata(raw, target); err == nil {
			t.Errorf("invalid metadata accepted: %s", raw)
		}
	}
}

func TestDecodeMetadataAllowedResources(t *testing.T) {
	target := mustTarget(t, testClientID)
	base := `{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`
	resource := `https://resource.example.test/api`
	for _, tc := range []struct {
		name    string
		extra   string
		accept  bool
		present bool
		want    []string
	}{
		{name: "absent", extra: ``, accept: true},
		{name: "allow-list", extra: `,"allowed_resources":["` + resource + `"]`, accept: true, present: true, want: []string{resource}},
		{name: "explicit empty", extra: `,"allowed_resources":[]`, accept: true, present: true},
		{name: "duplicate", extra: `,"allowed_resources":["` + resource + `","` + resource + `"]`},
		{name: "http", extra: `,"allowed_resources":["http://resource.example.test"]`},
		{name: "query", extra: `,"allowed_resources":["` + resource + `?x=1"]`},
		{name: "unknown field", extra: `,"allowed_resource":"` + resource + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.TrimSuffix(base, "}") + tc.extra + "}"
			metadata, err := decodeMetadata([]byte(doc), target)
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%t err=%v metadata=%#v", err == nil, err, metadata)
			}
			if err == nil {
				if metadata.AllowedResourcesPresent != tc.present || !slices.Equal(metadata.AllowedResources, tc.want) {
					t.Fatalf("resources=%v present=%v, want %v/%v", metadata.AllowedResources, metadata.AllowedResourcesPresent, tc.want, tc.present)
				}
			}
		})
	}
}

func TestDecodeMetadataIgnoreUnknownAuthFlowsIsNarrowAndDeterministic(t *testing.T) {
	target := mustTarget(t, testClientID)
	base := `{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`
	cases := []struct {
		name       string
		doc        string
		ignore     bool
		want       bool
		wantGrants []string
	}{
		{name: "strict grant", doc: `{"grant_types":["authorization_code","urn:example:future"]}`, want: false},
		{name: "ignore grant", doc: `{"grant_types":["authorization_code","urn:example:future"]}`, ignore: true, want: true, wantGrants: []string{"authorization_code"}},
		{name: "retain known grants", doc: `{"grant_types":["authorization_code","client_credentials","password","refresh_token","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:token-exchange","urn:example:future"]}`, ignore: true, want: true, wantGrants: []string{"authorization_code", "client_credentials", "password", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"}},
		{name: "known grants without auth code", doc: `{"grant_types":["refresh_token","client_credentials"]}`, ignore: true, want: false},
		{name: "response stays strict", doc: `{"response_types":["code","future"]}`, ignore: true, want: false},
		{name: "auth method stays strict", doc: `{"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"future"}`, ignore: true, want: false},
		{name: "known public-incompatible auth method", doc: `{"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}`, ignore: true, want: false},
		{name: "known post auth method", doc: `{"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}`, ignore: true, want: false},
		{name: "known private-key auth method", doc: `{"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"private_key_jwt"}`, ignore: true, want: false},
		{name: "unknown grant only", doc: `{"grant_types":["urn:example:future"]}`, ignore: true, want: false},
		{name: "unknown grant with safe response", doc: `{"grant_types":["urn:example:future"],"response_types":["code"]}`, ignore: true, want: false},
		{name: "strict empty grant", doc: `{"grant_types":[]}`, want: false},
		{name: "empty grant", doc: `{"grant_types":[]}`, ignore: true, want: false},
		{name: "strict empty response", doc: `{"response_types":[]}`, want: false},
		{name: "empty response", doc: `{"response_types":[]}`, ignore: true, want: false},
		{name: "strict empty auth method", doc: `{"token_endpoint_auth_method":""}`, want: false},
		{name: "empty auth method", doc: `{"token_endpoint_auth_method":""}`, ignore: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := mergeJSON(base, tc.doc)
			metadata, err := decodeMetadataWithPolicy([]byte(doc), target, Policy{IgnoreUnknownAuthFlows: tc.ignore})
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%t err=%v metadata=%#v", err == nil, err, metadata)
			}
			if err == nil && (metadata.ID != testClientID || len(metadata.RedirectURIs) != 1) {
				t.Fatalf("metadata=%#v", metadata)
			}
			if err == nil && !slices.Equal(metadata.GrantTypes, tc.wantGrants) {
				t.Fatalf("grant_types=%v want=%v", metadata.GrantTypes, tc.wantGrants)
			}
		})
	}
}

func TestDecodeMetadataIgnoreUnknownAuthFlowsStillRejectsMalformedValues(t *testing.T) {
	target := mustTarget(t, testClientID)
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{name: "duplicate grant", doc: `{"grant_types":["authorization_code","authorization_code"]}`},
		{name: "duplicate response", doc: `{"response_types":["code","code"]}`},
		{name: "oversize grant", doc: `{"grant_types":["` + strings.Repeat("x", maxValueLength+1) + `"]}`},
		{name: "oversize method", doc: `{"token_endpoint_auth_method":"` + strings.Repeat("x", maxValueLength+1) + `"}`},
		{name: "whitespace grant", doc: `{"grant_types":[" authorization_code"]}`},
		{name: "control response", doc: `{"response_types":["code\n"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeMetadataWithPolicy([]byte(mergeJSON(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`, tc.doc)), target, Policy{IgnoreUnknownAuthFlows: true}); err == nil {
				t.Fatal("malformed flow value accepted")
			}
		})
	}
}

func mergeJSON(base, extra string) string {
	return strings.TrimSuffix(base, "}") + "," + strings.TrimPrefix(extra, "{")
}

func TestCacheExpiryFixedClockAndDirectives(t *testing.T) {
	now := fixedNow()
	for _, tc := range []struct {
		head http.Header
		want time.Duration
		ok   bool
	}{
		{http.Header{}, minCacheLifetime, true},
		{http.Header{"Cache-Control": {"max-age=1"}}, minCacheLifetime, true},
		{http.Header{"Cache-Control": {"max-age=999999999999"}}, maxCacheLifetime, true},
		{http.Header{"Cache-Control": {"max-age=" + strconv.FormatInt(int64(^uint64(0)>>1), 10)}}, maxCacheLifetime, true},
		{http.Header{"Cache-Control": {"max-age=3600"}, "Age": {"60"}}, 59 * time.Minute, true},
		{http.Header{"Cache-Control": {"max-age=3600"}, "Age": {strconv.FormatInt(int64(^uint64(0)>>1), 10)}}, 0, true},
		{http.Header{"Cache-Control": {"no-store"}}, 0, false},
		{http.Header{"Cache-Control": {"no-cache"}}, 0, false},
		{http.Header{"Cache-Control": {"private"}}, 0, false},
	} {
		got, err := cacheExpiry(tc.head, now)
		if (err == nil) != tc.ok || (tc.ok && !got.Equal(now.Add(tc.want))) {
			t.Errorf("header=%v expiry=%v err=%v", tc.head, got, err)
		}
	}
}

func TestFetchCancellationDoesNotWait(t *testing.T) {
	f := NewFetcher()
	f.now = fixedNow
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	started := make(chan struct{})
	f.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := f.Fetch(ctx, testClientID); done <- err }()
	<-started
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled fetch succeeded")
	}
}

func fixedNow() time.Time { return time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC) }

func newTestFetcher(roots *x509.CertPool, endpoint string) *Fetcher {
	f := NewFetcher()
	f.now = fixedNow
	f.roots = roots
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	f.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}
	return f
}

func testDocument(t *testing.T, id string) []byte {
	t.Helper()
	value, err := json.Marshal(map[string]any{"client_id": id, "client_name": "Metadata client", "redirect_uris": []string{"https://metadata.example/callback"}, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none", "scope": "openid profile"})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testTLSServer(t *testing.T, hostname string, handler http.HandlerFunc, onSNI func(string)) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(appendPEM(t, "CERTIFICATE", der), appendPEM(t, "PRIVATE KEY", mustPKCS8(t, private)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	config := &tls.Config{Certificates: []tls.Certificate{certificate}}
	if onSNI != nil {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { onSNI(hello.ServerName); return config, nil }
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = config
	server.StartTLS()
	return server, roots
}

func appendPEM(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return []byte("-----BEGIN " + typ + "-----\n" + encodePEM(der) + "-----END " + typ + "-----\n")
}

func encodePEM(der []byte) string { return base64.StdEncoding.EncodeToString(der) + "\n" }

func mustPKCS8(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustTarget(t *testing.T, raw string) target {
	t.Helper()
	target, err := parseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func errorsIs(err, target error) bool { return err == target }
