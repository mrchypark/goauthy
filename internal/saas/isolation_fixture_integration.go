//go:build goauthy_integration

package saas

// Synthetic setup and synchronized snapshots only; no normal-binary hooks.
import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var IsolationRoutes = []string{"oauth-healthy", "oauth-header", "oauth-cancel", "api-healthy", "api-body", "api-dial"}

type IsolationPoolSample struct {
	Owner                                         string
	Entries, Retiring, Leases, Dials, Connections int
	DNS, TCP, TLS, DialFailures                   int64
}

type IsolationFixture struct {
	Providers                      *ProviderStore
	Credentials                    *CredentialStore
	Grants                         map[string]string
	secretIDs, accessTokens        map[string]string // immutable before the first dispatch
	mixed                          atomic.Bool
	dns, tcp, handshakes, failures [2]atomic.Int64
}

func (f *IsolationFixture) IdentifySecret(secret string) string { return f.secretIDs[secret] }
func (f *IsolationFixture) AccessToken(id string) string        { return f.accessTokens[id] }

type isolationResolver struct{ count *atomic.Int64 }

func (r isolationResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.count.Add(1)
	for i, route := range IsolationRoutes {
		if host == route+".example.com" {
			return []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, byte(10 + i)})}, nil
		}
	}
	return nil, fmt.Errorf("unmapped fixture hostname")
}

func IntegrationIsolationTLS(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(113), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, route := range IsolationRoutes {
		template.DNSNames = append(template.DNSNames, route+".example.com")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	server.StartTLS()
	return server
}

func (f *IsolationFixture) SetMixed(v bool) { f.mixed.Store(v) }
func (f *IsolationFixture) Pools() []IsolationPoolSample {
	out := make([]IsolationPoolSample, 0, 2)
	for i, owner := range []*restrictedTransport{&f.Providers.http, &f.Credentials.http} {
		s := IsolationPoolSample{Owner: []string{"oauth", "api"}[i], DNS: f.dns[i].Load(), TCP: f.tcp[i].Load(), TLS: f.handshakes[i].Load(), DialFailures: f.failures[i].Load()}
		owner.mu.Lock()
		for _, e := range owner.entries {
			s.Entries++
			if e.retired {
				s.Retiring++
			}
			s.Leases += len(e.leases)
			s.Dials += e.dials
			s.Connections += len(e.connections)
		}
		owner.mu.Unlock()
		out = append(out, s)
	}
	return out
}

// A finite inventory is seeded once. No credential is repaired/recycled later.
// Measured requests use production browser/bearer authorization, not this seed guard.
func IntegrationIsolation(t testing.TB, db *rhiza.DB, keys *oidc.Keyring, server *httptest.Server, inventory int, resource string) *IsolationFixture {
	t.Helper()
	ctx := t.Context()
	providers, err := NewProviderStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := NewCredentialStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	f := &IsolationFixture{Providers: providers, Credentials: credentials, Grants: make(map[string]string), secretIDs: make(map[string]string), accessTokens: make(map[string]string)}
	providers.OnPolicyChange = credentials.InvalidateProviderConnections
	t.Cleanup(providers.CloseConnections)
	t.Cleanup(credentials.CloseConnections)
	// A closed local listener supplies real connect failures. Unexpected reuse of
	// that port fails the dispatch-count oracle; there is no public fallback.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddress := listener.Addr().String()
	listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for i, owner := range []*restrictedTransport{&providers.http, &credentials.http} {
		owner.base = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
		owner.resolver = isolationResolver{&f.dns[i]}
		owner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, fmt.Errorf("unmapped fixture address")
			}
			n := -1
			for index := range IsolationRoutes {
				if host == fmt.Sprintf("8.8.8.%d", 10+index) {
					n = index
				}
			}
			if n < 0 || i == 0 && n > 2 || i == 1 && n < 3 {
				return nil, fmt.Errorf("unmapped fixture port")
			}
			target := server.Listener.Addr().String()
			if n == 5 && f.mixed.Load() {
				target = refusedAddress
			}
			c, err := (&net.Dialer{}).DialContext(ctx, network, target)
			if err != nil {
				f.failures[i].Add(1)
			} else {
				f.tcp[i].Add(1)
			}
			return c, err
		}
	}
	server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		index := 0
		if strings.HasPrefix(hello.ServerName, "api-") {
			index = 1
		}
		f.handshakes[index].Add(1)
		return nil, nil
	}
	for _, owner := range []*restrictedTransport{&providers.http, &credentials.http} {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://unmapped.example.test/", nil)
		if response, err := owner.RoundTrip(req); err == nil {
			response.Body.Close()
			t.Fatal("unmapped DNS permitted")
		}
		if conn, err := owner.dial(ctx, "tcp", "1.1.1.1:443"); err == nil {
			conn.Close()
			t.Fatal("unmapped dial permitted")
		}
	}
	guard := func() (string, []any) {
		return `EXISTS(SELECT 1 FROM identity_users WHERE subject='owner' AND disabled=0)`, nil
	}
	execute := func(id, sql string, args ...any) {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: id, SQL: sql, Args: args}); err != nil {
			t.Fatal(err)
		}
	}
	for ri, route := range IsolationRoutes {
		endpoint := "https://" + route + ".example.com/" + route
		in := ProviderInput{ID: route, Name: route, Enabled: true}
		method := "oauth2"
		if ri < 3 {
			in.Kind = "oauth2"
			in.ClientID = "client"
			in.ClientSecret = "synthetic-secret"
			in.CallbackURI = "https://auth.example/callback"
			in.AuthorizationURL = endpoint + "/authorize"
			in.TokenURL = endpoint + "/token"
			in.IdentityEndpoint = endpoint + "/identity"
			in.SubjectField = "sub"
			in.Scopes = []string{"openid"}
			in.AuthStyle = "header"
		} else {
			method = "api_key"
			in.Kind = method
			in.Connector = &APIKeyConnectorConfig{ID: route, Header: "Authorization", Prefix: "Bearer ", Operations: []APIKeyOperationConfig{{ID: "read", URL: endpoint + "/read", ResponseFields: map[string]string{"value": "string"}}}}
		}
		if _, err := providers.Create(ctx, in, guard); err != nil {
			t.Fatal(err)
		}
		execute("definition-"+route, `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,1,1,'definition','[]',?)`, route, route, method, `["`+route+`"]`)
		for _, phase := range []string{"baseline", "mixed", "recovery", "control"} {
			count := inventory
			if phase == "control" {
				count = 1
			}
			if phase == "recovery" {
				count = 12
				if ri != 0 && ri != 3 {
					continue
				}
			}
			for j := 0; j < count; j++ {
				id := fmt.Sprintf("%s-%s-%03d", phase, route, j)
				secret, access := rand.Text(), rand.Text()
				f.secretIDs[secret], f.secretIDs[access], f.accessTokens[id] = id, id, access
				execute("connection-"+id, `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,'owner','draft',1,1,'{}',?)`, id, route, id)
				if ri < 3 {
					if err := credentials.Install(ctx, credentialBinding{"owner", route, id, route, id, 1}, credential{AccountID: "account", AccessToken: "old", RefreshToken: secret, ExpiresAtUnixMS: time.Now().Add(time.Hour).UnixMilli(), Scopes: []string{"openid"}}, guard); err != nil {
						t.Fatal(err)
					}
				} else {
					c, err := credentials.APIKeyConnector(ctx, "owner", route, id, guard)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = credentials.PutBoundAPIKey(ctx, "owner", route, id, 0, secret, c, c.Digest(), guard); err != nil {
						t.Fatal(err)
					}
					g, err := credentials.CreateUseGrant(ctx, "owner", route, id, resource, UseGrantInput{ConsumerClientID: "consumer", Mode: "proxy", Purpose: "synthetic measurement", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}, guard)
					if err != nil {
						t.Fatal(err)
					}
					f.Grants[id] = g.ID
				}
			}
		}
	}
	return f
}
