//go:build goauthy_integration

package saas

// This fixture exists only in explicitly tagged integration builds. It exposes
// no transport configuration in normal binaries; cmd/goauthy's integration test
// supplies the real runtime-owned database and exercises public RefreshOAuth2.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type integrationResolver struct{}

func (integrationResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func IntegrationRegisteredRefresh(t testing.TB, db *rhiza.DB, server *httptest.Server) (*ProviderStore, *CredentialStore, *oidc.Keyring) {
	t.Helper()
	ctx := t.Context()
	keyDir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := oidc.LoadKeyring(keyDir, "master")
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := NewCredentialStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	providers, err := NewProviderStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	authority := func() (string, []any) { return "1", nil }
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "shutdown-fixture", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms) VALUES (1,1,'old','master',?,'prepared',1)`, Args: []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES('owner','owner','phc')`},
		{SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES('collection','Collection','oauth2',1,1,'definition-generation','[]','["provider"]')`},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES('connection','collection','owner','draft',1,1,'{}','generation')`},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err = providers.Create(ctx, ProviderInput{ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: "secret", CallbackURI: "https://auth.example/callback", AuthorizationURL: "https://example.com/authorize", TokenURL: "https://example.com/token", Scopes: []string{"openid"}, AuthStyle: "header", IdentityEndpoint: "https://example.com/identity", SubjectField: "sub"}, authority); err != nil {
		t.Fatal(err)
	}
	binding := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	if err = credentials.Install(ctx, binding, credential{AccountID: "account", AccessToken: "old", RefreshToken: "once", Scopes: []string{"openid"}, ExpiresAtUnixMS: time.Now().Add(time.Hour).UnixMilli()}, authority); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	providers.http.base = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	providers.http.resolver = integrationResolver{}
	providers.http.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	providers.OnPolicyChange = credentials.InvalidateProviderConnections
	t.Cleanup(providers.CloseConnections)
	t.Cleanup(credentials.CloseConnections)
	return providers, credentials, keys
}
