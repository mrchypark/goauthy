package saas

import (
	"context"
	"net/http"

	"github.com/mrchypark/rhiza"
)

// Provenance is separate from connector configuration/digest. A registered
// adapter must recheck this revision even after its transport has been evicted.
type providerHTTPBinding struct {
	db       *rhiza.DB
	id       string
	kind     string
	revision int64
}

func (b providerHTTPBinding) check(ctx context.Context) error {
	if b.id == "" {
		return nil
	}
	if b.db == nil || b.revision < 1 {
		return errSaaSHTTP
	}
	r, err := b.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM saas_providers WHERE id=? AND revision=? AND kind=? AND enabled=1 AND deleted=0`, Args: []any{b.id, b.revision, b.kind}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 {
		return errSaaSHTTP
	}
	return nil
}

type providerHTTPTransport struct {
	owner   *restrictedTransport
	binding providerHTTPBinding
}

func (t *providerHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.owner.roundTrip(req, t.binding)
}

func providerHTTPClient(owner *restrictedTransport, db *rhiza.DB, id, kind string, revision int64) *http.Client {
	client := newSaaSHTTPClient()
	client.Transport = &providerHTTPTransport{owner: owner, binding: providerHTTPBinding{db: db, id: id, kind: kind, revision: revision}}
	return client
}

// CloseConnections seals this store's outbound owner after inbound work drains.
func (s *ProviderStore) CloseConnections()   { s.http.Close() }
func (s *CredentialStore) CloseConnections() { s.http.Close() }

// InvalidateProviderConnections is wired to the provider store's successful
// local mutations. Remote mutations are detected by each dispatch-time check.
func (s *CredentialStore) InvalidateProviderConnections(id string) { s.http.invalidate(id) }

func (s *ProviderStore) invalidateConnections(id string) {
	s.http.invalidate(id)
	if s.OnPolicyChange != nil {
		s.OnPolicyChange(id)
	}
}

// CloseConnections seals only a directly constructed adapter's private owner.
// Registered adapters borrow their store's owner, which the store closes.
func (o *OAuth2) CloseConnections()          { closeDirectHTTPClient(o.client) }
func (c *APIKeyConnector) CloseConnections() { closeDirectHTTPClient(c.client) }
func (g *GitHub) CloseConnections()          { g.oauth.CloseConnections() }

func closeDirectHTTPClient(client *http.Client) {
	if t, ok := client.Transport.(*restrictedTransport); ok {
		t.Close()
	}
}
