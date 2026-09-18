package dcr

import (
	"context"
	"fmt"

	"github.com/mrchypark/rhiza"
)

// HasExactRedirectURI reports whether uri is stored verbatim by any dynamic
// client. Redirect URIs are identifiers here: they are deliberately neither
// parsed nor normalized, so RFC8252 loopback templates cannot match a port and
// a prefix, query, or fragment cannot broaden an existing registration.
func (s *Store) HasExactRedirectURI(ctx context.Context, uri string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("%w: store is not configured", ErrInvalid)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT redirect_uris_json FROM dynamic_oauth_clients`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	matched := false
	for _, row := range result.Rows {
		if len(row) != 1 {
			return false, fmt.Errorf("invalid dynamic client row")
		}
		redirects, err := decodeStrings(row[0])
		if err != nil {
			return false, fmt.Errorf("invalid dynamic client redirect URIs: %w", err)
		}
		for _, redirect := range redirects {
			if redirect == uri {
				matched = true
			}
		}
	}
	return matched, nil
}
