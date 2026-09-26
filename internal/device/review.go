package device

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mrchypark/rhiza"
)

// Review is the non-secret consent metadata for a pending device grant.
type Review struct {
	ClientID string
	Scopes   []string
	Resource string
	ForceMFA bool
}

// Review returns a pending, unexpired grant using the normalized user code.
func (s *Store) Review(ctx context.Context, userCode string, now time.Time) (Review, error) {
	normalized := NormalizeUserCode(userCode)
	if s == nil || s.db == nil || !validUserCode(normalized) {
		return Review{}, ErrInvalid
	}
	now = now.UTC().Truncate(time.Millisecond)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT g.client_id,g.scopes_json,g.resource,COALESCE(c.force_mfa,0)
   FROM oauth_device_grants g LEFT JOIN managed_oauth_clients c ON c.id=g.client_id
   WHERE g.user_code_digest = ? AND g.state = 'pending' AND g.expires_at_unix_ms > ?
   AND ((g.managed_client_generation IS NULL AND c.id IS NULL) OR
        (g.managed_client_generation=c.generation AND c.enabled=1 AND c.deleted=0))`,
		Args:        []any{digest(normalized), now.UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return Review{}, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return Review{}, ErrInvalid
	}
	row := result.Rows[0]
	clientID, ok := row[0].(string)
	if !ok || clientID == "" {
		return Review{}, ErrInvalid
	}
	rawScopes, ok := row[1].(string)
	if !ok {
		return Review{}, ErrInvalid
	}
	var scopes []string
	if json.Unmarshal([]byte(rawScopes), &scopes) != nil {
		return Review{}, ErrInvalid
	}
	resource := ""
	if row[2] != nil {
		resource, ok = row[2].(string)
		if !ok {
			return Review{}, ErrInvalid
		}
	}
	if !validResourceOrEmpty(resource) {
		return Review{}, ErrInvalid
	}
	mfa, ok := row[3].(int64)
	if !ok || (mfa != 0 && mfa != 1) {
		return Review{}, ErrInvalid
	}
	return Review{ClientID: clientID, Scopes: scopes, Resource: resource, ForceMFA: mfa == 1}, nil
}
