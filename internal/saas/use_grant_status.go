package saas

import (
	"context"

	"github.com/mrchypark/rhiza"
)

// UseGrantStatus is an owner-side metadata snapshot, never an execution capability.
// A read-authorized application may inspect consent targeting another consumer.
type UseGrantStatus struct {
	Grant                UseGrant `json:"grant"`
	ConnectionGeneration string   `json:"connection_generation"`
}

func (s *CredentialStore) GetUseGrantStatus(ctx context.Context, owner, collection, connection, id, resource string, authority func() (string, []any)) (UseGrantStatus, error) {
	if !s.validUseTarget(ctx, owner, collection, connection) || !validText(id) || !validGrantResource(resource) {
		return UseGrantStatus{}, ErrUseGrantInvalid
	}
	auth, args, err := authorityGuard(authority)
	if err != nil {
		return UseGrantStatus{}, err
	}
	parent, parentArgs := s.useOwnerGuard(owner, collection, connection)
	query := `SELECT ` + useGrantColumns + `,
		(SELECT c.generation FROM auth_collection_connections c WHERE c.id=saas_use_grants.connection_id AND c.collection_id=saas_use_grants.collection_id AND c.owner_subject=saas_use_grants.owner_subject)
		FROM saas_use_grants WHERE owner_subject=? AND collection_id=? AND connection_id=? AND id=? AND resource=? AND ` + parent + ` AND (` + auth + `)`
	values := append([]any{owner, collection, connection, id, resource}, parentArgs...)
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: append(values, args...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return UseGrantStatus{}, err
	}
	if len(q.Rows) != 1 {
		return UseGrantStatus{}, ErrUseGrantNotFound
	}
	row := q.Rows[0]
	if len(row) != 18 {
		return UseGrantStatus{}, ErrUseGrantInvalid
	}
	grant, err := decodeUseGrant(row[:17])
	if err != nil {
		return UseGrantStatus{}, err
	}
	generation, ok := row[17].(string)
	if !ok || generation == "" {
		return UseGrantStatus{}, ErrUseGrantInvalid
	}
	return UseGrantStatus{Grant: grant, ConnectionGeneration: generation}, nil
}
