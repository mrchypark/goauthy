package scim

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// UserMappingStore is the provider-scoped durable link used when projecting
// group membership. Links are immutable: a changed remote id fails closed.
type UserMappingStore struct{ DB *rhiza.DB }

func NewUserMappingStore(db *rhiza.DB) *UserMappingStore { return &UserMappingStore{DB: db} }

func (s *UserMappingStore) Put(ctx context.Context, clientID, localID, remoteID string, now time.Time) error {
	if s == nil || s.DB == nil || ctx == nil || !validOutboxClientID(clientID) || !validIdentifier(localID) || validRemoteID(remoteID) != nil || now.IsZero() || now.UnixMilli() < 0 {
		return ErrOutboxInvalid
	}
	_, err := storage.Execute(ctx, s.DB, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("scim-map/%s/%d", digestString(clientID+"\x00"+localID+"\x00"+remoteID), now.UnixMilli()), SQL: `INSERT INTO scim_user_mappings (client_id,local_external_id,remote_user_id,updated_at_unix_ms) VALUES (?,?,?,?) ON CONFLICT(client_id,local_external_id) DO NOTHING`, Args: []any{clientID, localID, remoteID, now.UnixMilli()}})
	if err != nil {
		return err
	}
	got, found, err := s.Lookup(ctx, clientID, localID)
	if err != nil {
		return err
	}
	if !found {
		return ErrIdentifierChanged
	}
	if got != remoteID {
		return ErrIdentifierChanged
	}
	return nil
}

func (s *UserMappingStore) Lookup(ctx context.Context, clientID, localID string) (string, bool, error) {
	if s == nil || s.DB == nil || ctx == nil || !validOutboxClientID(clientID) || !validIdentifier(localID) {
		return "", false, ErrOutboxInvalid
	}
	r, err := s.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT remote_user_id FROM scim_user_mappings WHERE client_id=? AND local_external_id=?`, Args: []any{clientID, localID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", false, err
	}
	if len(r.Rows) == 0 {
		return "", false, nil
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 1 {
		return "", false, errors.New("invalid SCIM user mapping")
	}
	id, ok := r.Rows[0][0].(string)
	if !ok || validRemoteID(id) != nil {
		return "", false, errors.New("invalid SCIM user mapping")
	}
	return id, true, nil
}

// Delete removes a link only when it still identifies the remote record that
// completed the deletion. This prevents one provider's mapping from removing
// another's, and makes an already-removed link harmless.
func (s *UserMappingStore) Delete(ctx context.Context, clientID, localID, remoteID string, now time.Time) error {
	if s == nil || s.DB == nil || ctx == nil || !validOutboxClientID(clientID) || !validIdentifier(localID) || validRemoteID(remoteID) != nil || now.IsZero() || now.UnixMilli() < 0 {
		return ErrOutboxInvalid
	}
	_, err := storage.Execute(ctx, s.DB, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("scim-unmap/%s/%d", digestString(clientID+"\x00"+localID+"\x00"+remoteID), now.UnixMilli()), SQL: `DELETE FROM scim_user_mappings WHERE client_id=? AND local_external_id=? AND remote_user_id=?`, Args: []any{clientID, localID, remoteID}})
	return err
}

func (s *UserMappingStore) Members(ctx context.Context, clientID string, localIDs []string) (map[string]string, error) {
	if s == nil || s.DB == nil || ctx == nil || !validOutboxClientID(clientID) {
		return nil, ErrOutboxInvalid
	}
	result := make(map[string]string, len(localIDs))
	for _, localID := range localIDs {
		id, found, err := s.Lookup(ctx, clientID, localID)
		if err != nil {
			return nil, err
		}
		if found {
			result[localID] = id
		}
	}
	return result, nil
}
