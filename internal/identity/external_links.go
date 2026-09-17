package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

var ErrExternalLinkConflict = errors.New("external identity link conflict")

// LinkExternal explicitly binds a validated upstream subject to an active
// local identity. Email is intentionally not part of this operation.
func (s *Store) LinkExternal(ctx context.Context, localSubject string, external upstreamprovider.SubjectResult, now time.Time) (upstreamprovider.LinkDecision, error) {
	if s == nil || s.db == nil {
		return upstreamprovider.LinkDecisionNone, ErrInvalidSubject
	}
	if err := validateSubject(localSubject); err != nil {
		return upstreamprovider.LinkDecisionNone, err
	}
	if err := external.Validate(); err != nil {
		return upstreamprovider.LinkDecisionNone, err
	}
	now = now.UTC().Truncate(time.Millisecond)
	key := external.ExternalKey()
	attemptBytes := make([]byte, 16)
	random := s.random
	if random == nil {
		random = rand.Read
	}
	if n, err := random(attemptBytes); err != nil || n != len(attemptBytes) {
		if err != nil {
			return upstreamprovider.LinkDecisionNone, err
		}
		return upstreamprovider.LinkDecisionNone, errors.New("short external link attempt")
	}
	attempt := base64.RawURLEncoding.EncodeToString(attemptBytes)
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("external-link", external.ProviderID, key, localSubject, strconv.FormatInt(now.UnixMilli(), 10), attempt),
		SQL: `INSERT INTO identity_external_links (provider_id,external_key,local_subject,linked_at_unix_ms)
			SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND disabled = 0)
			ON CONFLICT DO NOTHING`,
		Args: []any{external.ProviderID, key, localSubject, now.UnixMilli(), localSubject},
	})
	if err != nil {
		return upstreamprovider.LinkDecisionNone, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT l.local_subject,u.disabled FROM identity_external_links l LEFT JOIN identity_users u ON u.subject = l.local_subject WHERE l.provider_id = ? AND l.external_key = ?`, Args: []any{external.ProviderID, key}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return upstreamprovider.LinkDecisionNone, err
	}
	if len(result.Rows) > 1 || len(result.Rows) == 1 && len(result.Rows[0]) != 2 {
		return upstreamprovider.LinkDecisionNone, errors.New("invalid external identity link row")
	}
	if len(result.Rows) == 1 {
		linkedSubject, ok := result.Rows[0][0].(string)
		if !ok {
			return upstreamprovider.LinkDecisionNone, errors.New("invalid external identity link subject")
		}
		if linkedSubject != localSubject {
			return upstreamprovider.LinkDecisionConflict, ErrExternalLinkConflict
		}
		if result.Rows[0][1] == nil {
			return upstreamprovider.LinkDecisionNone, ErrInactiveSubject
		}
		disabled, ok := result.Rows[0][1].(int64)
		if !ok || (disabled != 0 && disabled != 1) {
			return upstreamprovider.LinkDecisionNone, errors.New("invalid linked identity state")
		}
		if disabled != 0 {
			return upstreamprovider.LinkDecisionNone, ErrInactiveSubject
		}
		return upstreamprovider.LinkDecisionLinked, nil
	}
	result, err = s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM identity_external_links WHERE provider_id = ? AND local_subject = ?`, Args: []any{external.ProviderID, localSubject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return upstreamprovider.LinkDecisionNone, err
	}
	if len(result.Rows) != 0 {
		return upstreamprovider.LinkDecisionConflict, ErrExternalLinkConflict
	}
	return upstreamprovider.LinkDecisionNone, ErrInactiveSubject
}

// FindExternalLink returns the local subject mapped to an upstream subject.
func (s *Store) FindExternalLink(ctx context.Context, external upstreamprovider.SubjectResult) (string, bool, error) {
	if s == nil || s.db == nil {
		return "", false, ErrInvalidSubject
	}
	if err := external.Validate(); err != nil {
		return "", false, err
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT l.local_subject FROM identity_external_links l JOIN identity_users u ON u.subject = l.local_subject AND u.disabled = 0 WHERE l.provider_id = ? AND l.external_key = ?`, Args: []any{external.ProviderID, external.ExternalKey()}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", false, err
	}
	if len(result.Rows) == 0 {
		return "", false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return "", false, errors.New("invalid external identity link row")
	}
	localSubject, ok := result.Rows[0][0].(string)
	if !ok {
		return "", false, errors.New("invalid external identity link subject")
	}
	return localSubject, true, nil
}

// UnlinkExternal removes a provider-scoped link. attempt must change for a
// later unlink after relink so Rhiza cannot suppress the newer mutation.
func (s *Store) UnlinkExternal(ctx context.Context, localSubject, providerID string, now time.Time, attempt string) error {
	if s == nil || s.db == nil {
		return ErrInvalidSubject
	}
	if err := validateSubject(localSubject); err != nil {
		return err
	}
	if err := (upstreamprovider.SubjectResult{ProviderID: providerID, Subject: "subject"}).Validate(); err != nil {
		return err
	}
	if attempt == "" || len(attempt) > 128 {
		return ErrInvalidSubject
	}
	now = now.UTC().Truncate(time.Millisecond)
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("external-unlink", providerID, localSubject, strconv.FormatInt(now.UnixMilli(), 10), attempt),
		SQL: `DELETE FROM identity_external_links
			WHERE provider_id = ? AND local_subject = ?
			AND EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND disabled = 0)`,
		Args: []any{providerID, localSubject, localSubject},
	})
	return err
}
