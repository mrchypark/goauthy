// Package cimd resolves cached Client ID Metadata Documents.
package cimd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	storeMaxMetadataBytes = 8192
	storeCleanupLimit     = 128
	storeActiveCacheCap   = 1024
)

var (
	ErrInvalidCache = errors.New("invalid CIMD cache value")
	ErrCacheFull    = errors.New("CIMD cache is full")
)

// Store is the shared, fail-closed CIMD metadata cache. It deliberately has
// no process-local fallback: metadata controls OAuth redirect and scope trust.
type Store struct{ db *rhiza.DB }

func NewStore(db *rhiza.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("CIMD store requires Rhiza DB")
	}
	return &Store{db: db}, nil
}

// Lookup reads a current cached document with a linearizable read. A cache
// miss is distinct from malformed persisted state, which fails closed.
func (s *Store) Lookup(ctx context.Context, clientID, policyDigest string, now time.Time) (Metadata, bool, error) {
	if s == nil || s.db == nil || !validCacheKey(clientID, policyDigest) || now.IsZero() {
		return Metadata{}, false, ErrInvalidCache
	}
	now = canonicalTime(now)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms
			FROM cimd_client_documents WHERE client_id = ? AND policy_digest = ? AND expires_at_unix_ms > ?`,
		Args: []any{clientID, policyDigest, now.UnixMilli()}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return Metadata{}, false, err
	}
	if len(result.Rows) == 0 {
		return Metadata{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return Metadata{}, false, ErrInvalidCache
	}
	row := result.Rows[0]
	encoded, encodedOK := row[0].(string)
	digest, digestOK := row[1].(string)
	fetched, fetchedOK := row[2].(int64)
	expires, expiresOK := row[3].(int64)
	if !encodedOK || !digestOK || !fetchedOK || !expiresOK || expires <= fetched || expires <= now.UnixMilli() {
		return Metadata{}, false, ErrInvalidCache
	}
	metadata, expected, err := decodeStoredMetadata(clientID, encoded)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(digest)) != 1 {
		return Metadata{}, false, ErrInvalidCache
	}
	return metadata, true, nil
}

// PutFirstWinner atomically bounds expired cleanup and admits a fetched
// document only if no current peer already cached the same client and policy.
// It rejects an uncertain before-ack commit before accepting a local winner.
func (s *Store) PutFirstWinner(ctx context.Context, clientID, policyDigest string, metadata Metadata, now time.Time, ttl time.Duration) (Metadata, error) {
	if s == nil || s.db == nil || !validCacheKey(clientID, policyDigest) || now.IsZero() || ttl <= 0 {
		return Metadata{}, ErrInvalidCache
	}
	now = canonicalTime(now)
	expiresAt := now.Add(ttl)
	if !expiresAt.After(now) {
		return Metadata{}, ErrInvalidCache
	}
	encoded, digest, err := encodeMetadata(clientID, metadata)
	if err != nil {
		return Metadata{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return Metadata{}, err
	}
	_, writeErr := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM cimd_client_documents WHERE rowid IN (
			SELECT rowid FROM cimd_client_documents WHERE expires_at_unix_ms <= ?
			ORDER BY expires_at_unix_ms,client_id,policy_digest LIMIT ?
		)`, Args: []any{now.UnixMilli(), int64(storeCleanupLimit)}},
		{SQL: `INSERT OR IGNORE INTO cimd_client_documents
			(client_id,policy_digest,metadata_json,metadata_digest,fetched_at_unix_ms,expires_at_unix_ms)
			SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM cimd_client_documents WHERE expires_at_unix_ms > ?) < ?`,
			Args: []any{clientID, policyDigest, encoded, digest, now.UnixMilli(), expiresAt.UnixMilli(), now.UnixMilli(), int64(storeActiveCacheCap)}},
	}})
	if errors.Is(writeErr, rhiza.ErrCommitUnknown) {
		return Metadata{}, writeErr
	}
	winner, found, readErr := s.Lookup(ctx, clientID, policyDigest, now)
	if readErr != nil {
		return Metadata{}, readErr
	}
	if found {
		return winner, nil
	}
	if writeErr != nil {
		return Metadata{}, writeErr
	}
	return Metadata{}, ErrCacheFull
}

type storedMetadata struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	// A pointer preserves the distinction between an omitted allow-list and an
	// explicitly empty one while keeping old cache rows canonical.
	AllowedResources *[]string `json:"allowed_resources,omitempty"`
}

func encodeMetadata(clientID string, metadata Metadata) (string, string, error) {
	if err := validateMetadata(clientID, metadata); err != nil {
		return "", "", err
	}
	var allowedResources *[]string
	if metadata.AllowedResourcesPresent || metadata.AllowedResources != nil {
		values := cloneStringSlice(metadata.AllowedResources)
		allowedResources = &values
	}
	encoded, err := json.Marshal(storedMetadata{
		ID: metadata.ID, Name: metadata.Name,
		RedirectURIs:     append([]string{}, metadata.RedirectURIs...),
		Scopes:           append([]string{}, metadata.Scopes...),
		GrantTypes:       append([]string{}, metadata.GrantTypes...),
		AllowedResources: allowedResources,
	})
	if err != nil || len(encoded) > storeMaxMetadataBytes {
		return "", "", ErrInvalidCache
	}
	sum := sha256.Sum256(encoded)
	return string(encoded), base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func decodeStoredMetadata(clientID, encoded string) (Metadata, string, error) {
	if len(encoded) == 0 || len(encoded) > storeMaxMetadataBytes {
		return Metadata{}, "", ErrInvalidCache
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var stored storedMetadata
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Metadata{}, "", ErrInvalidCache
	}
	var allowedResources []string
	if stored.AllowedResources != nil {
		allowedResources = cloneStringSlice(*stored.AllowedResources)
	}
	metadata := Metadata{ID: stored.ID, Name: stored.Name, RedirectURIs: append([]string{}, stored.RedirectURIs...), Scopes: append([]string{}, stored.Scopes...), GrantTypes: append([]string{}, stored.GrantTypes...), AllowedResources: allowedResources, AllowedResourcesPresent: stored.AllowedResources != nil}
	canonical, digest, err := encodeMetadata(clientID, metadata)
	if err != nil || subtle.ConstantTimeCompare([]byte(canonical), []byte(encoded)) != 1 {
		return Metadata{}, "", ErrInvalidCache
	}
	return metadata, digest, nil
}

func validCacheKey(clientID, policyDigest string) bool {
	if clientID == "" || len(clientID) > 2048 || strings.TrimSpace(clientID) != clientID || len(policyDigest) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(policyDigest)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == policyDigest
}

func validateMetadata(clientID string, metadata Metadata) error {
	client, err := parseTarget(clientID)
	if err != nil || metadata.ID != clientID || !validName(metadata.Name) || !validRedirects(metadata.RedirectURIs, client) || !validScopes(metadata.Scopes) || !validStoredGrantTypes(metadata.GrantTypes) || !validAllowedResources(metadata.AllowedResources) {
		return ErrInvalidCache
	}
	if metadata.AllowedResourcesPresent && metadata.AllowedResources == nil {
		return ErrInvalidCache
	}
	return nil
}

func validStoredGrantTypes(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if !validFlowValues(values) || !containsString(values, "authorization_code") {
		return false
	}
	for _, value := range values {
		if _, known := knownGrantTypes[value]; !known {
			return false
		}
	}
	return true
}

func randomRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "cimd-put/" + base64.RawURLEncoding.EncodeToString(b), nil
}

func canonicalTime(value time.Time) time.Time { return value.UTC().Truncate(time.Millisecond) }

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}
