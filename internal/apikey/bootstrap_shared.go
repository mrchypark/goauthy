package apikey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type sharedGeneratedBootstrapRow struct {
	configDigest string
	envelope     []byte
	deadline     int64
	created      int64
}

// BootstrapWithSharedGeneratedSecrets coordinates Rauthy Generate bootstrap
// across nodes. The shared encrypted record and digest-only API-key rows are
// one fenced Rhiza transaction; the local artifact is only a non-overwriting
// export of that committed winner.
func (s *Store) BootstrapWithSharedGeneratedSecrets(ctx context.Context, path, keyDir, artifact string, keyring *oidc.Keyring, deadline time.Time) error {
	if keyring == nil {
		return errors.New("shared generated bootstrap requires a keyring")
	}
	if artifact == "" {
		return errors.New("shared generated bootstrap requires an artifact path")
	}
	if !deadline.IsZero() && !deadline.After(s.timeNow()) {
		return errors.New("generated bootstrap deadline is expired")
	}
	content, err := readBootstrapFile(path)
	if err != nil {
		return err
	}
	defer clear(content)
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	digest := sharedBootstrapConfigDigest(content)
	row, found, err := s.sharedGeneratedBootstrapRow(ctx)
	if err != nil {
		return err
	}
	if found {
		if row.configDigest != digest {
			return errors.New("shared generated bootstrap configuration conflicts with initialized state")
		}
		if row.envelope == nil {
			return s.ackSharedGeneratedBootstrap(ctx, keyring, row)
		}
		return s.applySharedGeneratedBootstrapWinner(ctx, content, keyDir, artifact, keyring, row)
	}

	keys, err := s.parseSharedBootstrapKeys(content, keyDir)
	if err != nil {
		return err
	}
	defer wipeBootstrapKeys(keys)
	if err := validateBootstrapBatch(keys, true); err != nil {
		return err
	}
	deadlineUnix := deadline.Unix()
	if deadline.IsZero() {
		deadlineUnix = 0
	}
	if payload, localErr := readGeneratedBootstrapSecretPayload(artifact, keyDir); localErr == nil {
		if payload.Deadline > 0 && s.timeNow().Unix() >= payload.Deadline {
			return ErrGeneratedBootstrapExpired
		}
		if err := applySharedGeneratedEntries(keys, payload.Entries); err != nil {
			return fmt.Errorf("generated bootstrap artifact does not match requested keys: %w", err)
		}
		if err := syncBootstrapArtifact(artifact); err != nil {
			return err
		}
		deadlineUnix = payload.Deadline
	} else if !errors.Is(localErr, os.ErrNotExist) {
		return fmt.Errorf("read generated bootstrap artifact: %w", localErr)
	}

	entries, err := generatedBootstrapEntries(keys)
	if err != nil {
		return err
	}
	payloadBytes, err := json.Marshal(bootstrapSecretPayload{Version: 1, Deadline: deadlineUnix, Entries: entries})
	if err != nil {
		return errors.New("encode shared generated bootstrap payload")
	}
	defer clear(payloadBytes)
	envelope, err := keyring.SealEnvelope(oidc.GeneratedAPIKeyBootstrapEnvelopePurpose, payloadBytes)
	if err != nil {
		return fmt.Errorf("seal shared generated bootstrap payload: %w", err)
	}
	writer, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	statements, minimum := bootstrapStatements(keys, s.timeNow().UnixMilli())
	statements = append([]rhiza.SQLStatement{{SQL: `INSERT INTO generated_api_key_bootstrap(singleton,config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms) VALUES(1,?,?,?,?)`, Args: []any{digest, envelope, deadlineUnix, s.timeNow().UnixMilli()}}}, statements...)
	requestID, err := sharedBootstrapRequestID("insert", digest, envelope, writer)
	if err != nil {
		return err
	}
	response, err := storage.ExecuteEnvelope(ctx, s.db, writer, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err == nil {
		if response.RowsAffected < int64(minimum+1) {
			return errors.New("shared generated bootstrap did not persist every key")
		}
		winner := sharedGeneratedBootstrapRow{configDigest: digest, envelope: envelope, deadline: deadlineUnix}
		return s.finishSharedGeneratedBootstrap(ctx, keys, artifact, keyDir, keyring, winner)
	}
	if errors.Is(err, rhiza.ErrCommitUnknown) {
		return fmt.Errorf("apply shared generated bootstrap: %w", err)
	}
	// A plain uniqueness conflict is an ordinary election loss. Read and use
	// only the authenticated committed winner; our candidate is wiped on return.
	row, found, readErr := s.sharedGeneratedBootstrapRow(ctx)
	if readErr != nil {
		return readErr
	}
	if !found || row.configDigest != digest || row.envelope == nil {
		return fmt.Errorf("apply shared generated bootstrap: %w", err)
	}
	return s.applySharedGeneratedBootstrapWinner(ctx, content, keyDir, artifact, keyring, row)
}

// PurgeSharedGeneratedSecrets tombstones a verified expired shared artifact.
// It intentionally leaves the config digest and initialization marker intact.
func (s *Store) PurgeSharedGeneratedSecrets(ctx context.Context, keyring *oidc.Keyring) error {
	if keyring == nil {
		return errors.New("shared generated bootstrap requires a keyring")
	}
	row, found, err := s.sharedGeneratedBootstrapRow(ctx)
	if err != nil || !found || row.envelope == nil || row.deadline == 0 || s.timeNow().Unix() < row.deadline {
		return err
	}
	if _, err := openSharedGeneratedBootstrapPayload(keyring, row); err != nil {
		return err
	}
	writer, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	requestID, err := s.sharedBootstrapMutationRequestID("purge", row.configDigest, row.envelope, writer)
	if err != nil {
		return err
	}
	_, err = storage.ExecuteEnvelope(ctx, s.db, writer, rhiza.ExecuteRequest{RequestID: requestID, SQL: `UPDATE generated_api_key_bootstrap SET payload_envelope=NULL WHERE singleton=1 AND config_digest=? AND deadline_unix_s=? AND payload_envelope=?`, Args: []any{row.configDigest, row.deadline, row.envelope}})
	return err
}

func (s *Store) applySharedGeneratedBootstrapWinner(ctx context.Context, content []byte, keyDir, artifact string, keyring *oidc.Keyring, row sharedGeneratedBootstrapRow) error {
	payload, err := openSharedGeneratedBootstrapPayload(keyring, row)
	if err != nil {
		return err
	}
	if row.deadline > 0 && s.timeNow().Unix() >= row.deadline {
		if err := s.PurgeSharedGeneratedSecrets(ctx, keyring); err != nil {
			return err
		}
		tombstone, found, err := s.sharedGeneratedBootstrapRow(ctx)
		if err != nil {
			return err
		}
		if !found || tombstone.configDigest != row.configDigest || tombstone.envelope != nil {
			return errors.New("expired shared generated bootstrap was not tombstoned")
		}
		return s.ackSharedGeneratedBootstrap(ctx, keyring, tombstone)
	}
	keys, err := s.parseSharedBootstrapKeys(content, keyDir)
	if err != nil {
		return err
	}
	defer wipeBootstrapKeys(keys)
	if err := applySharedGeneratedEntries(keys, payload.Entries); err != nil {
		return fmt.Errorf("shared generated bootstrap payload does not match requested keys: %w", err)
	}
	return s.finishSharedGeneratedBootstrap(ctx, keys, artifact, keyDir, keyring, row)
}

func (s *Store) finishSharedGeneratedBootstrap(ctx context.Context, keys []bootstrapKey, artifact, keyDir string, keyring *oidc.Keyring, row sharedGeneratedBootstrapRow) error {
	if err := s.ackSharedGeneratedBootstrap(ctx, keyring, row); err != nil {
		return err
	}
	if matched, err := s.bootstrapMatches(ctx, keys); err != nil {
		return err
	} else if !matched {
		return errors.New("shared generated bootstrap key rows do not match winner")
	}
	entries, err := generatedBootstrapEntries(keys)
	if err != nil {
		return err
	}
	if err := verifyOrWriteSharedGeneratedArtifact(artifact, keyDir, keyring, entries, row.deadline, s.timeNow()); err != nil {
		return err
	}
	return nil
}

// ackSharedGeneratedBootstrap proves the exact winner (or its immutable
// tombstone) crossed Rhiza's before-ack durability boundary. Do this before
// publishing any locally retrievable token.
func (s *Store) ackSharedGeneratedBootstrap(ctx context.Context, keyring *oidc.Keyring, row sharedGeneratedBootstrapRow) error {
	writer, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	requestID, err := s.sharedBootstrapAckRequestID(row.configDigest, row.envelope, writer)
	if err != nil {
		return err
	}
	query := `UPDATE generated_api_key_bootstrap SET created_at_unix_ms=created_at_unix_ms WHERE singleton=1 AND config_digest=?`
	args := []any{row.configDigest}
	if row.envelope == nil {
		query += ` AND payload_envelope IS NULL`
	} else {
		query += ` AND payload_envelope=?`
		args = append(args, row.envelope)
	}
	response, err := storage.ExecuteEnvelope(ctx, s.db, writer, rhiza.ExecuteRequest{RequestID: requestID, SQL: query, Args: args})
	if err != nil {
		return fmt.Errorf("acknowledge shared generated bootstrap: %w", err)
	}
	if response.RowsAffected != 1 {
		return errors.New("shared generated bootstrap winner changed")
	}
	return nil
}

func (s *Store) sharedBootstrapAckRequestID(digest string, envelope []byte, writer string) (string, error) {
	return s.sharedBootstrapMutationRequestID("ack", digest, envelope, writer)
}

// Each before-ack confirmation needs a new Rhiza request ID. Reusing a
// cached successful receipt could otherwise avoid the current object-store
// durability boundary after a later outage.
func (s *Store) sharedBootstrapMutationRequestID(operation, digest string, envelope []byte, writer string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := s.random(nonce); err != nil {
		return "", fmt.Errorf("generate shared generated bootstrap acknowledgment ID: %w", err)
	}
	defer clear(nonce)
	material := append(append([]byte(nil), envelope...), nonce...)
	return sharedBootstrapRequestID(operation, digest, material, writer)
}

func (s *Store) parseSharedBootstrapKeys(content []byte, keyDir string) ([]bootstrapKey, error) {
	master, err := loadBootstrapMasterKeys(keyDir)
	if err != nil {
		return nil, err
	}
	defer wipeBootstrapMasterKeys(master)
	return parseBootstrapKeysWithDecrypt(content, func(envelope []byte) ([]byte, error) { return decryptCryptrValue(envelope, master) }, true, false)
}

func (s *Store) sharedGeneratedBootstrapRow(ctx context.Context) (sharedGeneratedBootstrapRow, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT config_digest,payload_envelope,deadline_unix_s,created_at_unix_ms FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return sharedGeneratedBootstrapRow{}, false, err
	}
	if len(result.Rows) == 0 {
		return sharedGeneratedBootstrapRow{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return sharedGeneratedBootstrapRow{}, false, errors.New("invalid shared generated bootstrap row")
	}
	row := result.Rows[0]
	digest, ok := row[0].(string)
	deadline, okDeadline := row[2].(int64)
	created, okCreated := row[3].(int64)
	if !ok || !okDeadline || !okCreated || digest == "" || deadline < 0 || created < 0 {
		return sharedGeneratedBootstrapRow{}, false, errors.New("invalid shared generated bootstrap row")
	}
	shared := sharedGeneratedBootstrapRow{configDigest: digest, deadline: deadline, created: created}
	if row[1] != nil {
		var envelopeOK bool
		shared.envelope, envelopeOK = row[1].([]byte)
		if !envelopeOK || len(shared.envelope) == 0 {
			return sharedGeneratedBootstrapRow{}, false, errors.New("invalid shared generated bootstrap envelope")
		}
	}
	return shared, true, nil
}

func openSharedGeneratedBootstrapPayload(keyring *oidc.Keyring, row sharedGeneratedBootstrapRow) (bootstrapSecretPayload, error) {
	if row.envelope == nil {
		return bootstrapSecretPayload{}, errors.New("shared generated bootstrap is tombstoned")
	}
	plain, err := keyring.OpenEnvelope(oidc.GeneratedAPIKeyBootstrapEnvelopePurpose, row.envelope)
	if err != nil {
		return bootstrapSecretPayload{}, fmt.Errorf("open shared generated bootstrap payload: %w", err)
	}
	defer clear(plain)
	var payload bootstrapSecretPayload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Version != 1 || payload.Deadline != row.deadline || payload.Deadline < 0 || payload.Entries == nil {
		return bootstrapSecretPayload{}, errors.New("invalid shared generated bootstrap payload")
	}
	return payload, nil
}

func hasGeneratedBootstrapKey(keys []bootstrapKey) bool {
	for _, key := range keys {
		if key.Generate {
			return true
		}
	}
	return false
}

func generatedBootstrapEntries(keys []bootstrapKey) ([]BootstrapSecretEntry, error) {
	entries := make([]BootstrapSecretEntry, 0, len(keys))
	for _, key := range keys {
		if !key.Generate {
			continue
		}
		if len(key.Secret) != secretLength || !alphaNum(string(key.Secret)) {
			return nil, errors.New("invalid generated bootstrap secret")
		}
		entries = append(entries, BootstrapSecretEntry{Kind: "api-key", ID: key.Name, Field: "token", Value: key.Name + "$" + string(key.Secret)})
	}
	if len(entries) == 0 {
		return nil, errors.New("shared generated bootstrap has no generated secret")
	}
	return entries, nil
}

func applySharedGeneratedEntries(keys []bootstrapKey, entries []BootstrapSecretEntry) error {
	generated := 0
	byName := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.Kind != "api-key" || entry.Field != "token" || !strings.HasPrefix(entry.Value, entry.ID+"$") || !validName(entry.ID) {
			return errors.New("invalid generated bootstrap entry")
		}
		secret := strings.TrimPrefix(entry.Value, entry.ID+"$")
		if len(secret) != secretLength || !alphaNum(secret) {
			return errors.New("invalid generated bootstrap entry")
		}
		if _, exists := byName[entry.ID]; exists {
			return errors.New("duplicate generated bootstrap entry")
		}
		byName[entry.ID] = secret
	}
	for i := range keys {
		if !keys[i].Generate {
			continue
		}
		generated++
		secret, ok := byName[keys[i].Name]
		if !ok {
			return errors.New("missing generated bootstrap entry")
		}
		clear(keys[i].Secret)
		keys[i].Secret = []byte(secret)
		delete(byName, keys[i].Name)
	}
	if generated == 0 || len(byName) != 0 {
		return errors.New("generated bootstrap entry set does not match configuration")
	}
	return nil
}

func verifyOrWriteSharedGeneratedArtifact(path, keyDir string, keyring *oidc.Keyring, entries []BootstrapSecretEntry, deadline int64, now time.Time) error {
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	if existing, err := readGeneratedBootstrapSecretPayload(path, keyDir); err == nil {
		if existing.Deadline != deadline || !sameGeneratedBootstrapEntries(existing.Entries, entries) {
			return errors.New("local generated bootstrap artifact conflicts with shared winner")
		}
		if deadline > 0 && now.Unix() >= deadline {
			return ErrGeneratedBootstrapExpired
		}
		return syncBootstrapArtifact(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read local generated bootstrap artifact: %w", err)
	}
	end := time.Time{}
	if deadline > 0 {
		end = time.Unix(deadline, 0).UTC()
	}
	if err := WriteGeneratedBootstrapSecrets(path, keyDir, active, entries, end); err != nil {
		return fmt.Errorf("export shared generated bootstrap artifact: %w", err)
	}
	return nil
}

func sameGeneratedBootstrapEntries(a, b []BootstrapSecretEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sharedBootstrapConfigDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sharedBootstrapRequestID(operation, digest string, envelope []byte, writer string) (string, error) {
	if operation == "" || digest == "" || writer == "" {
		return "", errors.New("invalid shared generated bootstrap request")
	}
	sum := sha256.Sum256(append(append(append([]byte(operation+"\x00"+digest+"\x00"+writer+"\x00"), envelope...), byte(0)), []byte(oidc.GeneratedAPIKeyBootstrapEnvelopePurpose)...))
	return id("shared-bootstrap", base64.RawURLEncoding.EncodeToString(sum[:])), nil
}
