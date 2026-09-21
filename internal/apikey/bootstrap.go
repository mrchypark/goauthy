package apikey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	maxBootstrapFileBytes  = 1 << 20
	maxBootstrapStatements = 64 // GoAuthy policy cap; Rhiza v0.9.0 permits 128.
	// SQLite stores expiry timestamps as signed milliseconds.  Bootstrap
	// accepts Unix seconds, so this is the largest value that can be scaled
	// without overflowing that column.
	maxExpiryUnixSeconds int64 = 9223372036854775
)

var (
	// ErrUnsupportedSecret is returned for bootstrap modes that require the
	// encrypted/generated-secret container, which this implementation does not
	// have.  Do not silently turn those modes into a plain secret.
	ErrUnsupportedSecret = errors.New("unsupported API-key bootstrap secret mode")
)

// bootstrapKey deliberately keeps the supplied secret private to this file.
// Only its digest is ever put in a Rhiza SQL argument.
type bootstrapKey struct {
	Name     string
	Exp      *int64
	Secret   []byte
	Access   []Access
	Generate bool
}

// Bootstrap reads and atomically applies an API-key bootstrap file. An unset
// path and an empty JSON array are successful no-ops. An explicitly configured
// path must be readable.
func (s *Store) Bootstrap(ctx context.Context, path string) error {
	return s.bootstrap(ctx, path, nil)
}

// BootstrapWithMasterKeyDir is the encrypted-secret bootstrap entry point.
// The directory contains the same raw-base64url 32-byte master-key files used
// by oidc.LoadKeyring. Plain entries remain supported; Generate remains
// intentionally unsupported because it requires Rauthy's separate generated
// secret container and retrieval lifecycle.
func (s *Store) BootstrapWithMasterKeyDir(ctx context.Context, path, keyDir string) error {
	if path == "" {
		return s.bootstrap(ctx, path, nil)
	}
	keys, err := loadBootstrapMasterKeys(keyDir)
	if err != nil {
		return err
	}
	defer wipeBootstrapMasterKeys(keys)
	return s.bootstrap(ctx, path, func(envelope []byte) ([]byte, error) {
		return decryptCryptrValue(envelope, keys)
	})
}

func (s *Store) bootstrap(ctx context.Context, path string, decrypt func([]byte) ([]byte, error)) error {
	return s.bootstrapOptions(ctx, path, decrypt, false, "", "", "", time.Time{})
}

func (s *Store) BootstrapWithGeneratedSecrets(ctx context.Context, path, keyDir, artifact, activeID string, deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(s.timeNow()) {
		return errors.New("generated bootstrap deadline is expired")
	}
	keys, err := loadBootstrapMasterKeys(keyDir)
	if err != nil {
		return err
	}
	defer wipeBootstrapMasterKeys(keys)
	return s.bootstrapOptions(ctx, path, func(envelope []byte) ([]byte, error) { return decryptCryptrValue(envelope, keys) }, true, artifact, keyDir, activeID, deadline)
}

func (s *Store) bootstrapOptions(ctx context.Context, path string, decrypt func([]byte) ([]byte, error), allowGenerate bool, artifact, keyDir, activeID string, deadline time.Time) error {
	content, err := readBootstrapFile(path)
	if err != nil {
		return err
	}
	defer clear(content)
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}

	keys, err := parseBootstrapKeysWithDecrypt(content, decrypt, allowGenerate, false)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	defer wipeBootstrapKeys(keys)
	if allowGenerate && artifact == "" {
		for _, k := range keys {
			if k.Generate {
				return errors.New("generated bootstrap requires an artifact path")
			}
		}
	}
	if allowGenerate && artifact != "" {
		existingArtifact := false
		if existing, err := ReadGeneratedBootstrapSecrets(artifact, keyDir, activeID, s.timeNow()); err == nil {
			existingArtifact = true
			wantGenerated := 0
			for _, k := range keys {
				if k.Generate {
					wantGenerated++
				}
			}
			if len(existing) != wantGenerated {
				return errors.New("generated bootstrap artifact does not match requested keys")
			}
			for i := range keys {
				if !keys[i].Generate {
					continue
				}
				found := false
				for _, e := range existing {
					if e.Kind == "api-key" && e.ID == keys[i].Name && e.Field == "token" && strings.HasPrefix(e.Value, keys[i].Name+"$") {
						clear(keys[i].Secret)
						keys[i].Secret = []byte(strings.TrimPrefix(e.Value, keys[i].Name+"$"))
						if len(keys[i].Secret) != secretLength || !alphaNum(string(keys[i].Secret)) {
							return errors.New("generated bootstrap artifact contains invalid secret")
						}
						found = true
						break
					}
				}
				if !found {
					return errors.New("generated bootstrap artifact does not match requested keys")
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read generated bootstrap artifact: %w", err)
		}
		if existingArtifact {
			// A previous publication may have linked the file but failed directory
			// Sync. Retry that durability boundary before importing any key rows.
			if err := syncBootstrapArtifact(artifact); err != nil {
				return err
			}
		}
		entries := make([]BootstrapSecretEntry, 0)
		for _, key := range keys {
			if key.Generate {
				entries = append(entries, BootstrapSecretEntry{Kind: "api-key", ID: key.Name, Field: "token", Value: key.Name + "$" + string(key.Secret)})
			}
		}
		if len(entries) > 0 && !existingArtifact {
			if err := WriteGeneratedBootstrapSecrets(artifact, keyDir, activeID, entries, deadline); err != nil {
				return err
			}
		}
	}

	statements, minimumRows := bootstrapStatements(keys, s.timeNow().UnixMilli())
	if len(statements) > maxBootstrapStatements {
		return fmt.Errorf("API-key bootstrap contains too many entries")
	}

	// One Rhiza command is one replicated SQLite transaction. If any key or
	// access row fails, Rhiza rolls the complete command back.
	// Include every SQL argument, including the creation timestamp, so an
	// independent starter never reuses an ID with a different fingerprint.
	requestBytes, err := json.Marshal(statements)
	if err != nil {
		return errors.New("encode API-key bootstrap statements")
	}
	requestID := bootstrapRequestID(requestBytes)
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID:  requestID,
		Statements: statements,
	})
	if err != nil {
		return fmt.Errorf("apply API-key bootstrap: %w", err)
	}
	if response.RowsAffected < int64(minimumRows) {
		return fmt.Errorf("apply API-key bootstrap: affected %d rows, want at least %d", response.RowsAffected, minimumRows)
	}
	if matched, err := s.bootstrapMatches(ctx, keys); err != nil {
		return fmt.Errorf("verify API-key bootstrap: %w", err)
	} else if !matched {
		return errors.New("verify API-key bootstrap: committed state does not match file")
	}
	return nil
}

func readBootstrapFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read API-key bootstrap file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat API-key bootstrap file: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("API-key bootstrap path is a directory")
	}
	content, err := io.ReadAll(io.LimitReader(f, maxBootstrapFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read API-key bootstrap file: %w", err)
	}
	if len(content) > maxBootstrapFileBytes {
		return nil, errors.New("API-key bootstrap file is too large")
	}
	return content, nil
}

// ValidateBootstrapFile checks the structure and content of a bootstrap
// API-key file before the secret store is opened. It verifies that the file
// exists, is readable, contains valid JSON with no duplicate field names or
// key names, that every entry is structurally valid, and that the file stays
// inside the statement budget the store enforces after Rhiza is open.
//
// The preflight cannot decrypt Encrypted entries because the master key is
// loaded during startup, so those entries are recorded as deferred and the
// parser keeps validating the rest of the document: duplicate names, later
// entries and the statement budget are all still checked. Generate entries are
// validated against allowGenerate, which the caller sets from the same
// generated-secret configuration startup uses, so a generate entry without
// that configuration is rejected here instead of after Rhiza is open.
//
// The function is side-effect-free: it does not touch the database, Rhiza,
// or global state and does not create the key directory or write anything.
// The caller must not reuse the parsed result; the real bootstrap path reads
// the file again.
func ValidateBootstrapFile(path string, decrypt func([]byte) ([]byte, error), allowGenerate bool) error {
	content, err := readBootstrapFile(path)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	keys, err := parseBootstrapKeysWithDecrypt(content, decrypt, allowGenerate, true)
	if err != nil {
		return err
	}
	defer wipeBootstrapKeys(keys)
	// GA-CONFIG-001: the store rejects an oversized statement batch only after
	// Rhiza is open and the generated-secret artifact may already be written, so
	// the preflight applies the same helper and limit.
	if statements, _ := bootstrapStatements(keys, 0); len(statements) > maxBootstrapStatements {
		return errors.New("API-key bootstrap contains too many entries")
	}
	return nil
}

func parseBootstrapKeys(content []byte) ([]bootstrapKey, error) {
	return parseBootstrapKeysWithDecrypt(content, nil, false, false)
}

// parseBootstrapKeysWithDecrypt parses a bootstrap document. preflight marks
// the configuration preflight, which runs before the master key exists: it
// defers Encrypted entries instead of rejecting them and turns the
// unsupported-mode sentinels into hard errors, because no later stage of that
// path re-checks them.
func parseBootstrapKeysWithDecrypt(content []byte, decrypt func([]byte) ([]byte, error), allowGenerate, preflight bool) ([]bootstrapKey, error) {
	if err := rejectDuplicateFields(content); err != nil {
		return nil, errors.New("invalid API-key bootstrap JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var raw []bootstrapJSONKey
	if err := decoder.Decode(&raw); err != nil {
		// GA-CONFIG-001: keep the decoder's reason (unknown field, malformed
		// secret payload) so a rejected file names the actual defect instead of
		// reporting every failure as a non-array document.
		return nil, fmt.Errorf("API-key bootstrap must be a JSON array: %w", err)
	}
	if raw == nil {
		return nil, errors.New("API-key bootstrap must be a JSON array")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("invalid API-key bootstrap JSON")
	}

	keys := make([]bootstrapKey, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i := range raw {
		entry := raw[i]
		if entry.Secret == nil {
			return nil, errors.New("API-key bootstrap secret is required")
		}
		req := Request{Name: entry.Name, Exp: entry.Exp, Access: entry.Access}
		if err := validate(req); err != nil {
			return nil, errors.New("invalid API-key bootstrap entry")
		}
		if _, exists := seen[entry.Name]; exists {
			return nil, errors.New("API-key bootstrap contains duplicate names")
		}
		seen[entry.Name] = struct{}{}
		for _, access := range entry.Access {
			// API keys and upstream SSO providers stay outside API-key policy.
			if access.Group == GroupAPIKeys || access.Group == "AuthProviders" {
				return nil, errors.New("API-key bootstrap cannot manage API keys or SSO providers")
			}
		}
		secret := append([]byte(nil), entry.Secret.plain...)
		if entry.Secret.generate {
			if !allowGenerate {
				if preflight {
					return nil, errors.New("API-key bootstrap generate mode requires a configured generated-secret export")
				}
				return nil, fmt.Errorf("%w: generate", ErrUnsupportedSecret)
			}
			var err error
			secret, err = generateBootstrapSecret()
			if err != nil {
				return nil, err
			}
		}
		if len(secret) == 0 && len(entry.Secret.encrypted) != 0 {
			if decrypt == nil {
				if !preflight {
					return nil, fmt.Errorf("%w: Encrypted", ErrUnsupportedSecret)
				}
				// GA-CONFIG-001: no master key yet. Keep the entry deferred and
				// keep validating the document; startup decrypts it later.
			} else {
				var err error
				clear(secret)
				secret, err = decrypt(entry.Secret.encrypted)
				if err != nil {
					return nil, fmt.Errorf("decrypt API-key bootstrap secret: %w", err)
				}
				if len(secret) != secretLength || !alphaNum(string(secret)) {
					clear(secret)
					return nil, errors.New("API-key bootstrap Encrypted secret must decrypt to exactly 64 ASCII alphanumeric characters")
				}
			}
		}
		keys = append(keys, bootstrapKey{
			Name: entry.Name, Exp: entry.Exp,
			Secret:   secret,
			Access:   normalize(entry.Access),
			Generate: entry.Secret.generate,
		})
		if len(entry.Secret.encrypted) != 0 {
			clear(entry.Secret.encrypted)
		}
	}
	return keys, nil
}

type bootstrapJSONKey struct {
	Name   string           `json:"name"`
	Exp    *int64           `json:"exp"`
	Secret *bootstrapSecret `json:"secret"`
	Access []Access         `json:"access"`
}

func (r *Request) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("API-key request must be an object")
	}
	for name := range fields {
		switch name {
		case "name", "exp", "access":
		default:
			return errors.New("invalid API-key request field")
		}
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	if raw, ok := fields["name"]; ok {
		if err := json.Unmarshal(raw, &r.Name); err != nil {
			return err
		}
	}
	if raw, ok := fields["exp"]; ok {
		if err := json.Unmarshal(raw, &r.Exp); err != nil {
			return err
		}
	}
	if raw, ok := fields["access"]; ok {
		if err := json.Unmarshal(raw, &r.Access); err != nil {
			return err
		}
	}
	return nil
}

func (k *bootstrapJSONKey) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("API-key bootstrap entry must be an object")
	}
	for name := range fields {
		switch name {
		case "name", "exp", "secret", "access":
		default:
			return errors.New("invalid API-key bootstrap field")
		}
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	if raw, ok := fields["name"]; ok {
		if err := json.Unmarshal(raw, &k.Name); err != nil {
			return err
		}
	}
	if raw, ok := fields["exp"]; ok {
		if err := json.Unmarshal(raw, &k.Exp); err != nil {
			return err
		}
	}
	if raw, ok := fields["secret"]; ok {
		if err := json.Unmarshal(raw, &k.Secret); err != nil {
			return err
		}
	}
	if raw, ok := fields["access"]; ok {
		if err := json.Unmarshal(raw, &k.Access); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON keeps bootstrap/API-key policy field names exact. The
// encoding/json package otherwise accepts case-insensitive aliases.
func (a *Access) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("API-key access must be an object")
	}
	for name := range fields {
		switch name {
		case "group", "access_rights":
		default:
			return errors.New("invalid API-key access field")
		}
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	if raw, ok := fields["group"]; ok {
		if err := json.Unmarshal(raw, &a.Group); err != nil {
			return err
		}
	}
	if raw, ok := fields["access_rights"]; ok {
		if err := json.Unmarshal(raw, &a.AccessRights); err != nil {
			return err
		}
	}
	return nil
}

type bootstrapSecret struct {
	plain     []byte
	encrypted []byte
	generate  bool
}

func (s *bootstrapSecret) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte(`"generate"`)) {
		s.generate = true
		return nil
	}
	if err := rejectDuplicateFields(data); err != nil {
		return errors.New("invalid API-key bootstrap secret")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil || len(values) != 1 {
		return errors.New("API-key bootstrap secret must be Plain")
	}
	raw, ok := values["Plain"]
	if ok {
		var plain string
		if err := json.Unmarshal(raw, &plain); err != nil || len(plain) != secretLength || !alphaNum(plain) {
			return errors.New("API-key bootstrap Plain secret must be exactly 64 ASCII alphanumeric characters")
		}
		s.plain = []byte(plain)
		return nil
	}
	raw, ok = values["Encrypted"]
	if !ok {
		return errors.New("API-key bootstrap secret must be Plain or Encrypted")
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil || encoded == "" {
		return errors.New("API-key bootstrap Encrypted secret must be base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		// GA-CONFIG-001: a malformed payload is not the deferred Encrypted mode.
		// Reporting the unsupported-mode sentinel here would let the preflight
		// accept a file that the real bootstrap path rejects.
		return errors.New("API-key bootstrap Encrypted secret must be base64")
	}
	s.encrypted = decoded
	return nil
}

func bootstrapStatements(keys []bootstrapKey, created int64) ([]rhiza.SQLStatement, int) {
	statements := make([]rhiza.SQLStatement, 0)
	minimumRows := 0
	for _, key := range keys {
		// Rauthy bootstrap is create-or-update: retain created_at on update,
		// while replacing the supplied secret and metadata atomically.
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO api_keys(name,secret_digest,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET secret_digest=excluded.secret_digest,expires_at_unix_ms=excluded.expires_at_unix_ms`, Args: []any{key.Name, digest(string(key.Secret)), created, millis(key.Exp)}})
		minimumRows++
		statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM api_key_access WHERE key_name=?`, Args: []any{key.Name}})
		for _, access := range key.Access {
			for _, right := range access.AccessRights {
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO api_key_access(key_name,group_name,right_name) VALUES(?,?,?)`, Args: []any{key.Name, access.Group, string(right)}})
				minimumRows++
			}
		}
	}
	return statements, minimumRows
}

func bootstrapRequestID(content []byte) string {
	sum := sha256.Sum256(content)
	return id("bootstrap", base64.RawURLEncoding.EncodeToString(sum[:]))
}

func (s *Store) bootstrapMatches(ctx context.Context, keys []bootstrapKey) (bool, error) {
	placeholders := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	args := make([]any, len(keys))
	for i, key := range keys {
		args[i] = key.Name
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT name,secret_digest,expires_at_unix_ms FROM api_keys WHERE name IN (` + placeholders + `)`, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	if len(r.Rows) == 0 {
		return false, nil
	}
	rows := make(map[string][]any, len(r.Rows))
	for _, row := range r.Rows {
		if len(row) != 3 {
			return false, ErrInvalid
		}
		name, ok := row[0].(string)
		if !ok {
			return false, ErrInvalid
		}
		rows[name] = row
	}
	for _, key := range keys {
		row, exists := rows[key.Name]
		if !exists || row[1] != digest(string(key.Secret)) || !sameExpiry(row[2], millis(key.Exp)) {
			return false, nil
		}
		accessRows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT group_name,right_name FROM api_key_access WHERE key_name=? ORDER BY group_name,right_name`, Args: []any{key.Name}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return false, err
		}
		want := 0
		for _, access := range key.Access {
			want += len(access.AccessRights)
		}
		if len(accessRows.Rows) != want {
			return false, nil
		}
		at := 0
		for _, access := range key.Access {
			for _, right := range access.AccessRights {
				if len(accessRows.Rows[at]) != 2 || accessRows.Rows[at][0] != access.Group || accessRows.Rows[at][1] != string(right) {
					return false, nil
				}
				at++
			}
		}
	}
	return len(rows) == len(keys), nil
}

func sameExpiry(got, want any) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	a, ok := got.(int64)
	b, ok2 := want.(int64)
	return ok && ok2 && a == b
}

func wipeBootstrapKeys(keys []bootstrapKey) {
	for i := range keys {
		clear(keys[i].Secret)
	}
}
