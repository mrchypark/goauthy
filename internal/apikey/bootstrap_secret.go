package apikey

// Compatibility reader for Rauthy cryptr 0.10 in-memory EncValue values.
// This is deliberately private: callers receive only the validated plaintext.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var bootstrapMasterKeyID = regexp.MustCompile(`^[a-zA-Z0-9:_-]{2,20}$`)

var ErrGeneratedBootstrapExpired = errors.New("generated bootstrap secret container expired")

const bootstrapSecretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func generateBootstrapSecret() ([]byte, error) {
	out := make([]byte, secretLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(bootstrapSecretAlphabet))))
		if err != nil {
			return nil, err
		}
		out[i] = bootstrapSecretAlphabet[n.Int64()]
	}
	return out, nil
}

type BootstrapSecretEntry struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Field string `json:"field"`
	Value string `json:"value"`
}
type bootstrapSecretPayload struct {
	Version  uint16                 `json:"version"`
	Deadline int64                  `json:"deadline"`
	Entries  []BootstrapSecretEntry `json:"entries"`
}

// WriteGeneratedBootstrapSecrets writes the Rauthy-compatible encrypted
// generated-secret container using the selected master-key file.
func WriteGeneratedBootstrapSecrets(path, keyDir, activeID string, entries []BootstrapSecretEntry, deadline time.Time) error {
	keys, err := loadBootstrapMasterKeys(keyDir)
	if err != nil {
		return err
	}
	defer wipeBootstrapMasterKeys(keys)
	key, ok := keys[activeID]
	if !ok {
		return fmt.Errorf("active bootstrap master key %q is missing", activeID)
	}
	deadlineUnix := int64(0)
	if !deadline.IsZero() {
		deadlineUnix = deadline.Unix()
	}
	payload, err := json.Marshal(bootstrapSecretPayload{Version: 1, Deadline: deadlineUnix, Entries: entries})
	if err != nil {
		return err
	}
	defer clear(payload)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	headerLen := 6 + len(activeID)
	header := make([]byte, headerLen)
	header[0], header[1] = 1, 1
	binary.BigEndian.PutUint16(header[2:4], uint16(headerLen))
	copy(header[6:], activeID)
	sealed := append(header, append(nonce, aead.Seal(nil, nonce, payload, nil)...)...)
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".bootstrap-secrets-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(sealed); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	// File Sync persists ciphertext, but the new directory entry also needs
	// acknowledgment before bootstrap may import its secret digest into Rhiza.
	return syncBootstrapArtifactDirectory(path)
}

// Recovered artifacts may have been written by another process without Sync.
func syncBootstrapArtifact(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	return syncBootstrapArtifactDirectory(path)
}

func syncBootstrapArtifactDirectory(path string) error {
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func ReadGeneratedBootstrapSecrets(path, keyDir, activeID string, now time.Time) ([]BootstrapSecretEntry, error) {
	if path == "" || now.IsZero() {
		return nil, errors.New("generated bootstrap artifact path and clock are required")
	}
	payload, err := readGeneratedBootstrapSecretPayload(path, keyDir)
	if err != nil {
		return nil, err
	}
	if payload.Deadline > 0 && now.Unix() >= payload.Deadline {
		return nil, ErrGeneratedBootstrapExpired
	}
	return payload.Entries, nil
}

// readGeneratedBootstrapSecretPayload reads and authenticates the artifact but
// deliberately leaves its deadline policy to its caller. Shared bootstrap uses
// this to preserve a prewritten artifact's original deadline.
func readGeneratedBootstrapSecretPayload(path, keyDir string) (bootstrapSecretPayload, error) {
	if path == "" {
		return bootstrapSecretPayload{}, errors.New("generated bootstrap artifact path is required")
	}
	data, err := readBootstrapFile(path)
	if err != nil {
		return bootstrapSecretPayload{}, err
	}
	defer clear(data)
	keys, err := loadBootstrapMasterKeys(keyDir)
	if err != nil {
		return bootstrapSecretPayload{}, err
	}
	defer wipeBootstrapMasterKeys(keys)
	p, err := decryptCryptrValue(data, keys)
	if err != nil {
		return bootstrapSecretPayload{}, err
	}
	defer clear(p)
	var payload bootstrapSecretPayload
	if err := json.Unmarshal(p, &payload); err != nil || payload.Version != 1 || payload.Deadline < 0 || payload.Entries == nil {
		return bootstrapSecretPayload{}, errors.New("invalid generated bootstrap secret container")
	}
	return payload, nil
}

func PurgeGeneratedBootstrapSecrets(path, keyDir, activeID string, now time.Time) (bool, error) {
	if _, err := ReadGeneratedBootstrapSecrets(path, keyDir, activeID, now); err == nil {
		return false, nil
	} else if !errors.Is(err, ErrGeneratedBootstrapExpired) {
		// Missing artifacts are already purged. A missing key directory is not:
		// preserve authentication errors while the artifact still exists.
		if errors.Is(err, os.ErrNotExist) {
			if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
				return false, nil
			}
		}
		return false, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func loadBootstrapMasterKeys(dir string) (map[string][]byte, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("API-key encrypted bootstrap requires a master-key directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read API-key bootstrap master-key directory: %w", err)
	}
	keys := make(map[string][]byte, len(entries))
	complete := false
	defer func() {
		if !complete {
			wipeBootstrapMasterKeys(keys)
		}
	}()
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		id := entry.Name()
		if !bootstrapMasterKeyID.MatchString(id) {
			return nil, fmt.Errorf("invalid API-key bootstrap master key ID %q", id)
		}
		encoded, err := os.ReadFile(filepath.Join(dir, id))
		if err != nil {
			return nil, fmt.Errorf("read API-key bootstrap master key %q: %w", id, err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		clear(encoded)
		if err != nil || len(decoded) != chacha20poly1305.KeySize {
			clear(decoded)
			return nil, fmt.Errorf("API-key bootstrap master key %q must be 32 raw-base64url bytes", id)
		}
		keys[id] = decoded
	}
	if len(keys) == 0 {
		return nil, errors.New("API-key encrypted bootstrap has no master keys")
	}
	complete = true
	return keys, nil
}

func wipeBootstrapMasterKeys(keys map[string][]byte) {
	for id, key := range keys {
		clear(key)
		delete(keys, id)
	}
}

func decryptCryptrValue(envelope []byte, keys map[string][]byte) ([]byte, error) {
	// cryptr EncValueHeader: version, algorithm, u16 full header length,
	// u16 chunk size, then UTF-8 key id. Values use version/algorithm 1 and
	// chunk size 0; payload is nonce(12)||ChaCha20Poly1305 ciphertext.
	if len(envelope) < 8 {
		return nil, errors.New("encrypted bootstrap secret envelope is truncated")
	}
	if envelope[0] != 1 || envelope[1] != 1 {
		return nil, errors.New("unsupported encrypted bootstrap secret envelope")
	}
	headerLen := int(binary.BigEndian.Uint16(envelope[2:4]))
	chunk := binary.BigEndian.Uint16(envelope[4:6])
	if headerLen < 8 || headerLen > len(envelope) || chunk != 0 {
		return nil, errors.New("invalid encrypted bootstrap secret header")
	}
	id := string(envelope[6:headerLen])
	key, ok := keys[id]
	if !ok {
		return nil, fmt.Errorf("unknown encrypted bootstrap master key %q", id)
	}
	if len(envelope)-headerLen < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("encrypted bootstrap secret payload is truncated")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := envelope[headerLen : headerLen+chacha20poly1305.NonceSize]
	plain, err := aead.Open(nil, nonce, envelope[headerLen+chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, errors.New("encrypted bootstrap secret authentication failed")
	}
	return plain, nil
}
