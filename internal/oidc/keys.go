package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	envelopeVersion        = 1
	maxKeyIDLength         = 64
	purposeEnvelopeVersion = 1
)

var (
	envelopeMagic        = [4]byte{'G', 'A', 'O', 'K'}
	purposeEnvelopeMagic = [4]byte{'G', 'A', 'O', 'P'}
	ErrNoSigningKey      = errors.New("no active OIDC signing key")
)

type Keyring struct {
	mu        sync.RWMutex
	active    string
	keys      map[string][32]byte
	directory string
}

type SigningKey struct {
	Private   ed25519.PrivateKey
	PublicJWK jose.JSONWebKey
	CreatedAt time.Time
}

// ActiveMasterKeyID returns the configured active key only when it is a valid
// ID backed by a loaded key.
func (keyring *Keyring) ActiveMasterKeyID() (string, error) {
	if keyring == nil || !validKeyID(keyring.active) {
		return "", errors.New("active master key is unavailable")
	}
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	if _, ok := keyring.keys[keyring.active]; !ok {
		return "", errors.New("active master key is unavailable")
	}
	return keyring.active, nil
}

// RemoveKey removes a non-active key from the in-memory keyring and deletes
// the corresponding file from disk. It is safe to call when the key is already
// absent.
func (keyring *Keyring) RemoveKey(id string) error {
	if keyring == nil || !validKeyID(id) {
		return errors.New("invalid master key ID for removal")
	}
	if id == keyring.active {
		return errors.New("cannot remove active master key")
	}
	keyring.mu.Lock()
	defer keyring.mu.Unlock()
	if _, ok := keyring.keys[id]; !ok {
		return nil
	}
	if keyring.directory != "" {
		if err := os.Remove(filepath.Join(keyring.directory, id)); err != nil {
			return err
		}
	}
	delete(keyring.keys, id)
	return nil
}

// HasKey reports whether the keyring contains the given key ID.
func (keyring *Keyring) HasKey(id string) bool {
	if keyring == nil || !validKeyID(id) {
		return false
	}
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	_, ok := keyring.keys[id]
	return ok
}

// keyCopy returns a snapshot of the named master key. The returned value is
// safe to use after the lock is released.
func (keyring *Keyring) keyCopy(id string) ([32]byte, bool) {
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	k, ok := keyring.keys[id]
	return k, ok
}

func NormalizeIssuer(raw string) (string, error) {
	issuer, err := url.Parse(raw)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.Opaque != "" {
		return "", fmt.Errorf("issuer must be an absolute URL")
	}
	if issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" {
		return "", fmt.Errorf("issuer must not contain user info, query, or fragment")
	}
	if issuer.RawPath != "" || !canonicalIssuerPath(issuer.Path) {
		return "", fmt.Errorf("issuer path is not canonical")
	}
	issuer.Scheme = strings.ToLower(issuer.Scheme)
	issuer.Host = strings.ToLower(issuer.Host)
	hostname := issuer.Hostname()
	loopback := hostname == "localhost"
	if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if issuer.Scheme != "https" && !(issuer.Scheme == "http" && loopback) {
		return "", fmt.Errorf("issuer must use HTTPS except on loopback")
	}
	if issuer.Path == "/" {
		issuer.Path = ""
	}
	return issuer.String(), nil
}

func canonicalIssuerPath(path string) bool {
	if path == "" || path == "/" {
		return true
	}
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") || strings.ContainsAny(path, `\\{}`) {
		return false
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." || segment == "" {
			return false
		}
	}
	return true
}

func LoadKeyring(directory, activeID string) (*Keyring, error) {
	if !validKeyID(activeID) {
		return nil, fmt.Errorf("invalid active master key ID")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read master key directory: %w", err)
	}
	keyring := &Keyring{active: activeID, keys: make(map[string][32]byte), directory: directory}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || entry.IsDir() {
			continue
		}
		if !validKeyID(name) {
			return nil, fmt.Errorf("invalid master key ID %q", name)
		}
		encoded, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, fmt.Errorf("read master key %q: %w", name, err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("master key %q must be 32 raw-base64url bytes", name)
		}
		var key [32]byte
		copy(key[:], decoded)
		keyring.keys[name] = key
	}
	if _, ok := keyring.keys[activeID]; !ok {
		return nil, fmt.Errorf("active master key %q is missing", activeID)
	}
	return keyring, nil
}

func EnsureSigningKey(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer string, now time.Time) (SigningKey, error) {
	key, err := LoadActiveSigningKey(ctx, db, keyring, issuer)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrNoSigningKey) {
		return SigningKey{}, err
	}

	writerKeyID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKey{}, err
	}
	candidate, publicJSON, envelope, err := generateSigningKey(keyring, writerKeyID, issuer, now)
	if err != nil {
		return SigningKey{}, err
	}
	requestID := "oidc-key-bootstrap/" + candidate.PublicJWK.KeyID
	_, insertErr := storage.ExecuteEnvelope(ctx, db, writerKeyID, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL: `INSERT INTO oidc_signing_keys
			(kid, public_jwk, private_envelope, state, created_at_unix_ms)
			VALUES (?, ?, ?, 'active', ?)`,
		Args: []any{candidate.PublicJWK.KeyID, string(publicJSON), base64.RawURLEncoding.EncodeToString(envelope), now.UnixMilli()},
	})
	winner, loadErr := LoadActiveSigningKey(ctx, db, keyring, issuer)
	if loadErr == nil {
		return winner, nil
	}
	return SigningKey{}, errors.Join(insertErr, loadErr)
}

func LoadActiveSigningKey(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer string) (SigningKey, error) {
	return loadSigningKey(ctx, db, keyring, issuer, "", "active")
}

func loadSigningKey(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer, kid, state string) (SigningKey, error) {
	query := `SELECT kid, public_jwk, private_envelope, created_at_unix_ms
		FROM oidc_signing_keys WHERE state = ?`
	args := []any{state}
	if kid != "" {
		query += ` AND kid = ?`
		args = append(args, kid)
	}
	query += ` LIMIT 1`
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         query,
		Args:        args,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return SigningKey{}, err
	}
	if len(result.Rows) == 0 {
		if state != "active" {
			return SigningKey{}, fmt.Errorf("signing key %q is not %s", kid, state)
		}
		return SigningKey{}, ErrNoSigningKey
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return SigningKey{}, fmt.Errorf("invalid active signing key row")
	}
	kid, ok := result.Rows[0][0].(string)
	if !ok || !validKeyID(kid) {
		return SigningKey{}, fmt.Errorf("invalid signing key ID")
	}
	publicJSON, ok := result.Rows[0][1].(string)
	if !ok {
		return SigningKey{}, fmt.Errorf("invalid public JWK storage type")
	}
	encodedEnvelope, ok := result.Rows[0][2].(string)
	if !ok {
		return SigningKey{}, fmt.Errorf("invalid private envelope storage type")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encodedEnvelope)
	if err != nil {
		return SigningKey{}, fmt.Errorf("invalid private envelope encoding")
	}
	createdAt, ok := result.Rows[0][3].(int64)
	if !ok {
		return SigningKey{}, fmt.Errorf("invalid signing key creation time")
	}

	seed, err := openEnvelope(keyring, issuer, kid, envelope)
	if err != nil {
		return SigningKey{}, err
	}
	key, _, _, err := signingKeyFromSeed(seed, time.UnixMilli(createdAt))
	if err != nil {
		return SigningKey{}, err
	}
	if key.PublicJWK.KeyID != kid {
		return SigningKey{}, fmt.Errorf("signing key thumbprint mismatch")
	}
	var stored jose.JSONWebKey
	if err := json.Unmarshal([]byte(publicJSON), &stored); err != nil || !stored.IsPublic() {
		return SigningKey{}, fmt.Errorf("invalid stored public JWK")
	}
	storedPublic, ok := stored.Key.(ed25519.PublicKey)
	if !ok || stored.KeyID != kid || stored.Algorithm != string(jose.EdDSA) || stored.Use != "sig" || !bytes.Equal(storedPublic, key.PublicJWK.Key.(ed25519.PublicKey)) {
		return SigningKey{}, fmt.Errorf("stored public JWK does not match private key")
	}
	return key, nil
}

func generateSigningKey(keyring *Keyring, writerKeyID, issuer string, now time.Time) (SigningKey, []byte, []byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, nil, nil, err
	}
	seed := private.Seed()
	key, publicJSON, kid, err := signingKeyFromSeed(seed, now)
	if err != nil {
		return SigningKey{}, nil, nil, err
	}
	envelope, err := sealEnvelopeWithKeyID(keyring, writerKeyID, issuer, kid, seed)
	if err != nil {
		return SigningKey{}, nil, nil, err
	}
	return key, publicJSON, envelope, nil
}

func signingKeyFromSeed(seed []byte, createdAt time.Time) (SigningKey, []byte, string, error) {
	if len(seed) != ed25519.SeedSize {
		return SigningKey{}, nil, "", fmt.Errorf("invalid Ed25519 seed length")
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	jwk := jose.JSONWebKey{Key: public, Algorithm: string(jose.EdDSA), Use: "sig"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return SigningKey{}, nil, "", err
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	jwk.KeyID = kid
	publicJSON, err := json.Marshal(jwk)
	if err != nil {
		return SigningKey{}, nil, "", err
	}
	return SigningKey{Private: private, PublicJWK: jwk, CreatedAt: createdAt}, publicJSON, kid, nil
}

func sealEnvelope(keyring *Keyring, issuer, kid string, seed []byte) ([]byte, error) {
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return nil, err
	}
	return sealEnvelopeWithKeyID(keyring, activeID, issuer, kid, seed)
}

func sealEnvelopeWithKeyID(keyring *Keyring, masterID, issuer, kid string, seed []byte) ([]byte, error) {
	if keyring == nil {
		return nil, errors.New("invalid signing key envelope configuration")
	}
	if !validKeyID(masterID) {
		return nil, errors.New("active master key is unavailable")
	}
	masterKey, ok := keyring.keyCopy(masterID)
	if !ok {
		return nil, errors.New("active master key is unavailable")
	}
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := makeEnvelopeHeader(masterID, nonce)
	ciphertext := gcm.Seal(nil, nonce, seed, envelopeAAD(issuer, kid, header))
	return append(header, ciphertext...), nil
}

func openEnvelope(keyring *Keyring, issuer, kid string, envelope []byte) ([]byte, error) {
	if keyring == nil {
		return nil, fmt.Errorf("invalid signing key envelope")
	}
	masterID, headerLength, err := parseEnvelopeHeader(envelope, envelopeMagic, envelopeVersion, "invalid signing key envelope")
	if err != nil {
		return nil, err
	}
	masterKey, ok := keyring.keyCopy(masterID)
	if !ok {
		return nil, fmt.Errorf("unknown master key %q", masterID)
	}
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := envelope[headerLength-gcm.NonceSize() : headerLength]
	seed, err := gcm.Open(nil, nonce, envelope[headerLength:], envelopeAAD(issuer, kid, envelope[:headerLength]))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("decrypt signing key envelope: authentication failed")
	}
	return seed, nil
}

// SealEnvelope encrypts purpose-scoped application data with the active
// master key. The purpose is authenticated as AAD and the envelope format is
// deliberately separate from OIDC signing-key envelopes.
func (keyring *Keyring) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	if !validEnvelopePurpose(purpose) || keyring == nil {
		return nil, errors.New("invalid envelope configuration")
	}
	masterKey, ok := keyring.keyCopy(keyring.active)
	if !ok {
		return nil, errors.New("active master key is unavailable")
	}
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := makePurposeEnvelopeHeader(keyring.active, nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, purposeEnvelopeAAD(purpose, header))
	return append(header, ciphertext...), nil
}

// OpenEnvelope authenticates and decrypts data produced by SealEnvelope.
func (keyring *Keyring) OpenEnvelope(purpose string, envelope []byte) ([]byte, error) {
	if !validEnvelopePurpose(purpose) || keyring == nil {
		return nil, errors.New("invalid envelope configuration")
	}
	masterID, headerLength, err := parseEnvelopeHeader(envelope, purposeEnvelopeMagic, purposeEnvelopeVersion, "invalid purpose envelope")
	if err != nil {
		return nil, err
	}
	masterKey, ok := keyring.keyCopy(masterID)
	if !ok {
		return nil, errors.New("unknown purpose envelope master key")
	}
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := envelope[headerLength-gcm.NonceSize() : headerLength]
	plaintext, err := gcm.Open(nil, nonce, envelope[headerLength:], purposeEnvelopeAAD(purpose, envelope[:headerLength]))
	if err != nil {
		return nil, errors.New("decrypt purpose envelope: authentication failed")
	}
	return plaintext, nil
}

// PurposeEnvelopeKeyID authenticates a purpose envelope and returns the
// embedded master-key ID. It fails closed for malformed, unknown-key, or
// tampered envelopes.
func (keyring *Keyring) PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error) {
	if !validEnvelopePurpose(purpose) || keyring == nil {
		return "", errors.New("invalid envelope configuration")
	}
	masterID, _, err := parseEnvelopeHeader(envelope, purposeEnvelopeMagic, purposeEnvelopeVersion, "invalid purpose envelope")
	if err != nil {
		return "", err
	}
	if _, err := keyring.OpenEnvelope(purpose, envelope); err != nil {
		return "", err
	}
	return masterID, nil
}

// RewrapEnvelope decrypts a purpose envelope with its embedded key and
// reseals it using the keyring's active key. The input is never modified.
func (keyring *Keyring) RewrapEnvelope(purpose string, envelope []byte) ([]byte, error) {
	plaintext, err := keyring.OpenEnvelope(purpose, envelope)
	if err != nil {
		return nil, err
	}
	return keyring.SealEnvelope(purpose, plaintext)
}

// SigningKeyEnvelopeKeyID authenticates a signing-key envelope and returns its
// embedded master-key ID.
func (keyring *Keyring) SigningKeyEnvelopeKeyID(issuer, kid string, envelope []byte) (string, error) {
	if keyring == nil {
		return "", errors.New("invalid envelope configuration")
	}
	masterID, _, err := parseEnvelopeHeader(envelope, envelopeMagic, envelopeVersion, "invalid signing key envelope")
	if err != nil {
		return "", err
	}
	if _, err := openEnvelope(keyring, issuer, kid, envelope); err != nil {
		return "", err
	}
	return masterID, nil
}

// RewrapSigningKeyEnvelope decrypts a signing-key envelope with its embedded
// key and reseals it using the keyring's active key. The input is never
// modified.
func (keyring *Keyring) RewrapSigningKeyEnvelope(issuer, kid string, envelope []byte) ([]byte, error) {
	seed, err := openEnvelope(keyring, issuer, kid, envelope)
	if err != nil {
		return nil, err
	}
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return nil, err
	}
	return sealEnvelopeWithKeyID(keyring, activeID, issuer, kid, seed)
}

func parseEnvelopeHeader(envelope []byte, magic [4]byte, version byte, invalid string) (string, int, error) {
	minimum := len(magic) + 2 + 1 + 12 + 16
	if len(envelope) < minimum || !bytes.Equal(envelope[:len(magic)], magic[:]) || envelope[len(magic)] != version {
		return "", 0, errors.New(invalid)
	}
	keyIDLength := int(envelope[len(magic)+1])
	headerLength := len(magic) + 2 + keyIDLength + 12
	if keyIDLength == 0 || keyIDLength > maxKeyIDLength || len(envelope) < headerLength+16 {
		return "", 0, errors.New(invalid)
	}
	masterID := string(envelope[len(magic)+2 : len(magic)+2+keyIDLength])
	if !validKeyID(masterID) {
		return "", 0, errors.New(invalid)
	}
	return masterID, headerLength, nil
}

func makePurposeEnvelopeHeader(masterID string, nonce []byte) []byte {
	header := make([]byte, 0, 6+len(masterID)+len(nonce))
	header = append(header, purposeEnvelopeMagic[:]...)
	header = append(header, purposeEnvelopeVersion, byte(len(masterID)))
	header = append(header, masterID...)
	header = append(header, nonce...)
	return header
}

func purposeEnvelopeAAD(purpose string, header []byte) []byte {
	aad := make([]byte, 0, 48+len(purpose)+len(header))
	aad = append(aad, "goauthy/purpose-envelope/v1"...)
	aad = append(aad, 0)
	aad = append(aad, purpose...)
	aad = append(aad, 0)
	return append(aad, header...)
}

func validEnvelopePurpose(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("._/-", char) {
			continue
		}
		return false
	}
	return true
}

func makeEnvelopeHeader(masterID string, nonce []byte) []byte {
	header := make([]byte, 0, 6+len(masterID)+len(nonce))
	header = append(header, envelopeMagic[:]...)
	header = append(header, envelopeVersion, byte(len(masterID)))
	header = append(header, masterID...)
	header = append(header, nonce...)
	return header
}

func envelopeAAD(issuer, kid string, header []byte) []byte {
	aad := make([]byte, 0, 64+len(issuer)+len(kid)+len(header))
	aad = append(aad, "goauthy/oidc-signing-key-envelope/v1"...)
	aad = append(aad, 0)
	aad = append(aad, issuer...)
	aad = append(aad, 0)
	aad = append(aad, kid...)
	aad = append(aad, 0)
	aad = append(aad, "Ed25519"...)
	aad = append(aad, 0)
	aad = append(aad, header...)
	return aad
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > maxKeyIDLength {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("._-", char) {
			continue
		}
		return false
	}
	return true
}
