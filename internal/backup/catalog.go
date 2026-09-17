package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thanos-io/objstore"
)

// CatalogEntry describes an immutable encrypted artifact. CreatedAt is supplied
// by the authorized publisher, not an independently attested clock.
type CatalogEntry struct {
	Version       int    `json:"version"`
	ID            string `json:"id"`
	CreatedAt     int64  `json:"created_at"`
	SourcePrefix  string `json:"source_prefix"`
	CatalogPrefix string `json:"catalog_prefix"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
}

type signedEntry struct {
	Entry     json.RawMessage `json:"entry"`
	Signature []byte          `json:"signature"`
}

// MaxCatalogTrustKeys bounds the concurrent public keys accepted while a
// catalog signing key is rotated.
const MaxCatalogTrustKeys = 32

// ValidateCatalogLocation rejects invalid or overlapping source/catalog namespaces.
func ValidateCatalogLocation(prefix, sourcePrefix string) error {
	if !validName(prefix) || !validName(sourcePrefix) || relatedPrefix(prefix, sourcePrefix) {
		return errors.New("invalid or overlapping backup catalog namespace")
	}
	return nil
}

func validatePublication(bucket objstore.Bucket, prefix, sourcePrefix string, key ed25519.PrivateKey, created time.Time) error {
	if bucket == nil || ValidateCatalogLocation(prefix, sourcePrefix) != nil || len(key) != ed25519.PrivateKeySize || created.Unix() <= 0 {
		return errors.New("invalid catalog publication configuration")
	}
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) || !slices.Contains(bucket.SupportedObjectUploadOptions(), objstore.IfNotExists) {
		return errors.New("catalog requires a valid signing key and conditional writes")
	}
	return nil
}

// Publish uploads into an independent namespace, verifies remote bytes, then
// conditionally publishes its signed completion record. The caller exclusively
// owns artifact until return. Failures may leave an unlisted orphan; never delete
// or overwrite an object in response to an ambiguous provider error.
func Publish(ctx context.Context, bucket objstore.Bucket, prefix, sourcePrefix string, artifact *os.File, key ed25519.PrivateKey, created time.Time) (CatalogEntry, error) {
	if artifact == nil {
		return CatalogEntry{}, errors.New("missing catalog artifact")
	}
	if err := validatePublication(bucket, prefix, sourcePrefix, key, created); err != nil {
		return CatalogEntry{}, err
	}
	info, err := artifact.Stat()
	if err != nil {
		return CatalogEntry{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() == int64(^uint64(0)>>1) {
		return CatalogEntry{}, errors.New("invalid catalog artifact")
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return CatalogEntry{}, err
	}
	header := make([]byte, len("age-encryption.org/v1\n"))
	if _, err := io.ReadFull(artifact, header); err != nil || string(header) != "age-encryption.org/v1\n" {
		return CatalogEntry{}, errors.New("catalog artifact is not age encrypted")
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return CatalogEntry{}, err
	}
	digest, err := streamDigest(artifact, info.Size())
	if err != nil {
		return CatalogEntry{}, err
	}
	entry := CatalogEntry{Version: 1, ID: rand.Text(), CreatedAt: created.UTC().Unix(), SourcePrefix: sourcePrefix, CatalogPrefix: prefix, Size: info.Size(), SHA256: digest}
	raw, err := json.Marshal(entry)
	if err != nil {
		return CatalogEntry{}, err
	}
	record, err := json.Marshal(signedEntry{Entry: raw, Signature: ed25519.Sign(key, raw)})
	if err != nil {
		return CatalogEntry{}, err
	}
	if len(record) > 4096 {
		return CatalogEntry{}, errors.New("catalog record exceeds size limit")
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return CatalogEntry{}, err
	}
	object := path.Join(prefix, "artifacts", entry.ID+".age")
	if err := bucket.Upload(ctx, object, artifact, objstore.WithIfNotExists()); err != nil {
		return CatalogEntry{}, err
	}
	if err := verifyCatalogArtifact(ctx, bucket, prefix, entry); err != nil {
		return CatalogEntry{}, err
	}
	if err := bucket.Upload(ctx, path.Join(prefix, "completed", entry.ID+".json"), bytes.NewReader(record), objstore.WithIfNotExists()); err != nil {
		return CatalogEntry{}, err
	}
	return entry, nil
}

// ListCompleted rejects malformed or unauthorized records instead of silently
// hiding them. Signatures prove publisher authorization, not availability or
// freshness: a bucket administrator can still remove/replay old signed records.
func ListCompleted(ctx context.Context, bucket objstore.Bucket, prefix string, keys []ed25519.PublicKey, maxEntries int) ([]CatalogEntry, error) {
	if bucket == nil || !validName(prefix) || maxEntries <= 0 || validateCatalogTrustKeys(keys) != nil {
		return nil, errors.New("invalid catalog listing configuration")
	}
	var entries []CatalogEntry
	err := bucket.Iter(ctx, path.Join(prefix, "completed")+"/", func(name string) error {
		if len(entries) >= maxEntries {
			return errors.New("catalog entry limit exceeded")
		}
		entry, err := readCatalogEntry(ctx, bucket, name, keys)
		if err != nil {
			return err
		}
		if name != path.Join(prefix, "completed", entry.ID+".json") || entry.CatalogPrefix != prefix || relatedPrefix(prefix, entry.SourcePrefix) {
			return errors.New("invalid catalog record location")
		}
		entries = append(entries, entry)
		return nil
	}, objstore.WithRecursiveIter())
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt == entries[j].CreatedAt {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].CreatedAt < entries[j].CreatedAt
	})
	return entries, nil
}

// FetchCompleted authenticates the named record and downloads exactly its
// encrypted bytes to a private file. The caller owns and removes that file on
// success. Decryption and the Rhiza restore checks must still follow.
func FetchCompleted(ctx context.Context, bucket objstore.Bucket, prefix, id string, keys []ed25519.PublicKey, workParent string, maxBytes int64) (_ string, _ CatalogEntry, err error) {
	if bucket == nil || !validName(prefix) || !validCatalogID(id) || maxBytes <= 0 || validateCatalogTrustKeys(keys) != nil {
		return "", CatalogEntry{}, errors.New("invalid catalog download configuration")
	}
	entry, err := readCatalogEntry(ctx, bucket, path.Join(prefix, "completed", id+".json"), keys)
	if err != nil {
		return "", CatalogEntry{}, err
	}
	if entry.ID != id || entry.CatalogPrefix != prefix || relatedPrefix(prefix, entry.SourcePrefix) || entry.Size > maxBytes {
		return "", CatalogEntry{}, errors.New("invalid catalog download boundary")
	}
	file, err := os.CreateTemp(workParent, ".goauthy-catalog-")
	if err != nil {
		return "", CatalogEntry{}, err
	}
	success := false
	defer func() {
		err = errors.Join(err, file.Close())
		if !success || err != nil {
			err = errors.Join(err, os.Remove(file.Name()))
		}
	}()
	reader, err := bucket.Get(ctx, path.Join(prefix, "artifacts", id+".age"))
	if err != nil {
		return "", CatalogEntry{}, err
	}
	digest := sha256.New()
	n, readErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(reader, entry.Size+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return "", CatalogEntry{}, err
	}
	if n != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return "", CatalogEntry{}, errors.New("catalog artifact mismatch")
	}
	if err := file.Sync(); err != nil {
		return "", CatalogEntry{}, err
	}
	success = true
	return file.Name(), entry, nil
}

func readCatalogEntry(ctx context.Context, bucket objstore.Bucket, name string, keys []ed25519.PublicKey) (CatalogEntry, error) {
	if validateCatalogTrustKeys(keys) != nil {
		return CatalogEntry{}, errors.New("invalid catalog trust bundle")
	}
	reader, err := bucket.Get(ctx, name)
	if err != nil {
		return CatalogEntry{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(reader, 4097))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return CatalogEntry{}, err
	}
	if len(raw) > 4096 || !utf8.Valid(raw) {
		return CatalogEntry{}, errors.New("catalog record exceeds size limit")
	}
	if _, err := jsonFields(raw, []string{"entry", "signature"}); err != nil || duplicateJSONKeys(raw) {
		return CatalogEntry{}, errors.New("invalid signed catalog record")
	}
	var signed signedEntry
	if err := json.Unmarshal(raw, &signed); err != nil {
		return CatalogEntry{}, err
	}
	if !catalogSignatureTrusted(keys, signed.Entry, signed.Signature) {
		return CatalogEntry{}, errors.New("unauthorized catalog record")
	}
	if _, err := jsonFields(signed.Entry, []string{"version", "id", "created_at", "source_prefix", "catalog_prefix", "size", "sha256"}); err != nil {
		return CatalogEntry{}, err
	}
	var entry CatalogEntry
	if err := json.Unmarshal(signed.Entry, &entry); err != nil {
		return CatalogEntry{}, err
	}
	if entry.Version != 1 || !validCatalogID(entry.ID) || entry.CreatedAt <= 0 || !validName(entry.SourcePrefix) || !validName(entry.CatalogPrefix) || entry.Size <= 0 || entry.Size == int64(^uint64(0)>>1) || !validHash(entry.SHA256) {
		return CatalogEntry{}, errors.New("invalid catalog entry")
	}
	return entry, nil
}

func validateCatalogTrustKeys(keys []ed25519.PublicKey) error {
	if len(keys) == 0 || len(keys) > MaxCatalogTrustKeys {
		return errors.New("invalid catalog trust bundle")
	}
	for i, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return errors.New("invalid catalog trust bundle")
		}
		for _, previous := range keys[:i] {
			if bytes.Equal(key, previous) {
				return errors.New("invalid catalog trust bundle")
			}
		}
	}
	return nil
}

func catalogSignatureTrusted(keys []ed25519.PublicKey, message, signature []byte) bool {
	for _, key := range keys {
		if ed25519.Verify(key, message, signature) {
			return true
		}
	}
	return false
}

func validCatalogID(id string) bool {
	return len(id) == 26 && strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == ""
}

func streamDigest(reader io.Reader, size int64) (string, error) {
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(reader, size+1))
	if err != nil {
		return "", err
	}
	if n != size {
		return "", errors.New("catalog artifact size changed")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func verifyCatalogArtifact(ctx context.Context, bucket objstore.Bucket, prefix string, entry CatalogEntry) error {
	reader, err := bucket.Get(ctx, path.Join(prefix, "artifacts", entry.ID+".age"))
	if err != nil {
		return err
	}
	got, readErr := streamDigest(reader, entry.Size)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return err
	}
	if got != entry.SHA256 {
		return errors.New("catalog artifact mismatch")
	}
	return nil
}
