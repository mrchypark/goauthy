// Package backupconfig reads the files and object-store settings shared by
// the backup CLI and the in-process backup scheduler.
package backupconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// ReadRecipients reads a bounded, regular age recipient file.
func ReadRecipients(name string) ([]age.Recipient, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.Join(errors.New("invalid recipient file"), statErr, file.Close())
	}
	recipients, parseErr := age.ParseRecipients(io.LimitReader(file, (1<<20)+1))
	if err := errors.Join(parseErr, file.Close()); err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, errors.New("recipient file has no recipients")
	}
	return recipients, nil
}

// ReadCatalogKey reads either a PKCS8 signing key or a PKIX trust key.
func ReadCatalogKey(name string, private bool) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if !private {
		keys, err := ReadCatalogTrustKeys(name)
		if err != nil {
			return nil, nil, err
		}
		if len(keys) != 1 {
			return nil, nil, errors.New("require one native PEM key")
		}
		return nil, keys[0], nil
	}
	raw, err := readCatalogData(name, true)
	if err != nil {
		return nil, nil, err
	}
	block, rest := pem.Decode(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) || block == nil || bytes.Count(raw[:len(raw)-len(rest)], []byte("-----BEGIN ")) != 1 || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || block.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("require one native PKCS8 signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("require Ed25519 signing key")
	}
	return key, key.Public().(ed25519.PublicKey), nil
}

// ReadCatalogTrustKeys reads an operator-pinned bundle, never keys from a catalog.
func ReadCatalogTrustKeys(name string) ([]ed25519.PublicKey, error) {
	raw, err := readCatalogData(name, false)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	seen := make(map[string]bool)
	for len(raw) != 0 {
		block, rest := pem.Decode(raw)
		if len(keys) == backup.MaxCatalogTrustKeys || !bytes.HasPrefix(raw, []byte("-----BEGIN PUBLIC KEY-----")) || block == nil || bytes.Count(raw[:len(raw)-len(rest)], []byte("-----BEGIN ")) != 1 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
			return nil, errors.New("require bounded native PKIX trust keys")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || seen[string(key)] {
			return nil, errors.New("require distinct Ed25519 trust keys")
		}
		seen[string(key)] = true
		keys = append(keys, key)
		raw = bytes.TrimSpace(rest)
	}
	if len(keys) == 0 {
		return nil, errors.New("trust bundle is empty")
	}
	return keys, nil
}

func readCatalogData(name string, private bool) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > 16384 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, errors.Join(errors.New("invalid catalog key file"), statErr, file.Close())
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if len(raw) > 16384 {
		return nil, errors.New("catalog key file exceeds size limit")
	}
	return bytes.TrimSpace(raw), nil
}

var objectStoreSuffixes = []string{
	"PROVIDER", "DIR", "ENDPOINT", "BUCKET", "PREFIX", "REGION", "INSECURE", "RETRIES",
	"ACCESS_KEY", "SECRET_KEY", "SESSION_TOKEN", "SERVICE_ACCOUNT", "AZURE_TENANT_ID",
	"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_STORAGE_ACCOUNT",
	"AZURE_STORAGE_ACCOUNT_KEY", "AZURE_CONNECTION_STRING", "AZURE_USER_ASSIGNED_ID",
	"DURABILITY", "SYNC_INTERVAL", "BATCH_DELAY", "GC_INTERVAL", "GC_GRACE_PERIOD",
}

// DestinationConfig parses a separately configured backup destination without
// inheriting any source credentials. Its catalog namespace belongs to callers.
func DestinationConfig(getenv func(string) string, source rhiza.Config) (rhiza.Config, bool, error) {
	configured := false
	for _, suffix := range objectStoreSuffixes {
		if getenv("GOAUTHY_BACKUP_OBJECT_STORE_"+suffix) != "" {
			configured = true
			if suffix == "PREFIX" {
				return rhiza.Config{}, false, errors.New("GOAUTHY_BACKUP_OBJECT_STORE_PREFIX is not supported; use -catalog-prefix")
			}
		}
	}
	if !configured {
		return source, false, nil
	}
	mapped := func(name string) string {
		const sourcePrefix = "GOAUTHY_RHIZA_OBJECT_STORE_"
		if suffix, ok := strings.CutPrefix(name, sourcePrefix); ok {
			if suffix == "PREFIX" {
				return "goauthy-backup-validation"
			}
			return getenv("GOAUTHY_BACKUP_OBJECT_STORE_" + suffix)
		}
		return getenv(name)
	}
	config, err := storage.RhizaConfigFromEnv(mapped)
	if err != nil {
		return rhiza.Config{}, false, err
	}
	return config, true, nil
}
