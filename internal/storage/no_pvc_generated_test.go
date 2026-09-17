package storage_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

const noPVCGeneratedBootstrapJSON = `[{"name":"recovery-api-key","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]`

// verifyNoPVCGeneratedAPIKey keeps the existing no-PVC helper honest for the
// shared Generate record too. The artifact lives in the disposable DataDir;
// the root expectation contains only the test's bearer value and is never
// logged or passed through an environment variable.
func verifyNoPVCGeneratedAPIKey(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, root, dataDir string, writing bool) error {
	config := filepath.Join(root, "generated-bootstrap.json")
	if err := os.WriteFile(config, []byte(noPVCGeneratedBootstrapJSON), 0600); err != nil {
		return err
	}
	store, err := apikey.NewStore(db)
	if err != nil {
		return err
	}
	keyDir := filepath.Join(root, "keys")
	artifact := filepath.Join(dataDir, "generated-api-key.secrets")
	if writing {
		if err := store.BootstrapWithSharedGeneratedSecrets(ctx, config, keyDir, artifact, keyring, time.Time{}); err != nil {
			return err
		}
		entries, err := apikey.ReadGeneratedBootstrapSecrets(artifact, keyDir, "test-key", time.Now().UTC())
		if err != nil || len(entries) != 1 {
			return errors.New("generated API-key writer artifact is invalid")
		}
		return os.WriteFile(filepath.Join(root, "generated-token"), []byte(entries[0].Value), 0600)
	}

	expected, err := os.ReadFile(filepath.Join(root, "generated-token"))
	if err != nil || len(expected) == 0 {
		return errors.New("generated API-key recovery expectation is unavailable")
	}
	defer clear(expected)
	bearer := string(expected)
	principal, err := store.Authenticate(ctx, "API-Key "+bearer)
	if err != nil {
		return errors.New("original generated API key did not recover before export")
	}
	if _, err := store.Authenticate(ctx, "API-Key "+mutatedNoPVCGeneratedBearer(bearer)); !errors.Is(err, apikey.ErrUnauthorized) {
		return errors.New("mutated generated API key was accepted")
	}
	assertPolicy := func() error {
		if err := store.Authorize(ctx, principal, "Clients", apikey.Read); err != nil {
			return errors.New("recovered generated API key lost Clients read")
		}
		if err := store.Authorize(ctx, principal, "Clients", apikey.Update); !errors.Is(err, apikey.ErrForbidden) {
			return errors.New("recovered generated API key gained Clients update")
		}
		return nil
	}
	if err := assertPolicy(); err != nil {
		return err
	}
	if err := store.BootstrapWithSharedGeneratedSecrets(ctx, config, keyDir, artifact, keyring, time.Time{}); err != nil {
		return err
	}
	entries, err := apikey.ReadGeneratedBootstrapSecrets(artifact, keyDir, "test-key", time.Now().UTC())
	if err != nil || len(entries) != 1 || entries[0].Value != bearer {
		return errors.New("generated API-key export did not preserve winner")
	}
	if err := assertPolicy(); err != nil {
		return err
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT deadline_unix_s FROM generated_api_key_bootstrap WHERE singleton=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || len(row.Rows[0]) != 1 || row.Rows[0][0] != int64(0) {
		return errors.New("generated API-key singleton did not recover")
	}
	keys, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM api_keys`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(keys.Rows) != 1 || len(keys.Rows[0]) != 1 || keys.Rows[0][0] != int64(1) {
		return errors.New("generated API-key row did not recover")
	}
	return nil
}

func mutatedNoPVCGeneratedBearer(bearer string) string {
	if !strings.HasSuffix(bearer, "A") {
		return bearer[:len(bearer)-1] + "A"
	}
	return bearer[:len(bearer)-1] + "B"
}
