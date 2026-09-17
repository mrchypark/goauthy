package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

// TestStandaloneMasterKeyStatus is the stopped-process half of the
// standalone rotation gate. Keeping the inspector here avoids depending on a
// host sqlite3 binary and proves the post-restart envelopes authenticate with
// the replacement key. The operator lifecycle itself is exercised through the
// public API by the companion shell gate.
func TestStandaloneMasterKeyStatus(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MASTER_KEY_STATUS") != "1" {
		t.Skip("set GOAUTHY_E2E_MASTER_KEY_STATUS=1 to inspect a stopped standalone DB")
	}
	dataDir := os.Getenv("GOAUTHY_E2E_DATA_DIR")
	masterKeyDir := os.Getenv("GOAUTHY_E2E_MASTER_KEY_DIR")
	issuer := os.Getenv("GOAUTHY_E2E_ISSUER")
	activeID := os.Getenv("GOAUTHY_E2E_ACTIVE_MASTER_KEY_ID")
	if dataDir == "" || masterKeyDir == "" || issuer == "" || activeID == "" {
		t.Fatal("GOAUTHY_E2E_DATA_DIR, GOAUTHY_E2E_MASTER_KEY_DIR, GOAUTHY_E2E_ISSUER, and GOAUTHY_E2E_ACTIVE_MASTER_KEY_ID are required")
	}

	keyring, err := oidc.LoadKeyring(masterKeyDir, activeID)
	if err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "standalone-master-key-0", DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if !db.Ready() {
		t.Fatal("standalone status DB is not ready")
	}

	status, err := oidc.InspectMasterKeyReferences(context.Background(), db, keyring, issuer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Safe || status.ActiveMasterKeyID != activeID {
		t.Fatalf("master-key status=%+v want safe active=%q", status, activeID)
	}
	if status.SigningKeys.Total == 0 || status.SigningKeys.ByKeyID[activeID] != status.SigningKeys.Total {
		t.Fatalf("signing-key status=%+v want every envelope under %q", status.SigningKeys, activeID)
	}
	if status.DCRIdempotency.Total == 0 || status.DCRIdempotency.ByKeyID[activeID] != status.DCRIdempotency.Total {
		t.Fatalf("DCR status=%+v want every envelope under %q", status.DCRIdempotency, activeID)
	}
}
