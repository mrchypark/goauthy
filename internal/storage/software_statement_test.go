package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestDCRSoftwareStatementTrustFencesExactTopologies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "trust-fence", DataDir: testDatabaseDir(t, "trust-fence")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	digest := testDCRTrustDigest("policy-a")
	if err := EnsureDCRSoftwareStatementTrust(ctx, db, digest, []string{"node-0"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckDCRSoftwareStatementTrust(ctx, db, digest, []string{"node-0"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckDCRSoftwareStatementTrust(ctx, db, digest, []string{"node-1"}); !errors.Is(err, ErrDCRSoftwareStatementTrustMismatch) {
		t.Fatalf("topology mismatch err=%v", err)
	}
	if err := EnsureDCRSoftwareStatementTrust(ctx, db, testDCRTrustDigest("policy-b"), []string{"node-0"}); !errors.Is(err, ErrDCRSoftwareStatementTrustMismatch) {
		t.Fatalf("policy mismatch err=%v", err)
	}

	clusterDB, err := rhiza.Open(ctx, rhiza.Config{NodeID: "trust-cluster", DataDir: testDatabaseDir(t, "trust-cluster")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clusterDB.Close() })
	if err := Migrate(ctx, clusterDB); err != nil {
		t.Fatal(err)
	}
	members := []string{"node-2", "node-0", "node-1"}
	if err := EnsureDCRSoftwareStatementTrust(ctx, clusterDB, digest, members); err != nil {
		t.Fatal(err)
	}
	if err := CheckDCRSoftwareStatementTrust(ctx, clusterDB, digest, []string{"node-0", "node-1", "node-2"}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]string{{}, {"node-0", "node-0"}, {"node-0", "node-1"}, {"node-0", "node-1", "node-2", "node-3"}} {
		if err := EnsureDCRSoftwareStatementTrust(ctx, clusterDB, digest, invalid); err == nil {
			t.Fatalf("invalid topology accepted: %v", invalid)
		}
	}
}

func testDCRTrustDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
