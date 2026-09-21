package dcr

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// TestUpdateRequiresAckDurabilityForRotatedCredentials reproduces GA-DCR-001.
// The UPDATE applies locally, the object-store archive fails before ack, and a
// matching linearizable snapshot must not be enough to hand back the rotated
// client secret and registration token. The exact retry case covers the same
// request resolving through the durability barrier once the archive answers
// again.
func TestUpdateRequiresAckDurabilityForRotatedCredentials(t *testing.T) {
	for _, test := range []struct {
		name    string
		restore bool
	}{
		{name: "unconfirmed archive"},
		{name: "exact retry after archive recovery", restore: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			objectStoreDir := t.TempDir()
			db, err := rhiza.Open(ctx, rhiza.Config{
				NodeID:             "dcr-update-before-ack-" + strings.ReplaceAll(test.name, " ", "-"),
				DataDir:            t.TempDir(),
				ObjStoreProvider:   rhiza.ObjectStoreProviderFilesystem,
				ObjStoreDir:        objectStoreDir,
				ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if err := storage.Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}

			base := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
			store := NewStore(db, Config{Now: func() time.Time { return base }})
			created, err := store.Create(ctx, validRequest("update-durability", TokenEndpointAuthClientBasic))
			if err != nil {
				t.Fatal(err)
			}
			update := validRequest(created.ClientID, TokenEndpointAuthClientBasic)
			update.Name = "Rotated RP"

			unavailable := objectStoreDir + "-unavailable"
			if err := os.Rename(objectStoreDir, unavailable); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(objectStoreDir, []byte("object store unavailable"), 0o600); err != nil {
				t.Fatal(err)
			}
			recovered := false
			restore := func() {
				if recovered {
					return
				}
				if err := os.Remove(objectStoreDir); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(unavailable, objectStoreDir); err != nil {
					t.Fatal(err)
				}
				recovered = true
			}
			t.Cleanup(restore)

			snapshots := 0
			if test.restore {
				// The update re-reads the snapshot between the failed mutation and
				// the retry of that exact request; the archive answers again from
				// there on.
				store.afterRegistrationSnapshot = func() {
					snapshots++
					if snapshots == 2 {
						restore()
					}
				}
			}

			rotated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, update)
			if !test.restore {
				if !errors.Is(err, rhiza.ErrCommitUnknown) {
					t.Fatalf("unconfirmed archive err=%v, want commit unknown", err)
				}
				if rotated.ClientID != "" || rotated.ClientSecret != "" || rotated.RegistrationAccessToken != "" {
					t.Fatalf("unconfirmed archive revealed rotation=%#v", rotated)
				}
				// The mutation did apply locally, so the refusal above comes from
				// the durability barrier rather than from a mid-flight rejection.
				result, queryErr := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT registration_token_digest FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
				digest, ok := "", false
				if queryErr == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 1 {
					digest, ok = result.Rows[0][0].(string)
				}
				if !ok || digest == digestString(created.RegistrationAccessToken) {
					t.Fatalf("reconciled rotation digest=%#v ok=%t err=%v", result.Rows, ok, queryErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact retry err=%v", err)
			}
			if snapshots != 2 || !recovered {
				t.Fatalf("exact retry snapshots=%d recovered=%t", snapshots, recovered)
			}
			// The acknowledged rotation must be the durable one the caller holds.
			reader := NewStore(db)
			persisted, err := reader.GetRegistration(ctx, created.ClientID, rotated.RegistrationAccessToken)
			if err != nil || persisted.Name != update.Name {
				t.Fatalf("acknowledged rotation persisted=%#v err=%v", persisted, err)
			}
			client, err := reader.GetClient(ctx, created.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			if err := bcryptCompare(client.GetHashedSecret(), rotated.ClientSecret); err != nil {
				t.Fatalf("acknowledged rotation secret does not match the durable hash: %v", err)
			}
		})
	}
}
