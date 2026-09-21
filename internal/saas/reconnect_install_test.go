package saas

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestReconnectInstallRequiresRevokedPriorGenerationAndNextVersion(t *testing.T) {
	t.Parallel()
	ctx, store, db, old := credentialStoreFixture(t)
	if err := store.Install(ctx, old, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{old.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || len(q.Rows[0]) != 1 {
		t.Fatalf("credential query=%v err=%v", q.Rows, err)
	}
	before := append([]byte(nil), q.Rows[0][0].([]byte)...)
	newBinding := old
	newBinding.TokenVersion = 2
	if err := store.Install(ctx, newBinding, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("unrevoked replacement=%v", err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{old.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || !bytes.Equal(before, q.Rows[0][0].([]byte)) {
		t.Fatal("rejected install changed ciphertext")
	}
	if err := store.Revoke(ctx, old, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, newBinding, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("same generation replacement=%v", err)
	}
	newBinding.Generation = "generation-new"
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "reconnect-generation", SQL: `UPDATE auth_collection_connections SET generation=? WHERE id=?`, Args: []any{"generation-new", old.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	bad := newBinding
	bad.TokenVersion = 4
	if err := store.Install(ctx, bad, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("skipped replacement=%v", err)
	}
	q, err = db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{old.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || !bytes.Equal(before, q.Rows[0][0].([]byte)) {
		t.Fatal("rejected reconnect changed ciphertext")
	}
	if err := store.Install(ctx, newBinding, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, newBinding, credentialAuthority()); err != nil {
		t.Fatalf("replacement load=%v", err)
	}
}
