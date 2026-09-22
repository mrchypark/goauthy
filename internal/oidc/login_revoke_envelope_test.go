package oidc

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoginRevokeEnvelopeStatusAndRewrapPreserveSharedCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	old, active := fixedKeyring("master-a"), fixedKeyring("master-b")
	subject, generation := "subject-login-revoke", strings.Repeat("g", 22)
	code := bytes.Repeat([]byte("A"), 48)
	purpose := LoginRevokeCodePurpose(subject, generation)
	envelope, err := old.SealEnvelope(purpose, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-revoke-envelope-user",
		SQL:       `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`,
		Args:      []any{subject, subject, ""},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "login-revoke-envelope-test",
		SQL:       `INSERT INTO identity_login_revoke(subject,generation,code_envelope) VALUES(?,?,?)`,
		Args:      []any{subject, generation, envelope},
	}); err != nil {
		t.Fatal(err)
	}

	status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
	if err != nil || status.Safe || status.LoginRevoke.Total != 1 || status.LoginRevoke.ByKeyID["master-a"] != 1 {
		t.Fatalf("old-key status=%+v err=%v", status, err)
	}

	result, err := RewrapLoginRevokeCodeBatch(ctx, db, active, "")
	if err != nil || result.Rewrapped != 1 || !result.Done {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_envelope FROM identity_login_revoke WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("rewrapped row=%v err=%v", row.Rows, err)
	}
	newEnvelope, ok := loginRevokeEnvelopeBytes(row.Rows[0][0])
	if !ok {
		t.Fatalf("rewrapped envelope type=%T", row.Rows[0][0])
	}
	plain, err := active.OpenEnvelope(purpose, newEnvelope)
	if err != nil || !bytes.Equal(plain, code) {
		t.Fatalf("shared code=%q err=%v", plain, err)
	}
	status, err = InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", nowForTest())
	if err != nil || !status.Safe || status.LoginRevoke.ByKeyID["master-b"] != 1 {
		t.Fatalf("active-key status=%+v err=%v", status, err)
	}
}

func TestLoginRevokeEnvelopePurposeBindsSubjectAndGeneration(t *testing.T) {
	t.Parallel()
	keyring := fixedKeyring("master-a")
	subject, generation := "subject", "generation"
	purpose := LoginRevokeCodePurpose(subject, generation)
	envelope, err := keyring.SealEnvelope(purpose, bytes.Repeat([]byte("B"), 48))
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{
		LoginRevokeCodePurpose(subject+"-other", generation),
		LoginRevokeCodePurpose(subject, generation+"-other"),
	} {
		if _, err := keyring.OpenEnvelope(other, envelope); err == nil {
			t.Fatal("login-revoke envelope opened with a different binding")
		}
	}
}

func TestRewrapLoginRevokeCodeHonorsFencedOldWriter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testDB(t)
	subject, generation := "login-revoke-fenced", strings.Repeat("f", 22)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-revoke-fenced-user", SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{subject, subject, ""}}); err != nil {
		t.Fatal(err)
	}
	oldWriter := fixedKeyring("master-a")
	source := fixedKeyring("master-b")
	envelope, err := source.SealEnvelope(LoginRevokeCodePurpose(subject, generation), bytes.Repeat([]byte("C"), 48))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-revoke-fenced-row", SQL: `INSERT INTO identity_login_revoke(subject,generation,code_envelope) VALUES(?,?,?)`, Args: []any{subject, generation, envelope}}); err != nil {
		t.Fatal(err)
	}
	fenceOIDCWriter(t, db, "master-a", "master-b", nowForTest())
	if _, err := RewrapLoginRevokeCodeBatch(ctx, db, oldWriter, ""); err == nil {
		t.Fatal("fenced old login-revoke writer committed")
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT code_envelope FROM identity_login_revoke WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || !bytes.Equal(row.Rows[0][0].([]byte), envelope) {
		t.Fatalf("fenced envelope changed row=%v err=%v", row.Rows, err)
	}
}
