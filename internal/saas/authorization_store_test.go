package saas

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func authorizationTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func authorizationTestRequest(store *CredentialStore, b credentialBinding) authorizationRequest {
	now := store.now()
	return authorizationRequest{Binding: b,
		StateDigest: authorizationTestDigest("state"), VerifierDigest: authorizationTestDigest("verifier"),
		SessionDigest: authorizationTestDigest("session"), ProviderDigest: authorizationTestDigest("provider"),
		ExpiresAtUnixMS: now + 60_000}
}

func TestAuthorizationStoreCreateConsumeAndReplay(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	req := authorizationTestRequest(store, b)
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,verifier_digest,session_digest,provider_digest FROM saas_authorization_requests`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("authorization row=%v err=%v", rows.Rows, err)
	}
	rowValues := rows.Rows[0]
	if len(rowValues) != 4 || rowValues[0] != req.StateDigest || rowValues[1] != req.VerifierDigest || rowValues[2] != req.SessionDigest || rowValues[3] != req.ProviderDigest {
		t.Fatalf("authorization digests=%v", rowValues)
	}
	got, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority())
	if err != nil || got != b {
		t.Fatalf("consume=%+v err=%v", got, err)
	}
	if _, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("replay=%v", err)
	}
}

func TestAuthorizationStoreWrongProofDoesNotConsume(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*authorizationRequest){
		"verifier": func(r *authorizationRequest) { r.VerifierDigest = authorizationTestDigest("wrong") },
		"session":  func(r *authorizationRequest) { r.SessionDigest = authorizationTestDigest("wrong") },
		"provider": func(r *authorizationRequest) { r.ProviderDigest = authorizationTestDigest("wrong") },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, store, _, b := credentialStoreFixture(t)
			req := authorizationTestRequest(store, b)
			if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			wrong := req
			mutate(&wrong)
			if _, err := store.ConsumeAuthorization(ctx, wrong.StateDigest, wrong.VerifierDigest, wrong.SessionDigest, wrong.ProviderDigest, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
				t.Fatalf("wrong proof=%v", err)
			}
			if _, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority()); err != nil {
				t.Fatalf("valid proof after wrong attempt=%v", err)
			}
		})
	}
}

func TestAuthorizationStoreExpiryAndProviderRemoval(t *testing.T) {
	t.Parallel()
	ctx, store, db, b := credentialStoreFixture(t)
	now := store.now()
	store.now = func() int64 { return now }
	req := authorizationTestRequest(store, b)
	req.ExpiresAtUnixMS = now + 1
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	store.now = func() int64 { return now + 1 }
	if _, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("expired authorization=%v", err)
	}
	store.now = func() int64 { return now }
	req = authorizationTestRequest(store, b)
	req.StateDigest = authorizationTestDigest("state-2")
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "authorization-provider-removal", SQL: `UPDATE auth_collection_definitions SET providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("removed provider authorization=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "authorization-provider-readd", SQL: `UPDATE auth_collection_definitions SET providers_json='["provider"]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorization(ctx, req.StateDigest, req.VerifierDigest, req.SessionDigest, req.ProviderDigest, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("re-added provider authorization=%v", err)
	}
}
