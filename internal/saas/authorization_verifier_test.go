package saas

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func verifierRequest(b credentialBinding) (authorizationRequest, string, string, string, string) {
	return verifierRequestWithSeed(b, "state")
}
func verifierRequestWithSeed(b credentialBinding, seed string) (authorizationRequest, string, string, string, string) {
	state := authorizationDigest(seed)
	session := authorizationDigest(seed + "-session")
	provider := authorizationDigest("provider-policy")
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijklmnopqrstuvwxyz"
	return authorizationRequest{Binding: b, StateDigest: state, VerifierDigest: authorizationDigest(verifier), SessionDigest: session, ProviderDigest: provider, Verifier: verifier, ExpiresAtUnixMS: 1800000001000}, state, session, provider, verifier
}

func TestAuthorizationVerifierEncryptedLoadConsumeAndGuards(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	req, state, session, provider, verifier := verifierRequest(b)
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT verifier_envelope FROM saas_authorization_requests WHERE state_digest=?`, Args: []any{state}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("row=%v err=%v", q.Rows, err)
	}
	env := q.Rows[0][0].([]byte)
	if len(env) == 0 || bytes.Contains(env, []byte(verifier)) {
		t.Fatal("verifier plaintext persisted")
	}
	got, plain, err := store.loadAuthorizationVerifier(ctx, state, session, provider, credentialAuthority())
	if err != nil || got != b || plain != verifier {
		t.Fatalf("binding=%#v verifier=%q err=%v", got, plain, err)
	}
	if _, _, err := store.loadAuthorizationVerifier(ctx, state, authorizationDigest("wrong"), provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("wrong session=%v", err)
	}
	if _, err := store.ConsumeAuthorization(ctx, state, req.VerifierDigest, session, provider, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAuthorizationVerifier(ctx, state, session, provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("consumed load=%v", err)
	}
	if _, err := store.ConsumeAuthorization(ctx, state, req.VerifierDigest, session, provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("replay=%v", err)
	}
}

func TestAuthorizationVerifierTamperAndExpiry(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	req, state, session, provider, _ := verifierRequest(b)
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-verifier-tamper", SQL: `UPDATE saas_authorization_requests SET verifier_envelope=? WHERE state_digest=?`, Args: []any{[]byte("tampered"), state}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAuthorizationVerifier(ctx, state, session, provider, credentialAuthority()); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	// A fresh request proves expiry is checked before decryption.
	req, state, session, provider, _ = verifierRequestWithSeed(b, "expired-state")
	req.ExpiresAtUnixMS = store.now() + 1000
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	store.now = func() int64 { return req.ExpiresAtUnixMS + 1 }
	if _, _, err := store.loadAuthorizationVerifier(ctx, state, session, provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("expired=%v", err)
	}
}

func TestAuthorizationVerifierRejectsAuthenticatedMetadataSwap(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	req, state, session, provider, _ := verifierRequestWithSeed(b, "metadata-state")
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	changedSession := authorizationDigest("changed-session")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-verifier-session-swap", SQL: `UPDATE saas_authorization_requests SET session_digest=? WHERE state_digest=?`, Args: []any{changedSession, state}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.loadAuthorizationVerifier(ctx, state, changedSession, provider, credentialAuthority()); err == nil {
		t.Fatal("session metadata swap accepted")
	}
	_ = session
}

func TestAuthorizationWithoutVerifierStoresNullEnvelope(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	req, state, _, _, _ := verifierRequestWithSeed(b, "legacy-state")
	req.Verifier = ""
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT verifier_envelope FROM saas_authorization_requests WHERE state_digest=?`, Args: []any{state}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil {
		t.Fatalf("legacy envelope=%v err=%v", q.Rows, err)
	}
}

func TestAuthorizationVerifierTwoRotationsPreserveProof(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	store.keys = credentialKeys(t, "key-a", "key-a", "key-b", "key-c")
	req, state, session, provider, verifier := verifierRequestWithSeed(b, "rotated")
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	for _, active := range []string{"key-b", "key-c"} {
		store.keys = credentialKeys(t, active, "key-a", "key-b", "key-c")
		result, err := RewrapAuthorizationEnvelopeBatch(ctx, db, store.keys, "")
		if err != nil || result.Rewrapped != 1 || !result.Done {
			t.Fatalf("rewrap %s: %+v %v", active, result, err)
		}
		refs, err := InspectAuthorizationEnvelopeReferences(ctx, db, store.keys)
		if err != nil || refs.Total != 1 || refs.ByKeyID[active] != 1 {
			t.Fatalf("references %s: %+v %v", active, refs, err)
		}
		got, plain, err := store.loadAuthorizationVerifier(ctx, state, session, provider, credentialAuthority())
		if err != nil || got != b || plain != verifier {
			t.Fatalf("proof after %s: %v", active, err)
		}
	}
}
