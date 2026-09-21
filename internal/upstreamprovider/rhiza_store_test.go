package upstreamprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRhizaStoreCiphertextDoesNotExposeSecrets(t *testing.T) {
	t.Parallel()
	ctx, store, db := testRhizaStore(t)
	tx := testRhizaTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_envelope FROM upstream_provider_transactions WHERE state_digest=?`, Args: []any{tx.StateDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("secret query: rows=%v err=%v", result.Rows, err)
	}
	envelope, ok := result.Rows[0][0].(string)
	if !ok || strings.Contains(envelope, tx.Nonce) || strings.Contains(envelope, tx.PKCEVerifier) || strings.Contains(envelope, tx.StateDigest) || strings.Contains(envelope, tx.BrowserBindingDigest) {
		t.Fatalf("secret envelope exposes transaction material: %q", envelope)
	}
}

func TestRhizaStoreExpiryBoundary(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ExpiresAt = tx.CreatedAt.Add(time.Millisecond)
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	_, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.ExpiresAt)
	if !errors.Is(err, ErrTransactionExpired) {
		t.Fatalf("Consume() error=%v, want expired", err)
	}
}

func TestRhizaStoreFencedOldWriterRollsBackAndReplacementIsAllowed(t *testing.T) {
	t.Parallel()
	ctx, db, oldStore, newStore := testRotatingRhizaStore(t)
	fenceMasterKeyRetirementForTest(t, ctx, db, "master-old", "master-new")
	tx := testRhizaTransaction()
	tx.StateDigest = DigestSHA256("fenced-save")
	if err := oldStore.Save(ctx, tx); err == nil {
		t.Fatal("fenced old writer was accepted")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM upstream_provider_transactions WHERE state_digest=?`, Args: []any{tx.StateDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("old writer left a row: rows=%#v err=%v", result.Rows, err)
	}
	if err := newStore.Save(ctx, tx); err != nil {
		t.Fatalf("replacement writer rejected: %v", err)
	}
	keyID, err := newStore.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, mustDecodeEnvelope(t, transactionEnvelopeText(t, ctx, db, tx.StateDigest)))
	if err != nil || keyID != "master-new" {
		t.Fatalf("replacement envelope key=%q err=%v", keyID, err)
	}
}

func TestRhizaStoreUsesAuthenticatedSealedKeyAsWriter(t *testing.T) {
	t.Parallel()
	ctx, db, _, replacement := testRotatingRhizaStore(t)
	fenceMasterKeyRetirementForTest(t, ctx, db, "master-old", "master-new")
	store, err := NewRhizaStore(db, &interposedRhizaKeyring{EnvelopeKeyring: replacement.keyring, active: "master-old"})
	if err != nil {
		t.Fatal(err)
	}
	tx := testRhizaTransaction()
	tx.StateDigest = DigestSHA256("authenticated-sealed-writer")
	if err := store.Save(ctx, tx); err != nil {
		t.Fatalf("sealed replacement writer rejected: %v", err)
	}
}

type interposedRhizaKeyring struct {
	EnvelopeKeyring
	active string
}

func (k *interposedRhizaKeyring) ActiveMasterKeyID() (string, error) { return k.active, nil }

func TestRhizaStoreRejectsInvalidTransaction(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.StateDigest = "not-a-digest"
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid digest: %v", err)
	}
	tx = testRhizaTransaction()
	tx.ProviderID = strings.Repeat("p", 65)
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long provider: %v", err)
	}
}

func TestRhizaStoreSaveRequestIDsUseEnvelopeDigest(t *testing.T) {
	t.Parallel()
	state := DigestSHA256("state")
	browser := DigestSHA256("browser")
	if first, second := transactionSaveRequestID(state, browser, "google", "envelope-one"), transactionSaveRequestID(state, browser, "google", "envelope-two"); first == second {
		t.Fatal("distinct encrypted envelopes reused a request ID")
	}
	if first, second := transactionSaveRequestID(state, browser, "google", "envelope"), transactionSaveRequestID(state, DigestSHA256("other-browser"), "google", "envelope"); first == second {
		t.Fatal("distinct browser bindings reused a request ID")
	}
	if first, second := transactionSaveRequestID(state, browser, "google", "envelope"), transactionSaveRequestID(state, browser, "github", "envelope"); first == second {
		t.Fatal("distinct providers reused a request ID")
	}
	if first, second := transactionRequestID("consume", state, browser, "google", "attempt"), transactionRequestID("consume", state, browser, "github", "attempt"); first == second {
		t.Fatal("consume request ID omitted provider binding")
	}
}

func TestRhizaStoreBindingRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionDigest != tx.SessionDigest || got.InteractionDigest != tx.InteractionDigest {
		t.Fatalf("binding = (%q, %q), want (%q, %q)", got.SessionDigest, got.InteractionDigest, tx.SessionDigest, tx.InteractionDigest)
	}
}

func TestRhizaStoreRoundTripsOAuthProviderWithoutNonce(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderID = "github"
	tx.Nonce = ""
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "" {
		t.Fatalf("nonce = %q, want empty", got.Nonce)
	}
}

func TestRhizaStoreLinkRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaLinkTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != PurposeLink || got.LinkSubject != tx.LinkSubject || got.LinkSessionDigest != tx.LinkSessionDigest {
		t.Fatalf("link transaction = %#v, want purpose=%q subject=%q session=%q", got, PurposeLink, tx.LinkSubject, tx.LinkSessionDigest)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionAlreadyConsumed) {
		t.Fatalf("link replay error=%v", err)
	}
}

func TestRhizaStoreLinkWrongSessionNeverConsumes(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaLinkTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, DigestSHA256("other-session"), tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong session error=%v", err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); err != nil {
		t.Fatalf("correct session after mismatch: %v", err)
	}
}

func TestRhizaStoreLegacyBindingRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.SessionDigest, tx.InteractionDigest = "", ""
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionDigest != "" || got.InteractionDigest != "" {
		t.Fatalf("legacy binding = (%q, %q), want empty", got.SessionDigest, got.InteractionDigest)
	}
}

func TestRhizaStoreRejectsMalformedLocalOAuthBinding(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	for _, tx := range []Transaction{
		func() Transaction { tx := testRhizaTransaction(); tx.SessionDigest = ""; return tx }(),
		func() Transaction { tx := testRhizaTransaction(); tx.InteractionDigest = "not-a-digest"; return tx }(),
	} {
		if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Save() error=%v, want invalid config", err)
		}
	}
	if err := ValidateLocalOAuthBinding("", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ValidateLocalOAuthBinding() error=%v, want invalid config", err)
	}
}

func TestRhizaStoreRejectsMalformedPurposeBindings(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	for _, tx := range []Transaction{
		func() Transaction { tx := testRhizaTransaction(); tx.LinkSubject = "subject"; return tx }(),
		func() Transaction {
			tx := testRhizaLinkTransaction()
			tx.SessionDigest = DigestSHA256("session")
			return tx
		}(),
		func() Transaction {
			tx := testRhizaLinkTransaction()
			tx.BrowserBindingDigest = DigestSHA256("other-session")
			return tx
		}(),
		func() Transaction { tx := testRhizaLinkTransaction(); tx.LinkSubject = " subject"; return tx }(),
	} {
		if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Save() error=%v, want invalid config", err)
		}
	}
}

func TestRhizaStoreRejectsBindingColumnEnvelopeMismatch(t *testing.T) {
	t.Parallel()
	ctx, store, db := testRhizaStore(t)
	tx := testRhizaTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "tamper-session-binding", SQL: `UPDATE upstream_provider_transactions SET session_digest=? WHERE state_digest=?`, Args: []any{DigestSHA256("tampered-session"), tx.StateDigest}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("Consume() error=%v, want transaction not found", err)
	}
}

func TestRhizaStoreRejectsLinkColumnEnvelopeMismatch(t *testing.T) {
	t.Parallel()
	ctx, store, db := testRhizaStore(t)
	tx := testRhizaLinkTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "tamper-link-subject", SQL: `UPDATE upstream_provider_transactions SET link_subject=? WHERE state_digest=?`, Args: []any{"other-subject", tx.StateDigest}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("Consume() error=%v, want transaction not found", err)
	}
}

func TestRhizaStoreRejectsTamperedLinkEnvelope(t *testing.T) {
	t.Parallel()
	ctx, store, db := testRhizaStore(t)
	tx := testRhizaLinkTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "tamper-link-envelope", SQL: `UPDATE upstream_provider_transactions SET secret_envelope=? WHERE state_digest=?`, Args: []any{"tampered", tx.StateDigest}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("Consume() error=%v, want transaction not found", err)
	}
}

func TestRhizaStoreWrongBindingsNeverConsume(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, DigestSHA256("other-browser"), tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong browser: %v", err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, "other-provider", tx.CreatedAt); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong provider: %v", err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); err != nil {
		t.Fatalf("correct binding after mismatches: %v", err)
	}
}

func TestRhizaStoreRejectsReplay(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionAlreadyConsumed) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestRhizaStoreConcurrentConsumeHasOneWinner(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaLinkTransaction()
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	winners, replays := 0, 0
	for err := range errs {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrTransactionAlreadyConsumed) {
			replays++
		} else {
			t.Fatalf("concurrent consume: %v", err)
		}
	}
	if winners != 1 || replays != 1 {
		t.Fatalf("winners=%d replays=%d", winners, replays)
	}
}

func testRhizaStore(t *testing.T) (context.Context, *RhizaStore, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db := openTestDB(t, "upstream-store-test")
	dir := t.TempDir()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(filepath.Join(dir, "test-key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(dir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRhizaStore(db, keyring)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, db
}

func fenceMasterKeyRetirementForTest(t *testing.T, ctx context.Context, db *rhiza.DB, oldKeyID, replacementKeyID string) {
	t.Helper()
	now := time.UnixMilli(1_900_000_000_000).UTC()
	if _, err := storage.PrepareMasterKeyRetirement(ctx, db, storage.MasterKeyRetirementPrepareRequest{Epoch: 1, OldKeyID: oldKeyID, ReplacementKeyID: replacementKeyID, MemberIDs: []string{"node-0", "node-1", "node-2"}, PreparedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.FenceMasterKeyRetirement(ctx, db, 1, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
}

func testRhizaTransaction() Transaction {
	now := time.Unix(1_800_000_000, 0).UTC()
	return Transaction{
		StateDigest: DigestSHA256("state"), BrowserBindingDigest: DigestSHA256("browser"), ProviderID: "google",
		SessionDigest: DigestSHA256("session"), InteractionDigest: DigestSHA256("interaction"),
		Nonce: "nonce-secret", PKCEVerifier: "pkce-secret", Issuer: "https://issuer.example.test", Audience: "audience", ClientID: "client",
		Scopes: []string{"openid"}, CallbackURI: "https://app.example.test/callback", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
}

func testRhizaLinkTransaction() Transaction {
	tx := testRhizaTransaction()
	tx.Purpose = PurposeLink
	tx.SessionDigest, tx.InteractionDigest = "", ""
	tx.LinkSubject = "subject-1"
	tx.LinkSessionDigest = tx.BrowserBindingDigest
	return tx
}
