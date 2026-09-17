package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestLinkExternalRetryAndFind(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "123"}
	now := time.UnixMilli(1000)
	decision, err := store.LinkExternal(ctx, "subject-1", external, now)
	if err != nil || decision != upstreamprovider.LinkDecisionLinked {
		t.Fatalf("first decision=%v err=%v", decision, err)
	}
	decision, err = store.LinkExternal(ctx, "subject-1", external, now)
	if err != nil || decision != upstreamprovider.LinkDecisionLinked {
		t.Fatalf("retry decision=%v err=%v", decision, err)
	}
	if got, found, err := store.FindExternalLink(ctx, external); err != nil || !found || got != "subject-1" {
		t.Fatalf("find subject=%q found=%v err=%v", got, found, err)
	}
}

func TestLinkExternalConflictsByExternalAndLocalProvider(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "subject-2", "bob", []byte("CurrentPassword1"))
	now := time.UnixMilli(2000)
	first := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "123"}
	if decision, err := store.LinkExternal(ctx, "subject-1", first, now); err != nil || decision != upstreamprovider.LinkDecisionLinked {
		t.Fatalf("first decision=%v err=%v", decision, err)
	}
	if decision, err := store.LinkExternal(ctx, "subject-2", first, now); decision != upstreamprovider.LinkDecisionConflict || !errors.Is(err, ErrExternalLinkConflict) {
		t.Fatalf("external conflict decision=%v err=%v", decision, err)
	}
	second := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "456"}
	if decision, err := store.LinkExternal(ctx, "subject-1", second, now); decision != upstreamprovider.LinkDecisionConflict || !errors.Is(err, ErrExternalLinkConflict) {
		t.Fatalf("local conflict decision=%v err=%v", decision, err)
	}
}

func TestLinkExternalRejectsMissingAndDisabledIdentity(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "missing"}
	if decision, err := store.LinkExternal(ctx, "missing", external, time.UnixMilli(3000)); decision != upstreamprovider.LinkDecisionNone || !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("missing decision=%v err=%v", decision, err)
	}
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "disable-external-link-test", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if decision, err := store.LinkExternal(ctx, "subject-1", upstreamprovider.SubjectResult{ProviderID: "google", Subject: "disabled"}, time.UnixMilli(3000)); decision != upstreamprovider.LinkDecisionNone || !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("disabled decision=%v err=%v", decision, err)
	}
}

func TestConcurrentExternalLinksConvergeToOneMapping(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "subject-2", "bob", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "race"}
	start := make(chan struct{})
	type outcome struct {
		decision upstreamprovider.LinkDecision
		err      error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, subject := range []string{"subject-1", "subject-2"} {
		wg.Add(1)
		go func(subject string) {
			defer wg.Done()
			<-start
			decision, err := store.LinkExternal(ctx, subject, external, time.UnixMilli(4000))
			results <- outcome{decision, err}
		}(subject)
	}
	close(start)
	wg.Wait()
	close(results)
	var linked, conflicts int
	for result := range results {
		if result.decision == upstreamprovider.LinkDecisionLinked && result.err == nil {
			linked++
		} else if result.decision == upstreamprovider.LinkDecisionConflict && errors.Is(result.err, ErrExternalLinkConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected race result=%#v", result)
		}
	}
	if linked != 1 || conflicts != 1 {
		t.Fatalf("linked=%d conflicts=%d", linked, conflicts)
	}
}

func TestUnlinkExternalRelinkAndPendingCleanup(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	bootstrapPassword(t, store, "subject-2", "bob", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "unlink"}
	base := time.UnixMilli(5000)
	if _, err := store.LinkExternal(ctx, "subject-1", external, base); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternal(ctx, "subject-1", "google", base, "attempt-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LinkExternal(ctx, "subject-2", external, base); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternal(ctx, "subject-2", "google", base, "attempt-2"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.FindExternalLink(ctx, external); err != nil || found {
		t.Fatalf("after unlink found=%v err=%v", found, err)
	}
	sameSubject := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "same-subject"}
	if _, err := store.LinkExternal(ctx, "subject-1", sameSubject, base); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternal(ctx, "subject-1", "google", base, "attempt-same-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LinkExternal(ctx, "subject-1", sameSubject, base); err != nil {
		t.Fatal(err)
	}
	if got, found, err := store.FindExternalLink(ctx, sameSubject); err != nil || !found || got != "subject-1" {
		t.Fatalf("same-time relink subject=%q found=%v err=%v", got, found, err)
	}

	pending := testResetStore(t, testRules(1))
	seedDeterministicRandom(pending)
	pending.now = func() time.Time { return base }
	registered, err := pending.RegisterOpenUser(ctx, OpenRegistration{Email: "pending@example.test", TTL: time.Minute})
	if err != nil || !registered.Created {
		t.Fatalf("pending registration=%#v err=%v", registered, err)
	}
	pendingExternal := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "pending"}
	if _, err := pending.LinkExternal(ctx, registered.Subject, pendingExternal, base); err != nil {
		t.Fatal(err)
	}
	if err := pending.CleanupExpiredOpenRegistrations(ctx, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := pending.FindExternalLink(ctx, pendingExternal); err != nil || found {
		t.Fatalf("pending link found=%v err=%v", found, err)
	}
}

func TestUnlinkExternalDoesNotDeleteDisabledSubjectLink(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "disabled-unlink"}
	now := time.UnixMilli(6000)
	if _, err := store.LinkExternal(ctx, "subject-1", external, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "disable-before-external-unlink", SQL: `UPDATE identity_users SET disabled = 1 WHERE subject = ?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkExternal(ctx, "subject-1", "google", now, "attempt-disabled"); err != nil {
		t.Fatal(err)
	}
	result, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_external_links WHERE provider_id = ? AND local_subject = ?`, Args: []any{"google", "subject-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(1) {
		t.Fatalf("link rows=%#v err=%v", result.Rows, err)
	}
}

func TestExpiredPasswordNewTokenDoesNotDeleteCompletedExternalLink(t *testing.T) {
	store := testResetStore(t, testRules(1))
	ctx := context.Background()
	bootstrapPassword(t, store, "subject-1", "alice", []byte("CurrentPassword1"))
	external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "completed"}
	now := time.UnixMilli(120000)
	if _, err := store.LinkExternal(ctx, "subject-1", external, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "completed-expired-password-new", SQL: `INSERT INTO identity_password_reset_tokens (token_digest,subject,password_generation,issued_at_unix_ms,expires_at_unix_ms,usage) VALUES (?,?,?,?,?,'password_new')`, Args: []any{digestForTest("completed-expired-password-new"), "subject-1", int64(1), now.Add(-time.Minute).UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupExpiredOpenRegistrations(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got, found, err := store.FindExternalLink(ctx, external); err != nil || !found || got != "subject-1" {
		t.Fatalf("completed link subject=%q found=%v err=%v", got, found, err)
	}
}
