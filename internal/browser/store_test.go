package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestSessionAndCookie(t *testing.T) {
	store := testStore(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	init, err := store.CreateInitSession(context.Background(), now.Add(time.Minute), "")
	if err != nil || init.Authenticated() {
		t.Fatalf("init=%#v err=%v", init, err)
	}
	if _, err := store.CreateSession(context.Background(), "", "pwd", now.Add(time.Hour), ""); err == nil {
		t.Fatal("authenticated session accepted empty subject")
	}
	if _, err := store.CreateSession(context.Background(), "user-1", "", now.Add(time.Hour), ""); err == nil {
		t.Fatal("authenticated session accepted empty method")
	}
	if _, err := store.CreateSession(context.Background(), "user-1", "other", now.Add(time.Hour), ""); err == nil {
		t.Fatal("authenticated session accepted unknown method")
	}
	external, err := store.CreateSession(context.Background(), "user-external", "external", now.Add(time.Hour), "")
	if err != nil || !external.Authenticated() || external.AuthenticationMethod != "external" {
		t.Fatalf("external session=%#v err=%v", external, err)
	}
	issued, err := store.CreateSession(context.Background(), "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == init.Token || !issued.Authenticated() || issued.AuthenticationMethod != "pwd" {
		t.Fatalf("auth session did not replace init state: init=%#v auth=%#v", init, issued)
	}
	if len(issued.Token) != 43 {
		t.Fatalf("token length=%d", len(issued.Token))
	}
	loaded, err := store.LoadSession(context.Background(), issued.Token)
	if err != nil || loaded.Subject != "user-1" || loaded.ExpiresAt.UnixMilli() != issued.ExpiresAt.UnixMilli() {
		t.Fatalf("session=%#v err=%v", loaded, err)
	}
	cookie, err := SessionCookie("https://issuer.example.test", issued.Token, issued.ExpiresAt)
	if err != nil || cookie.Name != secureSessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.MaxAge <= 0 || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie=%#v err=%v", cookie, err)
	}
	loopback, err := SessionCookie("http://localhost:8080", issued.Token, issued.ExpiresAt)
	if err != nil || loopback.Secure {
		t.Fatalf("loopback cookie=%#v err=%v", loopback, err)
	}
	if name, err := CookieName("https://issuer.example.test"); err != nil || name != secureSessionCookieName {
		t.Fatalf("secure cookie name=%q err=%v", name, err)
	}
	if name, err := CookieName("https://issuer.example.test/tenant"); err != nil || name != secureSessionCookieName {
		t.Fatalf("path issuer cookie name=%q err=%v", name, err)
	}
	deleted, err := DeleteSessionCookie("https://issuer.example.test")
	if err != nil || deleted.Name != secureSessionCookieName || deleted.Value != "" || deleted.MaxAge != -1 || !deleted.Expires.Equal(time.Unix(1, 0).UTC()) || !deleted.HttpOnly || !deleted.Secure || deleted.Path != "/" || deleted.SameSite != http.SameSiteLaxMode {
		t.Fatalf("deletion cookie=%#v err=%v", deleted, err)
	}
	if _, err := CookieName("http://issuer.example.test"); err == nil {
		t.Fatal("non-loopback HTTP cookie issuer accepted")
	}
	if err := store.RevokeSession(context.Background(), issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSession(context.Background(), issued.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked session err=%v", err)
	}
}

func TestAuthenticatedSessionRequiresEnabledUnexpiredIdentity(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	for i, subject := range []string{"missing-user", "user-1", "user-2"} {
		if subject == "user-1" {
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-expiry-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{subject}}); err != nil {
				t.Fatal(err)
			}
		} else if subject == "user-2" {
			if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-expiry-expire", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{now.UnixMilli(), subject}}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.CreateSession(ctx, subject, "pwd", now.Add(time.Hour), ""); err == nil {
			t.Fatalf("session %d accepted for %s", i, subject)
		}
	}
}

func TestSessionExpiryIsCappedAndNullIdentityKeepsRequestedExpiry(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	deadline := now.Add(30 * time.Minute)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-cap-deadline", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{deadline.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if !issued.ExpiresAt.Equal(deadline) {
		t.Fatalf("capped expiry=%v want=%v", issued.ExpiresAt, deadline)
	}
	unlimited, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if !unlimited.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unlimited expiry=%v", unlimited.ExpiresAt)
	}
}

func TestSessionIdentityRevocationAtDeadlineAffectsLoadsAndGuard(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(10 * time.Minute)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-shorten-deadline", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{deadline.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	now = deadline
	if _, err := store.LoadSession(ctx, issued.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("boundary load err=%v", err)
	}
	if _, err := store.LoadSessionReadOnly(ctx, issued.Token); !errors.Is(err, ErrExpired) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("boundary readonly err=%v", err)
	}
	guard, args := store.SessionAuthorizationGuard(issued.Session, "")
	r, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 WHERE ` + guard, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 0 {
		t.Fatalf("boundary guard rows=%v err=%v", r.Rows, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-disable-after-issue", SQL: `UPDATE identity_users SET disabled=1,user_expires_at_unix_ms=NULL WHERE subject='user-1'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionReadOnly(ctx, issued.Token); !errors.Is(err, ErrExpired) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled readonly err=%v", err)
	}
	deleted, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-delete-after-issue", SQL: `DELETE FROM identity_users WHERE subject='user-2'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionReadOnly(ctx, deleted.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted identity load err=%v", err)
	}
}

func TestExpiredSessionDoesNotConsumeAuthorizationInteraction(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, issued.Token, "expired-session", []byte("state"), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// Both the session and interaction remain live. Only the account expires.
	now = now.Add(time.Minute)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-expire-interaction-owner", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, issued.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume err=%v", err)
	}
	digest, _ := tokenDigest(interaction.Token)
	r, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT consumed_attempt FROM browser_authorization_interactions WHERE token_digest=?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != nil {
		t.Fatalf("consumed row=%v err=%v", r.Rows, err)
	}
}

func TestRevokeSessionIDUsesOnlyPublicDigest(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if issued.ID == issued.Token {
		t.Fatal("session ID exposed bearer token")
	}
	if err := store.RevokeSessionID(ctx, issued.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("raw token accepted as session ID: %v", err)
	}
	if _, err := store.LoadSession(ctx, issued.Token); err != nil {
		t.Fatalf("raw token attempt changed session: %v", err)
	}
	if err := store.RevokeSessionID(ctx, issued.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSession(ctx, issued.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session ID revocation err=%v", err)
	}
	if err := store.RevokeSessionID(ctx, issued.ID); err != nil {
		t.Fatalf("idempotent public ID revocation: %v", err)
	}
	if err := store.RevokeSessionID(ctx, "not-a-session-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed session ID err=%v", err)
	}
}

func TestCanonicalTokenDigestRejectsNoncanonicalTokens(t *testing.T) {
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	digest, err := CanonicalTokenDigest(token)
	if err != nil || len(digest) != 43 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	for _, invalid := range []string{"", token + "=", token[:42] + "B"} {
		if _, err := CanonicalTokenDigest(invalid); err == nil {
			t.Fatalf("noncanonical token accepted: %q", invalid)
		}
	}
}

func TestLoadSessionFailsClosedForInvalidAuthenticationPair(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	token, digest, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-invalid-auth-pair", SQL: `INSERT INTO browser_sessions (token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES (?,?,?,?,?,?)`, Args: []any{digest, "user-1", "", now.UnixMilli(), now.Add(time.Hour).UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionReadOnly(ctx, token); err == nil {
		t.Fatal("mismatched browser authentication row loaded")
	}
}

func TestExternalSessionLoadsAndConsumesAuthorizationInteraction(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	session, err := store.CreateSession(ctx, "external-user", "external", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSessionReadOnly(ctx, session.Token)
	if err != nil || !loaded.Authenticated() || loaded.AuthenticationMethod != "external" {
		t.Fatalf("external session=%#v err=%v", loaded, err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "external-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := store.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token)
	if err != nil || consumed.Subject != "external-user" || consumed.RequestID != "external-request" {
		t.Fatalf("external interaction=%#v err=%v", consumed, err)
	}
}

func TestLoadSessionReadOnlyDoesNotExtendIdleLifetime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(touchInterval + time.Second)
	if _, err := store.LoadSessionReadOnly(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(issued.CreatedAt) {
		t.Fatalf("read-only load touched session: got %s want %s", got, issued.CreatedAt)
	}
}

func TestAuthorizationInteractionIsSingleUseAndBoundToSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "request-1", []byte(`{"client_id":"browser"}`), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			got, err := store.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token)
			if err == nil && (got.RequestID != "request-1" || got.Subject != "user-1" || string(got.Payload) != `{"client_id":"browser"}`) {
				err = errors.New("wrong consumed interaction")
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrConsumed) {
			t.Fatalf("consume err=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumes=%d", successes)
	}

	other, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := store.CreateAuthorizationInteraction(ctx, session.Token, "request-2", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, other.Token, bound.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session consume err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, session.Token, bound.Token); err != nil {
		t.Fatalf("bound interaction lost after rejected cross-session attempt: %v", err)
	}
}

func TestAuthorizationInteractionRejectsExpiredOrRevokedSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "request-1", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSession(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked consume err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyIsBoundAndDoesNotConsume(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	init, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, init.Token, "request-read-only", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadAuthorizationInteractionReadOnly(ctx, init.Token, interaction.Token)
	if err != nil || got.RequestID != interaction.RequestID || string(got.Payload) != "state" {
		t.Fatalf("read-only interaction=%#v err=%v", got, err)
	}
	if _, err := store.LoadAuthorizationInteractionReadOnly(ctx, other.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-session read err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, init.Token, interaction.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAuthorizationInteractionReadOnly(ctx, init.Token, interaction.Token); !errors.Is(err, ErrConsumed) {
		t.Fatalf("consumed read err=%v", err)
	}
	expired, err := store.CreateAuthorizationInteraction(ctx, init.Token, "request-expired", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := store.LoadAuthorizationInteractionReadOnly(ctx, init.Token, expired.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired read err=%v", err)
	}
}

func TestAuthorizationInteractionByDigestRequiresInitSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	init, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, init.Token, "request-digest-load", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tokenDigest(interaction.Token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadAuthorizationInteractionReadOnlyByDigest(ctx, init.Token, digest)
	if err != nil || got.RequestID != interaction.RequestID || string(got.Payload) != "state" {
		t.Fatalf("digest read=%#v err=%v", got, err)
	}
	for _, invalid := range []string{"bad", digest[:42] + "B", digest + "="} {
		if _, err := store.LoadAuthorizationInteractionReadOnlyByDigest(ctx, init.Token, invalid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("invalid digest %q read err=%v", invalid, err)
		}
		if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, init.Token, invalid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("invalid digest %q consume err=%v", invalid, err)
		}
	}
	if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, other.Token, digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-session consume err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, init.Token, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAuthorizationInteractionReadOnlyByDigest(ctx, init.Token, digest); !errors.Is(err, ErrConsumed) {
		t.Fatalf("replay read err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, init.Token, digest); !errors.Is(err, ErrConsumed) {
		t.Fatalf("replay consume err=%v", err)
	}

	expired, err := store.CreateAuthorizationInteraction(ctx, init.Token, "request-digest-expired", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expiredDigest, err := tokenDigest(expired.Token)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := store.LoadAuthorizationInteractionReadOnlyByDigest(ctx, init.Token, expiredDigest); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired read err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, init.Token, expiredDigest); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired consume err=%v", err)
	}

	auth, err := store.CreateSession(ctx, "user-1", "external", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	authInteraction, err := store.CreateAuthorizationInteraction(ctx, auth.Token, "request-digest-auth", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authDigest, err := tokenDigest(authInteraction.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAuthorizationInteractionReadOnlyByDigest(ctx, auth.Token, authDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authenticated digest read err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteractionByDigest(ctx, auth.Token, authDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authenticated digest consume err=%v", err)
	}
}

func TestConsumeAuthorizationInteractionByDigestIsSingleUse(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	init, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, init.Token, "request-digest-concurrent", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tokenDigest(interaction.Token)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			got, err := store.ConsumeAuthorizationInteractionByDigest(ctx, init.Token, digest)
			if err == nil && (got.RequestID != interaction.RequestID || string(got.Payload) != "state") {
				err = errors.New("wrong digest-consumed interaction")
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrConsumed) {
			t.Fatalf("digest consume err=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful digest consumes=%d", successes)
	}
}

func TestSessionIdleBoundaryAndTouchThrottle(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(4*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(now) {
		t.Fatalf("initial last seen=%v want=%v", got, now)
	}
	now = now.Add(touchInterval - time.Millisecond)
	if _, err := store.LoadSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(issued.CreatedAt) {
		t.Fatalf("last seen changed before throttle: %v", got)
	}
	now = issued.CreatedAt.Add(touchInterval)
	if _, err := store.LoadSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(now) {
		t.Fatalf("last seen=%v want=%v", got, now)
	}

	idle, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(4*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	now = idle.CreatedAt.Add(DefaultIdleTimeout)
	if _, err := store.LoadSession(ctx, idle.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("idle boundary err=%v", err)
	}
}

func TestLoadSessionForPeerRejectsMismatchBeforeTouch(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	now = issued.CreatedAt.Add(touchInterval - time.Millisecond)
	for _, peerIP := range []string{"198.51.100.9", ""} {
		if _, err := store.LoadSessionForPeer(ctx, issued.Token, peerIP); !errors.Is(err, ErrPeerIPMismatch) {
			t.Fatalf("peer %q within throttle err=%v want %v", peerIP, err, ErrPeerIPMismatch)
		}
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(issued.CreatedAt) {
		t.Fatalf("within-throttle mismatch touched session: got %s want %s", got, issued.CreatedAt)
	}
	now = issued.CreatedAt.Add(touchInterval + time.Second)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-reject-peer-touch-trigger", SQL: `CREATE TRIGGER reject_browser_session_touch BEFORE UPDATE OF last_seen_at_unix_ms ON browser_sessions BEGIN SELECT RAISE(ABORT, 'unexpected session touch'); END`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "198.51.100.9"); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("wrong peer load err=%v want %v", err, ErrPeerIPMismatch)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(issued.CreatedAt) {
		t.Fatalf("wrong peer touched session: got %s want %s", got, issued.CreatedAt)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-remove-peer-touch-trigger", SQL: `DROP TRIGGER reject_browser_session_touch`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "203.0.113.8"); err != nil {
		t.Fatalf("matching peer load err=%v", err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(now) {
		t.Fatalf("matching peer last_seen=%s want %s", got, now)
	}
}

func TestSessionTouchV2DoesNotConflictWithBaseReceipt(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tokenDigest(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	now = issued.CreatedAt.Add(touchInterval + time.Second)
	baseRequestID := mutationID("session-touch", digest, fmt.Sprint(now.UnixMilli()))
	headRequestID := mutationID("session-touch-v2", digest, fmt.Sprint(now.UnixMilli()))
	if baseRequestID == headRequestID {
		t.Fatal("HEAD touch reused the pre-#104 request ID")
	}
	// This is the six-argument mutation submitted by the pre-#104 BASE binary.
	baseResponse, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{
		RequestID: baseRequestID,
		SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms = ?
			WHERE token_digest = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ?
			AND last_seen_at_unix_ms > ? AND last_seen_at_unix_ms <= ? AND ` + activeSessionSubjectSQL,
		Args: []any{now.UnixMilli(), digest, now.UnixMilli(), now.Add(-store.idleTimeout).UnixMilli(), now.Add(-touchInterval).UnixMilli(), now.UnixMilli()},
	})
	if err != nil || baseResponse.MutationReceipt.RowsAffected != 1 {
		t.Fatalf("BASE touch receipt=%+v err=%v", baseResponse.MutationReceipt, err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-reset-base-touch", SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?`, Args: []any{issued.CreatedAt.UnixMilli(), digest}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "203.0.113.8"); err != nil {
		t.Fatalf("HEAD touch conflicted with BASE receipt: %v", err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(now) {
		t.Fatalf("HEAD touch last_seen=%s want %s", got, now)
	}
}

func TestLoadSessionForPeerRechecksBindingAfterNoopTouch(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(touchInterval + time.Second)
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-change-peer-on-touch", SQL: `CREATE TRIGGER change_browser_session_peer_on_touch BEFORE UPDATE OF last_seen_at_unix_ms ON browser_sessions BEGIN UPDATE browser_sessions SET peer_ip='198.51.100.9' WHERE token_digest=OLD.token_digest; SELECT RAISE(IGNORE); END`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "203.0.113.8"); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("peer change during no-op touch err=%v want %v", err, ErrPeerIPMismatch)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(issued.CreatedAt) {
		t.Fatalf("no-op touch changed last_seen: got %s want %s", got, issued.CreatedAt)
	}
}

func TestLoadSessionForPeerTouchesLegacyEmptyBinding(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(touchInterval + time.Second)
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "198.51.100.9"); err != nil {
		t.Fatalf("legacy empty peer binding rejected: %v", err)
	}
	if got := sessionLastSeen(t, store, issued.Token); !got.Equal(now) {
		t.Fatalf("legacy session last_seen=%s want %s", got, now)
	}
}

func TestSessionTouchReplayIsStableAcrossPeerCallers(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(touchInterval + time.Second)
	if _, err := store.LoadSession(ctx, issued.Token); err != nil {
		t.Fatalf("initial touch: %v", err)
	}
	resetLastSeen := func(requestID string) {
		t.Helper()
		if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `UPDATE browser_sessions SET last_seen_at_unix_ms=? WHERE token_digest=?`, Args: []any{issued.CreatedAt.UnixMilli(), issued.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	resetLastSeen("browser-reset-touch-replay-one")
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "198.51.100.9"); err != nil {
		t.Fatalf("same-ms touch through peer API: %v", err)
	}
	resetLastSeen("browser-reset-touch-replay-two")
	if _, err := store.LoadSessionForPeer(ctx, issued.Token, "203.0.113.17"); err != nil {
		t.Fatalf("same-ms legacy touch through another peer: %v", err)
	}
}

func TestLoadSessionForPeerPreservesValidityGuards(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	expired, err := store.CreateSession(ctx, "user-external", "pwd", now.Add(5*time.Second), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	inactive, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(touchInterval + time.Second)
	if err := store.RevokeSession(ctx, revoked.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "browser-disable-touched-session", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='user-2'`}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		issued IssuedSession
		want   error
	}{{"expired", expired, ErrExpired}, {"revoked", revoked, ErrRevoked}, {"inactive", inactive, ErrNotFound}} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.LoadSessionForPeer(ctx, test.issued.Token, "203.0.113.8"); !errors.Is(err, test.want) {
				t.Fatalf("load err=%v want %v", err, test.want)
			}
			if got := sessionLastSeen(t, store, test.issued.Token); !got.Equal(test.issued.CreatedAt) {
				t.Fatalf("invalid session touched: got %s want %s", got, test.issued.CreatedAt)
			}
		})
	}
}

func TestConcurrentLoadSessionForPeerTouches(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	base := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return base }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", base.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	store.now = func() time.Time { return base.Add(touchInterval + time.Duration(calls.Add(1))*time.Millisecond) }
	const readers = 16
	start := make(chan struct{})
	errs := make(chan error, readers)
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.LoadSessionForPeer(ctx, issued.Token, "203.0.113.8")
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent load err=%v", err)
		}
	}
	if got := sessionLastSeen(t, store, issued.Token); got.Before(base.Add(touchInterval)) {
		t.Fatalf("concurrent loads did not touch session: last_seen=%s", got)
	}
}

func TestInteractionsRejectIdleSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(4*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, issued.Token, "request-1", []byte("state"), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultIdleTimeout)
	if _, err := store.CreateAuthorizationInteraction(ctx, issued.Token, "request-2", []byte("state"), now.Add(time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("idle create err=%v", err)
	}
	if _, err := store.ConsumeAuthorizationInteraction(ctx, issued.Token, interaction.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("idle consume err=%v", err)
	}
}

func sessionLastSeen(t *testing.T, store *Store, token string) time.Time {
	t.Helper()
	digest, err := tokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT last_seen_at_unix_ms FROM browser_sessions WHERE token_digest = ?`, Args: []any{digest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("last seen rows=%#v err=%v", result.Rows, err)
	}
	ms, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("last seen type=%T", result.Rows[0][0])
	}
	return time.UnixMilli(ms).UTC()
}

func TestSessionPeerIPStorageAndRetrieval(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if issued.PeerIP != "203.0.113.8" {
		t.Fatalf("PeerIP=%q want %q", issued.PeerIP, "203.0.113.8")
	}
	loaded, err := store.LoadSession(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PeerIP != "203.0.113.8" {
		t.Fatalf("loaded PeerIP=%q want %q", loaded.PeerIP, "203.0.113.8")
	}
}

func TestSessionEmptyPeerIP(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	issued, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if issued.PeerIP != "" {
		t.Fatalf("PeerIP=%q want empty", issued.PeerIP)
	}
	loaded, err := store.LoadSession(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PeerIP != "" {
		t.Fatalf("loaded PeerIP=%q want empty", loaded.PeerIP)
	}
}

func TestInitSessionStoresPeerIP(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	init, err := store.CreateInitSession(ctx, now.Add(time.Minute), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if init.PeerIP != "10.0.0.1" {
		t.Fatalf("init PeerIP=%q want %q", init.PeerIP, "10.0.0.1")
	}
	loaded, err := store.LoadSessionReadOnly(ctx, init.Token)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PeerIP != "10.0.0.1" {
		t.Fatalf("loaded init PeerIP=%q want %q", loaded.PeerIP, "10.0.0.1")
	}
}

func TestForegroundSessionExpiryCleanupMutationCap(t *testing.T) {
	for _, backlog := range []int{0, 100, 1000} {
		t.Run(fmt.Sprintf("backlog_%d", backlog), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
			s.now = func() time.Time { return now }
			liveDigest := fmt.Sprintf("%043d", 10_000_000)
			liveBinding := rhiza.SQLStatement{SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{liveDigest, "https://issuer.example.test", "live-client", "live-subject", "live-sid", now.UnixMilli()}}
			liveSession := rhiza.SQLStatement{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES(?,?,?,?,?,?,?)`, Args: []any{liveDigest, "user-external", "external", now.Add(-time.Minute).UnixMilli(), now.Add(time.Hour).UnixMilli(), now.Add(-time.Minute).UnixMilli(), ""}}
			if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-cleanup-live-control", Statements: []rhiza.SQLStatement{liveSession, liveBinding}}); err != nil {
				t.Fatal(err)
			}
			init, err := s.CreateInitSession(ctx, now.Add(time.Hour), "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"init-interaction", "password-session"} {
				t.Run(path, func(t *testing.T) {
					seedExpiredBrowserSessions(t, s, ctx, backlog, now, path)
					beforeSessions := expiredBrowserSessionCount(t, s, ctx, now)
					beforeBindings := expiredBrowserBindingCount(t, s, ctx, now)
					started := time.Now()
					if path == "init-interaction" {
						_, _, err = s.CreateInitSessionWithAuthorizationInteraction(ctx, "192.0.2.1", fmt.Sprintf("cleanup-%s-%d", path, backlog), []byte("state"), now.Add(time.Minute))
					} else {
						_, err = s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, now.Add(time.Hour), "192.0.2.1", init.Token)
					}
					elapsed := time.Since(started)
					if err != nil {
						t.Fatal(err)
					}
					afterSessions := expiredBrowserSessionCount(t, s, ctx, now)
					afterBindings := expiredBrowserBindingCount(t, s, ctx, now)
					removedSessions, removedBindings := beforeSessions-afterSessions, beforeBindings-afterBindings
					t.Logf("path=%s backlog=%d expired_sessions_mutated=%d bindings_mutated=%d elapsed=%s (observed, not a latency bound)", path, backlog, removedSessions, removedBindings, elapsed)
					if removedSessions > 32 || removedBindings > 32 {
						t.Errorf("cleanup exceeded 32-row mutation cap: sessions=%d bindings=%d", removedSessions, removedBindings)
					}
					if removedSessions != removedBindings {
						t.Errorf("binding/session cleanup mismatch: sessions=%d bindings=%d", removedSessions, removedBindings)
					}
					if got := countBrowserRows(t, s, ctx, `SELECT COUNT(*) FROM browser_sessions WHERE token_digest=? AND expires_at_unix_ms>?`, liveDigest, now.UnixMilli()); got != 1 {
						t.Errorf("live session control count=%d want=1", got)
					}
					if got := countBrowserRows(t, s, ctx, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest=?`, liveDigest); got != 1 {
						t.Errorf("live binding control count=%d want=1", got)
					}
				})
			}
		})
	}
}

func seedExpiredBrowserSessions(t *testing.T, s *Store, ctx context.Context, count int, now time.Time, key string) {
	t.Helper()
	salt := 0
	for _, value := range key {
		salt += int(value)
	}
	for start := 0; start < count; start += 32 {
		end := start + 32
		if end > count {
			end = count
		}
		statements := make([]rhiza.SQLStatement, 0, (end-start)*2)
		for i := start; i < end; i++ {
			digest := fmt.Sprintf("%043d", salt*1_000_000+i+1)
			statements = append(statements,
				rhiza.SQLStatement{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) VALUES(?,?,?,?,?,?,?)`, Args: []any{digest, "user-external", "external", now.Add(-time.Hour).UnixMilli(), now.Add(-time.Minute).UnixMilli(), now.Add(-time.Hour).UnixMilli(), ""}},
				rhiza.SQLStatement{SQL: `INSERT INTO browser_upstream_session_bindings(session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{digest, "https://issuer.example.test", "expired-client", "expired-subject", "expired-sid", now.Add(-time.Hour).UnixMilli()}},
			)
		}
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("expiry-cleanup-seed-%s-%d", key, start), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
}

func expiredBrowserSessionCount(t *testing.T, s *Store, ctx context.Context, now time.Time) int64 {
	t.Helper()
	return countBrowserRows(t, s, ctx, `SELECT COUNT(*) FROM browser_sessions WHERE expires_at_unix_ms<=?`, now.UnixMilli())
}

func expiredBrowserBindingCount(t *testing.T, s *Store, ctx context.Context, now time.Time) int64 {
	t.Helper()
	return countBrowserRows(t, s, ctx, `SELECT COUNT(*) FROM browser_upstream_session_bindings WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE expires_at_unix_ms<=?)`, now.UnixMilli())
}

func countBrowserRows(t *testing.T, s *Store, ctx context.Context, query string, args ...any) int64 {
	t.Helper()
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("count query rows=%v err=%v", row.Rows, err)
	}
	return row.Rows[0][0].(int64)
}

func TestBoundedSessionExpiryCleanupRollsBackOnLaterFailure(t *testing.T) {
	for _, path := range []string{"init-interaction", "password-session"} {
		t.Run(path, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
			s.now = func() time.Time { return now }
			init, err := s.CreateInitSession(ctx, now.Add(time.Hour), "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			seedExpiredBrowserSessions(t, s, ctx, 40, now, "rollback-"+path)
			if path == "init-interaction" {
				_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-cleanup-reject-interaction", SQL: `CREATE TRIGGER expiry_cleanup_reject_interaction BEFORE INSERT ON browser_authorization_interactions BEGIN SELECT RAISE(ABORT, 'reject later interaction'); END`})
			} else {
				_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "expiry-cleanup-reject-login-record", SQL: `CREATE TRIGGER expiry_cleanup_reject_login_record BEFORE UPDATE OF last_login_at_unix_ms ON identity_users BEGIN SELECT RAISE(ABORT, 'reject later login record'); END`})
			}
			if err != nil {
				t.Fatal(err)
			}
			if path == "init-interaction" {
				_, _, err = s.CreateInitSessionWithAuthorizationInteraction(ctx, "192.0.2.1", "rollback-expiry-pair", []byte("state"), now.Add(time.Minute))
			} else {
				_, err = s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, now.Add(time.Hour), "192.0.2.1", init.Token)
			}
			if err == nil {
				t.Fatal("expected later statement failure")
			}
			if got := expiredBrowserSessionCount(t, s, ctx, now); got != 40 {
				t.Errorf("expired sessions after rollback=%d want=40", got)
			}
			if got := expiredBrowserBindingCount(t, s, ctx, now); got != 40 {
				t.Errorf("expired bindings after rollback=%d want=40", got)
			}
			if path == "password-session" {
				if _, err := s.LoadSessionReadOnly(ctx, init.Token); err != nil {
					t.Errorf("failed password batch consumed init session: %v", err)
				}
				if got := countBrowserRows(t, s, ctx, `SELECT COUNT(*) FROM browser_sessions WHERE subject='user-1' AND revoked_at_unix_ms IS NULL`); got != 0 {
					t.Errorf("failed password batch left authenticated sessions=%d", got)
				}
			}
		})
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "browser-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var statements []rhiza.SQLStatement
	for _, subject := range []string{"user-1", "user-2", "user-external", "external-user"} {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES (?,?,?)`, Args: []any{subject, subject, "phc"}})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES ('user-1','password',1,0)`})
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "browser-test-schema", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCreatePasswordSessionCombinesWrites(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Hour).UnixMilli()
	newSession, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token)
	if err != nil {
		t.Fatal(err)
	}
	if newSession.Token == "" || newSession.Session.ID == "" {
		t.Fatal("missing new session")
	}
	if _, err := s.LoadSessionReadOnly(ctx, init.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old init session should be revoked: %v", err)
	}
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms FROM identity_users WHERE subject=?`, Args: []any{"user-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("login bookkeeping read: %v", err)
	}
	if lastLogin := row.Rows[0][0].(int64); lastLogin < before {
		t.Fatalf("login timestamp %d not monotonic (>= %d)", lastLogin, before)
	}
}

func TestCreatePasswordSessionRejectsStaleAuthenticationGenerations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change string
	}{
		{name: "password reset", change: `UPDATE identity_users SET password_generation=password_generation+1 WHERE subject='user-1'`},
		{name: "password mode changed", change: `UPDATE identity_authentication_modes SET mode='passkey',generation=generation+1 WHERE subject='user-1'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "password-generation-change", SQL: tc.change}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err == nil {
				t.Fatal("stale authentication proof created a password session")
			}
			assertNoPasswordReplacement(t, s, ctx, "user-1")
			if _, err := s.LoadSessionReadOnly(ctx, init.Token); err != nil {
				t.Fatalf("failed session creation consumed the init session: %v", err)
			}
		})
	}
}

func TestCreatePasswordSessionRejectsBadOldInit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(ctx, init.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err == nil {
		t.Fatal("expected rejection for revoked old init")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionRejectsPeerMismatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.9", init.Token); err == nil {
		t.Fatal("expected rejection for peer mismatch")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionRejectsExpiredUser(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "password-expired-user", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{time.Now().Add(-time.Hour).UnixMilli(), "user-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err == nil {
		t.Fatal("expected rejection for expired user")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionRejectsExpiredOldInit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "password-expire-init", SQL: `UPDATE browser_sessions SET expires_at_unix_ms=? WHERE token_digest=?`, Args: []any{time.Now().Add(-time.Hour).UnixMilli(), init.Session.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err == nil {
		t.Fatal("expected rejection for expired old init")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionRejectsDisabledUser(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "password-disable-user", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"user-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err == nil {
		t.Fatal("expected rejection for disabled user")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionResetsFailedMetadataMonotonic(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	later := time.Now().Add(48 * time.Hour).UnixMilli()
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "password-seed-metadata", SQL: `UPDATE identity_users SET last_login_at_unix_ms=?, failed_login_attempts=3, last_failed_login_at_unix_ms=? WHERE subject=?`, Args: []any{later, later, "user-1"}}); err != nil {
		t.Fatal(err)
	}
	init, err := s.CreateInitSession(ctx, time.Now().Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", init.Token); err != nil {
		t.Fatal(err)
	}
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms, failed_login_attempts, last_failed_login_at_unix_ms FROM identity_users WHERE subject=?`, Args: []any{"user-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("metadata read: %v", err)
	}
	if got := row.Rows[0][0].(int64); got != later {
		t.Fatalf("monotonic last_login=%d want=%d", got, later)
	}
	if row.Rows[0][1] != nil || row.Rows[0][2] != nil {
		t.Fatalf("failure metadata not reset: %v", row.Rows[0])
	}
}

func assertNoPasswordReplacement(t *testing.T, s *Store, ctx context.Context, subject string) {
	t.Helper()
	row, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_sessions WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatalf("session count read: %v", err)
	}
	if count := row.Rows[0][0].(int64); count != 0 {
		t.Fatalf("expected no new session, got %d", count)
	}
	meta, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms FROM identity_users WHERE subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(meta.Rows) != 1 {
		t.Fatalf("metadata read: %v", err)
	}
	if meta.Rows[0][0] != nil {
		t.Fatalf("expected no bookkeeping, got %v", meta.Rows[0][0])
	}
}

func TestCreatePasswordSessionRejectsMalformedToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", "invalid-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for malformed old token, got %v", err)
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCreatePasswordSessionRollsBackOnGuardFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// A valid canonical 32-byte base64url token that is not stored: the token
	// decodes, but the old-init revoke guard matches zero rows, so the guarded
	// transaction must reject and leave no replacement or bookkeeping.
	unused := strings.Repeat("A", 43)
	if _, err := CanonicalTokenDigest(unused); err != nil {
		t.Fatalf("fixture token must be canonical: %v", err)
	}
	if _, err := s.CreatePasswordSession(ctx, "user-1", "pwd", 1, 1, time.Now().Add(time.Hour), "203.0.113.8", unused); err == nil {
		t.Fatal("expected rejection for unstored canonical token")
	}
	assertNoPasswordReplacement(t, s, ctx, "user-1")
}

func TestCheckPeerIPLegacyEmptySession(t *testing.T) {
	session := Session{PeerIP: ""}
	if err := CheckPeerIP(session, "203.0.113.8"); err != nil {
		t.Fatalf("legacy empty PeerIP should accept any current IP: %v", err)
	}
}

func TestCheckPeerIPMatch(t *testing.T) {
	session := Session{PeerIP: "203.0.113.8"}
	if err := CheckPeerIP(session, "203.0.113.8"); err != nil {
		t.Fatalf("matching PeerIP should succeed: %v", err)
	}
}

func TestCheckPeerIPMismatch(t *testing.T) {
	session := Session{PeerIP: "203.0.113.8"}
	if err := CheckPeerIP(session, "198.51.100.9"); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("mismatched PeerIP should return ErrPeerIPMismatch: err=%v", err)
	}
}

func TestCheckPeerIPEmptyCurrentWithNonemptySession(t *testing.T) {
	session := Session{PeerIP: "203.0.113.8"}
	if err := CheckPeerIP(session, ""); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("empty current IP with nonempty session should return ErrPeerIPMismatch: err=%v", err)
	}
}

func TestContextPeerIPRoundTrip(t *testing.T) {
	ctx := ContextWithPeerIP(context.Background(), "10.0.0.1")
	if got := PeerIPFromContext(ctx); got != "10.0.0.1" {
		t.Fatalf("PeerIPFromContext=%q want %q", got, "10.0.0.1")
	}
}

func TestContextPeerIPEmptyDefault(t *testing.T) {
	if got := PeerIPFromContext(context.Background()); got != "" {
		t.Fatalf("PeerIPFromContext on bare context=%q want empty", got)
	}
}

func TestSessionBindingWithMiddlewareContext(t *testing.T) {
	store := testStore(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	issued, err := store.CreateSession(context.Background(), "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate middleware-resolved context carrying the canonical peer IP.
	ctx := ContextWithPeerIP(context.Background(), "203.0.113.8")
	session, err := store.LoadSession(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	peerIP := PeerIPFromContext(ctx)
	if err := CheckPeerIP(session, peerIP); err != nil {
		t.Fatalf("CheckPeerIP should pass: %v", err)
	}
}

func TestSessionBindingMismatchFromContext(t *testing.T) {
	store := testStore(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	issued, err := store.CreateSession(context.Background(), "user-1", "pwd", now.Add(time.Hour), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate middleware-resolved context with a different IP (e.g. spoofed).
	ctx := ContextWithPeerIP(context.Background(), "198.51.100.9")
	session, err := store.LoadSession(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	peerIP := PeerIPFromContext(ctx)
	if err := CheckPeerIP(session, peerIP); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("CheckPeerIP should fail with mismatch: err=%v", err)
	}
}
