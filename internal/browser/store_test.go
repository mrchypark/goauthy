package browser

import (
	"context"
	"errors"
	"net/http"
	"sync"
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
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "browser-test-schema", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
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
