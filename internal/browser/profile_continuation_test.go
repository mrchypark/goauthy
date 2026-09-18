package browser

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoadAuthorizationInteractionReadOnlyForSessionAuthenticatedSuccess(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "cont-request", []byte(`{"flow":"remediation"}`), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token)
	if err != nil {
		t.Fatalf("authenticated continuation read err=%v", err)
	}
	if got.RequestID != "cont-request" || string(got.Payload) != `{"flow":"remediation"}` {
		t.Fatalf("got=%#v", got)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); err != nil {
		t.Fatalf("second read should not consume: %v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionRejectsInitSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	init, err := store.CreateInitSession(ctx, now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, init.Token, "init-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, init.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("init session should be rejected: err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionRejectsWrongSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateSession(ctx, "user-2", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "bound-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, other.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong session should be rejected: err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionRejectsConsumed(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "consume-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token); err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); !errors.Is(err, ErrConsumed) {
		t.Fatalf("consumed interaction should be rejected: err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionRejectsExpired(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "expire-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Minute)
	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired interaction should be rejected: err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionRejectsRevokedSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "revoke-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeSession(ctx, session.Token); err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked session should be rejected: err=%v", err)
	}
}

func TestLoadAuthorizationInteractionReadOnlyForSessionDoesNotExtendIdle(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "idle-request", []byte("state"), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(touchInterval + time.Second)
	if _, err := store.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); err != nil {
		t.Fatal(err)
	}

	if got := sessionLastSeen(t, store, session.Token); !got.Equal(session.CreatedAt) {
		t.Fatalf("continuation read touched session: got %s want %s", got, session.CreatedAt)
	}
}

func TestLoadAuthorizationInteractionReadOnlyStillDeniesAuthenticatedSession(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	session, err := store.CreateSession(ctx, "user-1", "pwd", now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := store.CreateAuthorizationInteraction(ctx, session.Token, "init-auth-request", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.LoadAuthorizationInteractionReadOnly(ctx, session.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("original init method should deny authenticated session: err=%v", err)
	}
}
