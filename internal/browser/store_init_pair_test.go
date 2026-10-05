package browser

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func countRows(t *testing.T, s *Store, sql string, args ...any) int {
	t.Helper()
	result, err := s.db.Query(context.Background(), rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("unexpected count result shape: %v", result.Rows)
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("unexpected count type %T", result.Rows[0][0])
	}
	return int(count)
}

// A combined pair must be as usable as the separate session-then-interaction
// sequence: the session keeps its peer binding, and the interaction stays bound
// to that session, single-use, and scoped to an init (unauthenticated) session.
func TestCreateInitSessionWithAuthorizationInteractionBindsPair(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	payload := []byte("/authorize?client_id=browser&state=xyz")

	session, interaction, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", "pair-request-1", payload, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if session.Token == "" || session.Session.ID == "" || interaction.Token == "" {
		t.Fatalf("pair issued incomplete state: %+v %+v", session, interaction)
	}
	if session.Subject != "" || session.AuthenticationMethod != "" || session.Authenticated() {
		t.Fatalf("pair must create an unauthenticated init session: %+v", session.Session)
	}
	if session.PeerIP != "203.0.113.9" {
		t.Fatalf("session PeerIP=%q want %q", session.PeerIP, "203.0.113.9")
	}
	if !session.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("session ExpiresAt=%v want %v", session.ExpiresAt, now.Add(10*time.Minute))
	}
	loaded, err := s.LoadSessionReadOnlyForPeer(ctx, session.Token, "203.0.113.9")
	if err != nil {
		t.Fatalf("pair session must load for its bound peer: %v", err)
	}
	if loaded.ID != session.ID {
		t.Fatalf("loaded session ID=%q want %q", loaded.ID, session.ID)
	}
	if _, err := s.LoadSessionReadOnlyForPeer(ctx, session.Token, "198.51.100.4"); !errors.Is(err, ErrPeerIPMismatch) {
		t.Fatalf("peer mismatch must be rejected, got %v", err)
	}

	readOnly, err := s.LoadAuthorizationInteractionReadOnly(ctx, session.Token, interaction.Token)
	if err != nil {
		t.Fatalf("pair interaction must load bound to its session: %v", err)
	}
	if readOnly.RequestID != "pair-request-1" || string(readOnly.Payload) != string(payload) {
		t.Fatalf("interaction round-trip mismatch: %+v", readOnly)
	}
	if !readOnly.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("interaction ExpiresAt=%v want %v", readOnly.ExpiresAt, now.Add(10*time.Minute))
	}
	// The pair must not widen the init/authenticated boundary.
	if _, err := s.LoadAuthorizationInteractionReadOnlyForSession(ctx, session.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("init session must not satisfy the authenticated interaction load, got %v", err)
	}
	// Not bound to any other session.
	other, err := s.CreateInitSession(ctx, now.Add(time.Hour), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadAuthorizationInteractionReadOnly(ctx, other.Token, interaction.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session interaction load must fail, got %v", err)
	}

	consumed, err := s.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token)
	if err != nil {
		t.Fatalf("pair interaction must be consumable once: %v", err)
	}
	if consumed.RequestID != "pair-request-1" {
		t.Fatalf("consumed RequestID=%q want %q", consumed.RequestID, "pair-request-1")
	}
	if _, err := s.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume must fail closed, got %v", err)
	}
}

// Validation and expiry fences must reject the pair before anything is written.
func TestCreateInitSessionWithAuthorizationInteractionRejectsInvalidInput(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	cases := []struct {
		name      string
		requestID string
		payload   []byte
		expiresAt time.Time
	}{
		{name: "empty request id", requestID: "", payload: []byte("state"), expiresAt: now.Add(time.Minute)},
		{name: "blank request id", requestID: "   ", payload: []byte("state"), expiresAt: now.Add(time.Minute)},
		{name: "oversized request id", requestID: strings.Repeat("r", maxRequestIDLength+1), payload: []byte("state"), expiresAt: now.Add(time.Minute)},
		{name: "empty payload", requestID: "request-invalid-1", payload: nil, expiresAt: now.Add(time.Minute)},
		{name: "oversized payload", requestID: "request-invalid-2", payload: make([]byte, maxPayloadLength+1), expiresAt: now.Add(time.Minute)},
		{name: "expiry in the past", requestID: "request-invalid-3", payload: []byte("state"), expiresAt: now},
		{name: "expiry in the past sub-second", requestID: "request-invalid-4", payload: []byte("state"), expiresAt: now.Add(-time.Millisecond)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", tc.requestID, tc.payload, tc.expiresAt); err == nil {
				t.Fatal("expected rejection")
			}
			if sessions := countRows(t, s, `SELECT COUNT(*) FROM browser_sessions`); sessions != 0 {
				t.Fatalf("rejected pair must not create a session, got %d", sessions)
			}
			if interactions := countRows(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions`); interactions != 0 {
				t.Fatalf("rejected pair must not create an interaction, got %d", interactions)
			}
		})
	}
}

// A duplicate request_id fails the batch through the UNIQUE constraint on
// browser_authorization_interactions, not through a guarded-insert
// precondition. It must therefore not be reported as ErrNotFound, it must
// return no tokens, and the whole batch must roll back: the freshly inserted
// session disappears and both expiry sweeps (sessions and interactions) are
// undone, leaving the seeded rows exactly as they were.
func TestCreateInitSessionWithAuthorizationInteractionDuplicateRequestRollsBackBatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	base := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }

	// Genuine upstream session plus its binding, so the pair's own expiry sweep
	// has real rows to delete and its rollback can be observed.
	upstream, err := s.CreateUpstreamSession(ctx, "user-1", UpstreamSessionBinding{
		Issuer: "https://idp.example", ClientID: "client-1", Subject: "upstream-subject-1",
	}, "external", base.Add(time.Minute), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if upstream.Subject != "user-1" {
		t.Fatalf("unexpected upstream session subject %q", upstream.Subject)
	}
	// A separate init session owning two interactions. Advancing the clock
	// expires the two sessions and the binding. The long-lived interaction stays
	// live, so it keeps its UNIQUE request_id and causes the failure; the
	// short-lived one is genuinely expired, so the batch's interaction expiry
	// sweep has a real row to delete and that deletion's rollback is observable.
	init, err := s.CreateInitSession(ctx, base.Add(time.Minute), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := s.CreateAuthorizationInteraction(ctx, init.Token, "seeded-request", []byte("seeded-payload"), base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAuthorizationInteraction(ctx, init.Token, "expired-seeded-request", []byte("expired-payload"), base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	later := base.Add(2 * time.Minute)
	s.now = func() time.Time { return later }
	counts := func() (sessions, bindings, interactions, live int) {
		t.Helper()
		return countRows(t, s, `SELECT COUNT(*) FROM browser_sessions`),
			countRows(t, s, `SELECT COUNT(*) FROM browser_upstream_session_bindings`),
			countRows(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions`),
			countRows(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE consumed_attempt IS NULL`)
	}
	expiredInteractions := func() int {
		t.Helper()
		return countRows(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions WHERE expires_at_unix_ms <= ?`, later.UnixMilli())
	}
	beforeSessions, beforeBindings, beforeInteractions, beforeLive := counts()
	if beforeSessions != 2 || beforeBindings != 1 || beforeInteractions != 2 || beforeLive != 2 {
		t.Fatalf("seed rows=%d/%d/%d/%d want 2/1/2/2", beforeSessions, beforeBindings, beforeInteractions, beforeLive)
	}
	if expired := expiredInteractions(); expired != 1 {
		t.Fatalf("expired seeded interactions=%d want 1", expired)
	}

	session, interaction, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", "seeded-request", []byte("state"), later.Add(time.Minute))
	if err == nil {
		t.Fatal("expected rejection for duplicate request ID")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("UNIQUE constraint failure must not be reported as absence: %v", err)
	}
	if session.Token != "" || session.ID != "" || interaction.Token != "" || session.Subject != "" {
		t.Fatalf("failed pair returned state: session=%+v interaction=%+v", session, interaction)
	}

	afterSessions, afterBindings, afterInteractions, afterLive := counts()
	if afterSessions != beforeSessions || afterBindings != beforeBindings || afterInteractions != beforeInteractions || afterLive != beforeLive {
		t.Fatalf("rollback disturbed seeded rows: sessions %d->%d bindings %d->%d interactions %d->%d live %d->%d",
			beforeSessions, afterSessions, beforeBindings, afterBindings, beforeInteractions, afterInteractions, beforeLive, afterLive)
	}
	// The expired interaction must survive: the batch's interaction expiry sweep
	// deleted it inside the failed transaction, so its rollback is what puts it
	// back. If the sweep were not rolled back this row would be gone.
	if expired := expiredInteractions(); expired != 1 {
		t.Fatalf("expired interaction rows after rollback=%d want 1", expired)
	}
	// The seeded interaction must be untouched: still unconsumed and still
	// carrying its own request_id and payload.
	readBack, err := s.LoadAuthorizationInteractionReadOnly(ctx, init.Token, seeded.Token)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("seeded interaction must still be readable only under its own guards, got %v", err)
	}
	if readBack.Payload != nil {
		t.Fatalf("rejected read must not return payload: %q", readBack.Payload)
	}

	// Negative control for the assertion above: a pair that does commit must
	// actually sweep that same expired row. Without this, survival of the row
	// after the failure would not prove the sweep ever targeted it.
	controlSession, controlInteraction, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", "control-request", []byte("control-payload"), later.Add(time.Minute))
	if err != nil {
		t.Fatalf("control pair must commit: %v", err)
	}
	if controlSession.Token == "" || controlInteraction.Token == "" {
		t.Fatal("control pair returned no state")
	}
	if expired := expiredInteractions(); expired != 0 {
		t.Fatalf("committed pair must sweep the expired interaction, got %d rows", expired)
	}
}

// The guarded interaction insert's ExpectedRowsAffected=1 is live, and its
// rejection natively rolls back the co-batched session insert. The fixture is
// deliberately built from the public API only: an expiry strictly after the
// in-memory now, but inside the same millisecond, so it passes the
// expiresAt.After(now) validation while the stored millisecond-precision expiry
// is not greater than the guard's cutoff. No production guard is relaxed.
func TestCreateInitSessionWithAuthorizationInteractionGuardedExpiryRollsBackSession(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	expiresAt := now.Add(500 * time.Microsecond)
	if !expiresAt.After(now) {
		t.Fatal("fixture must pass in-memory future validation")
	}
	if expiresAt.UnixMilli() != now.UnixMilli() {
		t.Fatalf("fixture must store an expiry equal to the guard cutoff: %d vs %d", expiresAt.UnixMilli(), now.UnixMilli())
	}

	session, interaction, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", "pair-submillisecond", []byte("state"), expiresAt)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed guarded insert must be absence, got %v", err)
	}
	if session.Token != "" || session.ID != "" || session.ExpiresAt != (time.Time{}) || interaction.Token != "" || interaction.RequestID != "" {
		t.Fatalf("rejected pair returned state: session=%+v interaction=%+v", session, interaction)
	}
	if rows := countRows(t, s, `SELECT COUNT(*) FROM browser_sessions`); rows != 0 {
		t.Fatalf("guarded rejection must natively roll back the session insert, got %d rows", rows)
	}
	if rows := countRows(t, s, `SELECT COUNT(*) FROM browser_authorization_interactions`); rows != 0 {
		t.Fatalf("guarded rejection must leave no interaction, got %d rows", rows)
	}

	// The same fixture with an expiry a whole millisecond beyond the cutoff must
	// succeed, showing the guard rejects on the stored cutoff and not on the input.
	next := now.Add(time.Millisecond)
	s.now = func() time.Time { return next }
	future := next.Add(time.Millisecond + 500*time.Microsecond)
	if future.UnixMilli() <= next.UnixMilli() {
		t.Fatalf("success fixture must store an expiry beyond the cutoff: %d vs %d", future.UnixMilli(), next.UnixMilli())
	}
	session, interaction, err = s.CreateInitSessionWithAuthorizationInteraction(ctx, "203.0.113.9", "pair-submillisecond", []byte("state"), future)
	if err != nil {
		t.Fatalf("stored expiry beyond the cutoff must succeed: %v", err)
	}
	if _, err := s.LoadSessionReadOnlyForPeer(ctx, session.Token, "203.0.113.9"); err != nil {
		t.Fatalf("pair session must load: %v", err)
	}
	if _, err := s.LoadAuthorizationInteractionReadOnly(ctx, session.Token, interaction.Token); err != nil {
		t.Fatalf("pair interaction must load: %v", err)
	}
}

// A pair's session must expire and idle out under the same guards as any other
// session, and its interaction must stop being usable with that session.
func TestCreateInitSessionWithAuthorizationInteractionSessionGuardsApply(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	session, interaction, err := s.CreateInitSessionWithAuthorizationInteraction(ctx, "", "pair-guards", []byte("state"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expired := now.Add(time.Minute + time.Millisecond)
	s.now = func() time.Time { return expired }
	if _, err := s.LoadSessionReadOnly(ctx, session.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired pair session must not load, got %v", err)
	}
	if _, err := s.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token); err == nil {
		t.Fatal("expired pair session must not consume its interaction")
	}
	if rows := countRows(t, s, `SELECT COUNT(*) FROM browser_sessions`); rows != 1 {
		t.Fatalf("expiry sweep should not have removed the session yet, got %d", rows)
	}
}
