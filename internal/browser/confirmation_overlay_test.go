//go:build confirmationproof

package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// Only scripts/test-confirmation-proof.sh rewrites call sites to these functions.
// They capture the actual request, not a copied SQL implementation.
type confirmationKey struct{}
type confirmationProbe struct {
	request           rhiza.ExecuteRequest
	response          rhiza.ExecuteResponse
	pairRequest       rhiza.ExecuteRequest
	pairResponse      rhiza.ExecuteResponse
	queries, executes int
	before            func(rhiza.ExecuteRequest)
	after             func(rhiza.ExecuteResponse, error) (rhiza.ExecuteResponse, error)
	touch             func(rhiza.ExecuteRequest)
	pairBefore        func(rhiza.ExecuteRequest)
	pairAfter         func(rhiza.ExecuteResponse, error) (rhiza.ExecuteResponse, error)
}

// isConfirmationCreator identifies the separate two-statement interaction
// creator: expiry sweep plus one guarded insert of ten args.
func isConfirmationCreator(request rhiza.ExecuteRequest) bool {
	return len(request.Statements) == 2 && len(request.Statements[1].Args) == 10
}

// isConfirmationPair identifies the combined init-session and interaction batch
// by its own shape. That batch is five statements: two session expiry sweeps, the
// guarded session insert, the interaction expiry sweep, and the guarded
// interaction insert. Both inserts carry ExpectedRowsAffected, and the third
// statement is the session insert. This is deliberately a separate predicate from
// the creator's, so a five-statement batch can never be mistaken for it and the
// creator tests keep their own two-statement identification.
func isConfirmationPair(request rhiza.ExecuteRequest) bool {
	if len(request.Statements) != 5 || len(request.Statements[4].Args) != 10 {
		return false
	}
	for _, index := range []int{2, 4} {
		statement := request.Statements[index]
		if statement.ExpectedRowsAffected == nil || *statement.ExpectedRowsAffected != 1 {
			return false
		}
	}
	return request.Statements[3].ExpectedRowsAffected == nil
}

func confirmationExecute(ctx context.Context, db *rhiza.DB, request rhiza.ExecuteRequest) (rhiza.ExecuteResponse, error) {
	p, _ := ctx.Value(confirmationKey{}).(*confirmationProbe)
	creator, pair := isConfirmationCreator(request), isConfirmationPair(request)
	if p != nil {
		p.executes++
		switch {
		case pair:
			p.pairRequest = request
			if p.pairBefore != nil {
				p.pairBefore(request)
			}
		case creator:
			p.request = request
			if p.before != nil {
				p.before(request)
			}
		default:
			if p.touch != nil {
				p.touch(request)
			}
		}
	}
	response, err := storage.Execute(ctx, db, request)
	if p != nil {
		switch {
		case pair:
			p.pairResponse = response
			if p.pairAfter != nil {
				return p.pairAfter(response, err)
			}
		case creator:
			p.response = response
			if p.after != nil {
				return p.after(response, err)
			}
		}
	}
	return response, err
}
func confirmationQuery(ctx context.Context, db *rhiza.DB, request rhiza.QueryRequest) (rhiza.QueryResponse, error) {
	if p, ok := ctx.Value(confirmationKey{}).(*confirmationProbe); ok {
		p.queries++
	}
	return db.Query(ctx, request)
}
func confirmationFixture(t *testing.T) (*Store, IssuedSession, time.Time) {
	t.Helper()
	s := testStore(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }
	session, err := s.CreateInitSession(t.Context(), now.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	return s, session, now
}
func TestConfirmationActualRequestReplay(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprint(rejected), func(t *testing.T) {
			s, session, now := confirmationFixture(t)
			p := &confirmationProbe{}
			if rejected {
				p.before = func(rhiza.ExecuteRequest) {
					if _, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "revoke", SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=1 WHERE token_digest=?", Args: []any{session.ID}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			issued, err := s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, "replay", []byte("payload"), now.Add(time.Minute))
			if (err != nil) != rejected || rejected && !errors.Is(err, ErrNotFound) {
				t.Fatalf("create=%+v %v", issued, err)
			}
			if p.request.RequestID == "" || p.request.Statements[0].ExpectedRowsAffected != nil || p.request.Statements[1].ExpectedRowsAffected == nil || *p.request.Statements[1].ExpectedRowsAffected != 1 {
				t.Fatal("wrong actual statement precondition")
			}
			// Change present state: replay must prove retained history, not reauthorize.
			if rejected {
				_, err = storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "restore", SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=NULL WHERE token_digest=?", Args: []any{session.ID}})
			} else {
				_, err = storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "remove", SQL: "DELETE FROM browser_authorization_interactions"})
			}
			if err != nil {
				t.Fatal(err)
			}
			replay, err := storage.Execute(t.Context(), s.db, p.request)
			if replay.Slot != p.response.Slot || replay.Status != p.response.Status || replay.ErrorCode != p.response.ErrorCode || (err != nil) != rejected {
				t.Fatalf("replay=%+v %v original=%+v", replay, err, p.response)
			}
			if confirmationCount(t, s) != 0 {
				t.Fatal("historical replay recreated interaction")
			}
			changed := p.request
			changed.Statements = append([]rhiza.SQLStatement(nil), p.request.Statements...)
			changed.Statements[1].Args = append([]any(nil), p.request.Statements[1].Args...)
			changed.Statements[1].Args[1] = "changed-logical-id"
			if _, err := storage.Execute(t.Context(), s.db, changed); !errors.Is(err, rhiza.ErrRequestConflict) {
				t.Fatalf("conflict=%v", err)
			}
		})
	}
}
func TestConfirmationPopulatedReceiptErrors(t *testing.T) {
	for _, status := range []rhiza.MutationStatus{rhiza.MutationCommitted, rhiza.MutationRejected} {
		for _, failure := range []error{rhiza.ErrCommitUnknown, rhiza.ErrRequestConflict, context.Canceled, context.DeadlineExceeded, rhiza.ErrQuorumUnavailable} {
			// Ordinary non-precondition errors do not carry a rejected/precondition receipt
			// in the actual helper; exercise that conflicting shape only for the vetoes.
			if status == rhiza.MutationRejected && !errors.Is(failure, rhiza.ErrCommitUnknown) && !errors.Is(failure, rhiza.ErrRequestConflict) {
				continue
			}
			t.Run(fmt.Sprintf("%s/%v", status, failure), func(t *testing.T) {
				s, session, now := confirmationFixture(t)
				p := &confirmationProbe{after: func(r rhiza.ExecuteResponse, err error) (rhiza.ExecuteResponse, error) {
					if err != nil {
						t.Fatal(err)
					}
					r.Status = status
					r.ErrorCode = rhiza.MutationErrorCodePreconditionFailed
					return r, failure
				}}
				issued, err := s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, "mapping", []byte("payload"), now.Add(time.Minute))
				if !errors.Is(err, failure) || errors.Is(err, ErrNotFound) || issued.Token != "" {
					t.Fatalf("populated receipt became success/absence: %+v %v", issued, err)
				}
			})
		}
	}
}
func TestConfirmationOverlappingRemoval(t *testing.T) {
	for _, kind := range []string{"delete", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			s, session, now := confirmationFixture(t)
			p := &confirmationProbe{after: func(r rhiza.ExecuteResponse, err error) (rhiza.ExecuteResponse, error) {
				if err != nil {
					t.Fatal(err)
				}
				sql := "DELETE FROM browser_authorization_interactions"
				if kind == "revoke" {
					sql = "UPDATE browser_sessions SET revoked_at_unix_ms=1"
				}
				if _, err := storage.Execute(t.Context(), s.db, rhiza.ExecuteRequest{RequestID: "overlap", SQL: sql}); err != nil {
					t.Fatal(err)
				}
				return r, nil
			}}
			issued, err := s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, "overlap", []byte("payload"), now.Add(time.Minute))
			if err != nil || issued.Token == "" {
				t.Fatalf("insertion-time success=%+v %v", issued, err)
			}
			if _, err := s.LoadAuthorizationInteractionReadOnly(t.Context(), session.Token, issued.Token); err == nil {
				t.Fatal("load accepted removed authority")
			}
			if _, err := s.ConsumeAuthorizationInteraction(t.Context(), session.Token, issued.Token); err == nil {
				t.Fatal("consume accepted removed authority")
			}
		})
	}
}
func TestConfirmationActualRequestDurabilityAndRestart(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprint(rejected), func(t *testing.T) {
			objects := t.TempDir()
			config := rhiza.Config{NodeID: "creator-durability", DataDir: t.TempDir(), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objects, ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck}
			db, err := rhiza.Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					_ = db.Close()
				}
			})
			if err := storage.Migrate(t.Context(), db); err != nil {
				t.Fatal(err)
			}
			s, err := NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			s.now = func() time.Time { return now }
			session, err := s.CreateInitSession(t.Context(), now.Add(time.Hour), "")
			if err != nil {
				t.Fatal(err)
			}
			backup := objects + "-backup"
			p := &confirmationProbe{before: func(rhiza.ExecuteRequest) {
				if rejected {
					if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "revoke", SQL: "UPDATE browser_sessions SET revoked_at_unix_ms=1"}); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Rename(objects, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(objects, []byte("unavailable"), 0600); err != nil {
					t.Fatal(err)
				}
			}}
			t.Cleanup(func() { _ = os.Remove(objects); _ = os.Rename(backup, objects) })
			issued, err := s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, "durability", []byte("payload"), now.Add(time.Minute))
			expected := rhiza.MutationCommitted
			if rejected {
				expected = rhiza.MutationRejected
			}
			if !errors.Is(err, rhiza.ErrCommitUnknown) || errors.Is(err, ErrNotFound) || issued.Token != "" || p.response.Status != expected {
				t.Fatalf("unconfirmed creator=%+v response=%+v err=%v", issued, p.response, err)
			}
			if _, err := storage.Execute(t.Context(), db, p.request); !errors.Is(err, rhiza.ErrCommitUnknown) {
				t.Fatalf("unresolved replay=%v", err)
			}
			if err := os.Remove(objects); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, objects); err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				got, err := storage.Execute(t.Context(), db, p.request)
				if got.Slot != p.response.Slot || got.Status != expected || got.ErrorCode != p.response.ErrorCode || (err != nil) != rejected || errors.Is(err, rhiza.ErrCommitUnknown) {
					t.Fatalf("confirmed replay=%+v err=%v", got, err)
				}
				want := int64(1)
				if rejected {
					want = 0
				}
				if confirmationCount(t, s) != want {
					t.Fatal("duplicate domain effects")
				}
			}
			check()
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = rhiza.Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			s.db = db
			check()
			changed := p.request
			changed.Statements = append([]rhiza.SQLStatement(nil), p.request.Statements...)
			changed.Statements[1].Args = append([]any(nil), p.request.Statements[1].Args...)
			changed.Statements[1].Args[1] = "different"
			if _, err := storage.Execute(t.Context(), db, changed); !errors.Is(err, rhiza.ErrRequestConflict) {
				t.Fatalf("restart conflict=%v", err)
			}
		})
	}
}

// Moving only the wall clock after cutoff capture must not invent apply-time
// expiry semantics. The next authority read uses the new clock and rejects.
func TestConfirmationCapturedCutoff(t *testing.T) {
	s, session, now := confirmationFixture(t)
	p := &confirmationProbe{before: func(r rhiza.ExecuteRequest) {
		if r.Statements[1].Args[7] != now.UnixMilli() {
			t.Fatal("unexpected creator cutoff")
		}
		s.now = func() time.Time { return now.Add(2 * time.Hour) }
	}}
	issued, err := s.CreateAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), session.Token, "cutoff", []byte("payload"), now.Add(time.Minute))
	if err != nil || issued.Token == "" {
		t.Fatalf("fixed-cutoff creation=%+v %v", issued, err)
	}
	if _, err := s.LoadAuthorizationInteractionReadOnly(t.Context(), session.Token, issued.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("later expired authority=%v", err)
	}
}

// The combined pair batch must treat a populated receipt the same way the
// separate creator does: a veto carrying CommitUnknown or RequestConflict is not
// absence and must not yield usable state. The pair is identified by its own
// five-statement shape, not by the creator's two-statement heuristic.
func TestConfirmationPairPopulatedReceiptErrors(t *testing.T) {
	for _, status := range []rhiza.MutationStatus{rhiza.MutationCommitted, rhiza.MutationRejected} {
		for _, failure := range []error{rhiza.ErrCommitUnknown, rhiza.ErrRequestConflict, context.Canceled, context.DeadlineExceeded, rhiza.ErrQuorumUnavailable} {
			if status == rhiza.MutationRejected && !errors.Is(failure, rhiza.ErrCommitUnknown) && !errors.Is(failure, rhiza.ErrRequestConflict) {
				continue
			}
			t.Run(fmt.Sprintf("%s/%v", status, failure), func(t *testing.T) {
				s := testStore(t)
				now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
				s.now = func() time.Time { return now }
				p := &confirmationProbe{pairAfter: func(r rhiza.ExecuteResponse, err error) (rhiza.ExecuteResponse, error) {
					if err != nil {
						t.Fatal(err)
					}
					r.Status = status
					r.ErrorCode = rhiza.MutationErrorCodePreconditionFailed
					return r, failure
				}}
				session, interaction, err := s.CreateInitSessionWithAuthorizationInteraction(context.WithValue(t.Context(), confirmationKey{}, p), "203.0.113.9", "pair-veto", []byte("payload"), now.Add(time.Minute))
				if !errors.Is(err, failure) || errors.Is(err, ErrNotFound) {
					t.Fatalf("populated pair receipt became success/absence: %+v %v", session, err)
				}
				if session.Token != "" || session.ID != "" || interaction.Token != "" {
					t.Fatalf("vetoed pair returned usable state: session=%+v interaction=%+v", session, interaction)
				}
				if !isConfirmationPair(p.pairRequest) || len(p.pairRequest.Statements) != 5 {
					t.Fatalf("pair request not identified exactly: %+v", p.pairRequest.Statements)
				}
				if p.request.RequestID != "" {
					t.Fatal("pair must not be captured as the two-statement creator")
				}
			})
		}
	}
}
