package oauth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// ResponseRecorder has no network deadline; model the supported server method.
type passwordDeadlineRecorder struct{ *httptest.ResponseRecorder }

func (w *passwordDeadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestPasswordFailureExtendsWriteDeadlineBeforeWait(t *testing.T) {
	for _, failDeadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "deadline error"}[failDeadline], func(t *testing.T) {
			db := oauthTestDB(t)
			s := oauthTestServer(t, db, randomSecret(t))
			users, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := credential.Hash([]byte("correct password"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := users.BootstrapUser(t.Context(), "deadline-user", "alice", hash); err != nil {
				t.Fatal(err)
			}
			policy := loginpolicy.NewStore(db)
			if _, err := policy.Failure(t.Context(), "192.0.2.44", time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "expired-ip-block", SQL: "UPDATE login_ip_failures SET failures=10,blocked_until_unix_ms=0"}); err != nil {
				t.Fatal(err)
			}
			h := newPasswordGrantHandler(s.store, users, s.accessTokens.(oauth2.CoreStrategy), &fosite.Config{})
			ctx, cancel := context.WithCancel(browser.ContextWithPeerIP(t.Context(), "192.0.2.44"))
			defer cancel()
			ctx = context.WithValue(ctx, passwordAuthenticationKey{}, &identity.Authentication{})
			var deadline time.Time
			ctx = context.WithValue(ctx, passwordWriteDeadlineKey{}, func(d time.Time) error {
				deadline = d
				if failDeadline {
					return errors.New("cannot extend network deadline")
				}
				cancel() // proves the deadline is set before waiting, without sleeping 110s.
				return nil
			})
			before := time.Now()
			_, err = h.Authenticate(ctx, "alice", "wrong password")
			if deadline.Before(before.Add(115 * time.Second)) {
				t.Fatalf("deadline %v must cover 110s penalty and 5s write grace", deadline)
			}
			if failDeadline {
				if !errors.Is(err, fosite.ErrServerError) {
					t.Fatalf("want server error, got %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("want cancellation, got %v", err)
			}
			status, err := policy.Check(t.Context(), "192.0.2.44", time.Now())
			if err != nil || status.Failures != 11 {
				t.Fatalf("failure accounting lost: %+v %v", status, err)
			}
		})
	}
}
