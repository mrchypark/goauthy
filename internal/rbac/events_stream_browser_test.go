package rbac

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEventsStreamBrowserRevocationBetweenHistoryFrames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate string
	}{
		{"role", `DELETE FROM rbac_user_roles WHERE subject='admin'`},
		{"session", `UPDATE browser_sessions SET revoked_at_unix_ms=1700000000000 WHERE subject='admin'`},
		{"expiry", `UPDATE identity_users SET user_expires_at_unix_ms=1700000000000 WHERE subject='admin'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _, _, cookie := userCreateHTTPFixture(t)
			at := time.UnixMilli(1_700_000_000_000).UTC()
			store.now = func() time.Time { return at }
			var statements []rhiza.SQLStatement
			ids := []string{"browser-stream-one", "browser-stream-two"}
			expectedFirst := ""
			for _, id := range ids {
				e := eventlog.Creation(id, "browser-private@example.test", "192.0.2.10", false, at)
				if expectedFirst == "" {
					expectedFirst = e.ID
				}
				stmt, err := e.Statement("1=1")
				if err != nil {
					t.Fatal(err)
				}
				statements = append(statements, stmt)
			}
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "browser-stream-seed-" + tc.name, Statements: statements}); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				wrapped := &revokeAfterFirstEventWriter{ResponseWriter: w, revoke: func() {
					if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "browser-stream-revoke-" + tc.name, SQL: tc.mutate}); err != nil {
						t.Error(err)
					}
				}}
				h.EventsStream(wrapped, r)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/auth/v1/events/stream?latest=2", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d", resp.StatusCode)
			}
			frames := 0
			var first string
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "data: ") {
					frames++
					if first == "" {
						first = scanner.Text()
					}
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("handler did not exit")
			}
			if frames != 1 || !strings.Contains(first, expectedFirst) || h.eventStreams.Load() != 0 {
				t.Fatalf("frames=%d first=%q streams=%d", frames, first, h.eventStreams.Load())
			}
		})
	}
}
