package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEventsTestUsesServerClockAndResolvedPeer(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	at := time.UnixMilli(1_800_000_000_123)
	store.now = func() time.Time { return at }
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "fixed-test-event", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Create}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, resolved := range []string{"", "2001:db8::9"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
		r.RemoteAddr = "198.51.100.7:4000"
		r.Header.Set("Authorization", "API-Key "+token)
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		r = r.WithContext(browser.ContextWithPeerIP(r.Context(), resolved))
		w := httptest.NewRecorder()
		h.EventsTest(w, r)
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
	}
	rows, err := store.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT e.id,e.timestamp,e.level,e.typ,e.ip,e.data,e.text FROM event_log e JOIN event_log_order o ON o.event_id=e.id ORDER BY o.sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows.Rows, err)
	}
	if rows.Rows[0][0] == rows.Rows[1][0] {
		t.Fatal("independent same-clock POSTs reused an event ID")
	}
	for i, ip := range []string{"198.51.100.7", "2001:db8::9"} {
		row := rows.Rows[i]
		if row[1] != at.UnixMilli() || row[2] != int64(0) || row[3] != "Test" || row[4] != ip || row[5] != nil || row[6] != "This is a Test-Event" {
			t.Fatalf("server-assigned payload=%v", row)
		}
	}
}

func TestEventsTestFailureDoesNotAppendEventOrSequence(t *testing.T) {
	for _, failure := range []string{"entropy", "short entropy", "database", "invalid peer"} {
		t.Run(failure, func(t *testing.T) {
			h, store, _, keys, _ := userCreateHTTPFixture(t)
			_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "test-event-failure", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Create}}}})
			if err != nil {
				t.Fatal(err)
			}
			want := http.StatusServiceUnavailable
			r := httptest.NewRequest(http.MethodPost, "/auth/v1/events/test", nil)
			switch failure {
			case "entropy":
				store.random = func([]byte) (int, error) { return 0, errors.New("fixture entropy failure") }
			case "short entropy":
				store.random = func(p []byte) (int, error) { return len(p) - 1, nil }
			case "database":
				_, err = storage.Execute(r.Context(), store.db, rhiza.ExecuteRequest{RequestID: "test-event-failure-trigger", SQL: `CREATE TRIGGER reject_test_event BEFORE INSERT ON event_log BEGIN SELECT RAISE(ABORT,'test fixture'); END`})
				if err != nil {
					t.Fatal(err)
				}
			case "invalid peer":
				r.RemoteAddr = "not-an-IP"
				want = http.StatusBadRequest
			}
			r.Header.Set("Authorization", "API-Key "+token)
			w := httptest.NewRecorder()
			h.EventsTest(w, r)
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
			}
			rows, err := store.db.Query(r.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM event_log),(SELECT COUNT(*) FROM event_log_order),COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) {
				t.Fatalf("failed mutation left records=%v err=%v", rows.Rows, err)
			}
		})
	}
}
