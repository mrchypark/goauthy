package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type eventDeadlineWriter struct {
	*httptest.ResponseRecorder
	setDeadlineErr error
	writeErr       error
	flushErrAt     int
	deadlines      []time.Time
	flushes        int
	onData         func()
	dataSeen       bool
}

func (w *eventDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return w.setDeadlineErr
}

func (w *eventDeadlineWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil && strings.Contains(string(p), "data: ") {
		return 0, w.writeErr
	}
	if !w.dataSeen && strings.Contains(string(p), "data: ") {
		w.dataSeen = true
		if w.onData != nil {
			w.onData()
		}
	}
	return w.ResponseRecorder.Write(p)
}

func (w *eventDeadlineWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *eventDeadlineWriter) FlushError() error {
	w.flushes++
	if w.flushErrAt != 0 && w.flushes == w.flushErrAt {
		return errors.New("flush failed")
	}
	return nil
}

func (w *eventDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseRecorder }

func deadlineEventFixture(t *testing.T, count int) (*Handler, string) {
	t.Helper()
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	at := time.UnixMilli(1_800_000_000_000).UTC()
	store.now = func() time.Time { return at }
	var statements []rhiza.SQLStatement
	for i := 0; i < count; i++ {
		e := eventlog.Creation("deadline-event-"+string(rune('a'+i)), "stream@example.test", "192.0.2.10", false, at.Add(time.Duration(i)*time.Second))
		stmt, err := e.Statement("1=1")
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, stmt)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "deadline-event-seed", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "deadline-stream", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	return h, token
}

func TestEventsStreamInitialWriteDeadlineErrorReleasesCapacity(t *testing.T) {
	t.Parallel()
	h, token := deadlineEventFixture(t, 1)
	w := &eventDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), setDeadlineErr: errors.New("deadline unsupported")}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream?latest=1", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	h.EventsStream(w, r)
	if w.Code != http.StatusServiceUnavailable || h.eventStreams.Load() != 0 {
		t.Fatalf("status=%d streams=%d body=%q", w.Code, h.eventStreams.Load(), w.Body.String())
	}
	if len(w.deadlines) != 1 || strings.Contains(w.Body.String(), "data: ") {
		t.Fatalf("deadlines=%d body=%q", len(w.deadlines), w.Body.String())
	}
}

func TestEventsStreamWriteErrorClosesWithoutLaterData(t *testing.T) {
	t.Parallel()
	h, token := deadlineEventFixture(t, 2)
	w := &eventDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), writeErr: errors.New("write failed")}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream?latest=2", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	h.EventsStream(w, r)
	if h.eventStreams.Load() != 0 || strings.Contains(w.Body.String(), "data: ") {
		t.Fatalf("streams=%d body=%q", h.eventStreams.Load(), w.Body.String())
	}
}

func TestEventsStreamFlushErrorStopsAfterFirstData(t *testing.T) {
	t.Parallel()
	h, token := deadlineEventFixture(t, 2)
	w := &eventDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), flushErrAt: 2}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream?latest=2", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	h.EventsStream(w, r)
	if h.eventStreams.Load() != 0 || strings.Count(w.Body.String(), "data: ") != 1 {
		t.Fatalf("streams=%d data=%d body=%q", h.eventStreams.Load(), strings.Count(w.Body.String(), "data: "), w.Body.String())
	}
}

func TestEventsStreamSuccessfulFlushClearsDeadline(t *testing.T) {
	t.Parallel()
	h, token := deadlineEventFixture(t, 1)
	w := &eventDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	rctx, requestCancel := context.WithCancel(context.Background())
	defer requestCancel()
	w.onData = requestCancel
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream?latest=1", nil).WithContext(rctx)
	r.Header.Set("Authorization", "API-Key "+token)
	h.EventsStream(w, r)
	if h.eventStreams.Load() != 0 || len(w.deadlines) != 5 || w.flushes != 2 || strings.Count(w.Body.String(), "data: ") != 1 {
		t.Fatalf("streams=%d deadlines=%d flushes=%d data=%d", h.eventStreams.Load(), len(w.deadlines), w.flushes, strings.Count(w.Body.String(), "data: "))
	}
	for i, deadline := range w.deadlines {
		if i == 2 || i == 4 {
			if !deadline.IsZero() {
				t.Fatalf("deadline[%d]=%v, want cleared", i, deadline)
			}
		} else if deadline.IsZero() {
			t.Fatalf("deadline[%d] unexpectedly cleared", i)
		}
	}
}
