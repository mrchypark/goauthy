package rbac

import (
	"bufio"
	"context"
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

type revokeAfterFirstEventWriter struct {
	http.ResponseWriter
	revoke func()
	done   bool
}

func (w *revokeAfterFirstEventWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *revokeAfterFirstEventWriter) FlushError() error {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}
func (w *revokeAfterFirstEventWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if !w.done && strings.Contains(string(p), "data: ") {
		w.done = true
		w.revoke()
	}
	return n, err
}

func TestEventStreamQueryBoundaries(t *testing.T) {
	for _, raw := range []string{"", "?latest=0", "?latest=1&level=warning", "?latest=1000"} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream"+raw, nil)
		if _, _, err := eventStreamQuery(r); err != nil {
			t.Fatalf("raw=%q err=%v", raw, err)
		}
	}
	for _, raw := range []string{"?latest=1001", "?latest=x", "?latest=1&latest=2", "?unknown=1", "?level=bad", "?latest="} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream"+raw, nil)
		if _, _, err := eventStreamQuery(r); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestEventsStreamKeySendsHistoryAndCancels(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	at := time.UnixMilli(1_800_000_000_000).UTC()
	store.now = func() time.Time { return at }
	e := eventlog.Creation("stream-history", "stream@example.test", "192.0.2.8", false, at)
	stmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "stream-history-seed", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "stream-reader", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(handlerDone); h.EventsStream(w, r) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/auth/v1/events/stream?latest=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "API-Key "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), e.ID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("stream did not send event: %v", scanner.Err())
	}
	cancel()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not cancel")
	}
	if got := h.eventStreams.Load(); got != 0 {
		t.Fatalf("event stream count=%d after cancellation", got)
	}
}

func TestEventsStreamRevokedBeforeInitialReadAndCapacity(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "stream-revoke", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	h.beforeEventRead = func() {
		h.beforeEventRead = nil
		if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "stream-revoke-before-read", SQL: `DELETE FROM api_key_access WHERE key_name='stream-revoke'`}); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream", nil)
	r.Header.Set("Authorization", "API-Key "+token)
	w := httptest.NewRecorder()
	h.EventsStream(w, r)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "data:") {
		t.Fatalf("revoked status=%d body=%s", w.Code, w.Body)
	}
	h.eventStreams.Store(64)
	_, capToken, err := keys.Create(context.Background(), nil, apikey.Request{Name: "stream-cap", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/auth/v1/events/stream", nil)
	r.Header.Set("Authorization", "API-Key "+capToken)
	w = httptest.NewRecorder()
	h.EventsStream(w, r)
	if w.Code != http.StatusTooManyRequests || h.eventStreams.Load() != 64 {
		t.Fatalf("capacity status=%d count=%d", w.Code, h.eventStreams.Load())
	}
}

func TestEventsStreamRevokesBetweenBufferedHistoryFrames(t *testing.T) {
	h, store, _, keys, _ := userCreateHTTPFixture(t)
	at := time.UnixMilli(1_800_000_000_000).UTC()
	store.now = func() time.Time { return at }
	var statements []rhiza.SQLStatement
	for _, id := range []string{"stream-buffer-one", "stream-buffer-two"} {
		e := eventlog.Creation(id, "private@example.test", "192.0.2.9", false, at)
		stmt, err := e.Statement("1=1")
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, stmt)
	}
	if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "stream-buffer-seed", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(context.Background(), nil, apikey.Request{Name: "stream-buffer", Access: []apikey.Access{{Group: "Events", AccessRights: []apikey.Right{apikey.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		wrapped := &revokeAfterFirstEventWriter{ResponseWriter: w, revoke: func() {
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{RequestID: "stream-buffer-revoke", SQL: `DELETE FROM api_key_access WHERE key_name='stream-buffer'`}); err != nil {
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
	req.Header.Set("Authorization", "API-Key "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: ") {
			data++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not exit")
	}
	if data != 1 || h.eventStreams.Load() != 0 {
		t.Fatalf("data frames=%d streams=%d", data, h.eventStreams.Load())
	}
}
