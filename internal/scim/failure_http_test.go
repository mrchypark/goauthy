package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type realHTTPRequests struct {
	mu      sync.Mutex
	methods []string
}

func (r *realHTTPRequests) add(method string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods = append(r.methods, method)
}

func (r *realHTTPRequests) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.methods...)
}

func TestScimRealHTTPGroupFailureTerminalEvent(t *testing.T) {
	t.Parallel()
	var requests realHTTPRequests
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/scim+json")
			_ = json.NewEncoder(w).Encode(struct {
				Schemas      []string `json:"schemas"`
				TotalResults int      `json:"totalResults"`
				Resources    []Group  `json:"Resources"`
			}{[]string{listResponseSchema}, 1, []Group{{Schemas: []string{groupSchema}, ID: "remote", ExternalID: "group-1", DisplayName: "Old name"}}})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return client, nil }, OutboxConfig{MaxAttempts: 5, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{21}, 256))})
	now := time.UnixMilli(1_800_000_100_000).UTC()
	if _, err := o.EnqueueGroup(context.Background(), "client-1", Group{ExternalID: "group-1", DisplayName: "Engineering"}, now); err != nil {
		t.Fatal(err)
	}
	job, terminalAt := runRealHTTPFailureAttempts(t, o, now, "group-1")
	if job.Status != "dead" || job.Attempts != 5 {
		t.Fatalf("terminal group job=%+v", job)
	}
	methods := requests.snapshot()
	if len(methods) != 10 {
		t.Fatalf("HTTP requests=%d want=10 (%v)", len(methods), methods)
	}
	for i := 0; i < len(methods); i += 2 {
		if methods[i] != "GET /Groups" || methods[i+1] != "PUT /Groups/remote" {
			t.Fatalf("HTTP requests=%v", methods)
		}
	}
	assertRealHTTPFailureEvent(t, o, terminalAt, `client-1 / GroupCreateUpdate("group-1")`)
	if err := o.Step(context.Background(), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := requests.snapshot(); len(got) != 10 || scimFailureEventCount(t, o) != 1 {
		t.Fatalf("post-terminal requests=%d events=%d", len(got), scimFailureEventCount(t, o))
	}
}

func TestScimRealHTTPGroupCreateFailureTerminalEvent(t *testing.T) {
	t.Parallel()
	var requests realHTTPRequests
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"Resources":[]}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return client, nil }, OutboxConfig{MaxAttempts: 5, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{23}, 256))})
	now := time.UnixMilli(1_800_000_102_000).UTC()
	if _, err := o.EnqueueGroup(context.Background(), "client-1", Group{ExternalID: "group-2", DisplayName: "Engineering"}, now); err != nil {
		t.Fatal(err)
	}
	job, terminalAt := runRealHTTPFailureAttempts(t, o, now, "group-2")
	if job.Status != "dead" || job.Attempts != 5 {
		t.Fatalf("terminal group job=%+v", job)
	}
	methods := requests.snapshot()
	if len(methods) != 15 {
		t.Fatalf("HTTP requests=%d want=15 (%v)", len(methods), methods)
	}
	posts := 0
	for _, method := range methods {
		if method == "POST /Groups" {
			posts++
		} else if method != "GET /Groups" {
			t.Fatalf("HTTP requests=%v", methods)
		}
	}
	if posts != 5 {
		t.Fatalf("failed POST requests=%d want=5 (%v)", posts, methods)
	}
	assertRealHTTPFailureEvent(t, o, terminalAt, `client-1 / GroupCreateUpdate("group-2")`)
	if err := o.Step(context.Background(), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := requests.snapshot(); len(got) != 15 || scimFailureEventCount(t, o) != 1 {
		t.Fatalf("post-terminal requests=%d events=%d", len(got), scimFailureEventCount(t, o))
	}
}

func TestScimRealHTTPTombstoneDeleteFailureTerminalEvent(t *testing.T) {
	t.Parallel()
	var requests realHTTPRequests
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodGet {
			writeList(w, []User{{ID: "remote", ExternalID: "ext-1", UserName: "alice", Active: true}})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return client, nil }, OutboxConfig{MaxAttempts: 5, RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{22}, 256))})
	now := time.UnixMilli(1_800_000_101_000).UTC()
	generation := "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := storage.Execute(context.Background(), o.DB, rhiza.ExecuteRequest{RequestID: "real-http-delete-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,1,?,?)`, Args: []any{"ext-1", "alice", generation, now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(DeleteRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(context.Background(), "client-1", testUser(), DeleteRemote, generation, now); err != nil || !admitted {
		t.Fatalf("delete admitted=%v err=%v", admitted, err)
	}
	job, terminalAt := runRealHTTPFailureAttempts(t, o, now, "ext-1")
	if job.Status != "dead" || job.Attempts != 5 {
		t.Fatalf("terminal delete job=%+v", job)
	}
	methods := requests.snapshot()
	if len(methods) != 10 {
		t.Fatalf("HTTP requests=%d want=10 (%v)", len(methods), methods)
	}
	for i := 0; i < len(methods); i += 2 {
		if methods[i] != "GET /Users" || methods[i+1] != "DELETE /Users/remote" {
			t.Fatalf("HTTP requests=%v", methods)
		}
	}
	assertRealHTTPFailureEvent(t, o, terminalAt, `client-1 / UserDelete("ext-1")`)
	if err := o.Step(context.Background(), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := requests.snapshot(); len(got) != 10 || scimFailureEventCount(t, o) != 1 {
		t.Fatalf("post-terminal requests=%d events=%d", len(got), scimFailureEventCount(t, o))
	}
}

func runRealHTTPFailureAttempts(t *testing.T, o *Outbox, now time.Time, externalID string) (Job, time.Time) {
	t.Helper()
	ctx := context.Background()
	for attempt := 1; attempt <= 5; attempt++ {
		if err := o.Step(ctx, now); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		job, found, err := o.Lookup(ctx, "client-1", externalID)
		if err != nil || !found {
			t.Fatalf("attempt %d job=%+v found=%v err=%v", attempt, job, found, err)
		}
		if attempt < 5 {
			if got := scimFailureEventCount(t, o); got != 0 {
				t.Fatalf("attempt %d failure events=%d", attempt, got)
			}
			if job.Status != "pending" || job.Attempts != attempt || !job.NextAttemptAt.After(now) {
				t.Fatalf("attempt %d retry job=%+v", attempt, job)
			}
			now = job.NextAttemptAt
		}
	}
	job, found, err := o.Lookup(ctx, "client-1", externalID)
	if err != nil || !found {
		t.Fatalf("terminal lookup job=%+v found=%v err=%v", job, found, err)
	}
	return job, now
}

func assertRealHTTPFailureEvent(t *testing.T, o *Outbox, now time.Time, wantText string) {
	t.Helper()
	rows, err := o.DB.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT timestamp,level,ip,data,text FROM event_log WHERE typ=?`, Args: []any{string(eventlog.ScimTaskFailed)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != now.UnixMilli() || rows.Rows[0][1] != int64(eventlog.Critical.Rank()) || rows.Rows[0][2] != nil || rows.Rows[0][3] != int64(5) || rows.Rows[0][4] != wantText {
		t.Fatalf("failure event=%#v err=%v", rows.Rows, err)
	}
}
