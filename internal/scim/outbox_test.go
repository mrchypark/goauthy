package scim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type fakeReconciler func(context.Context, Request) (Result, error)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type lockedReader struct {
	mu sync.Mutex
	r  *bytes.Reader
}

func (r *lockedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Read(p)
}

func (f fakeReconciler) Reconcile(ctx context.Context, request Request) (Result, error) {
	return f(ctx, request)
}

func newOutboxTest(t *testing.T, resolve ClientResolver, config OutboxConfig) *Outbox {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "scim-outbox-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	o := NewOutbox(db, resolve, config)
	putOutboxProjection(t, o, testUser(), "phc", false, "password")
	return o
}

func testUser() User { return User{ExternalID: "ext-1", UserName: "alice", Active: true} }

func putOutboxProjection(t *testing.T, o *Outbox, user User, password string, disabled bool, mode string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), o.DB, rhiza.ExecuteRequest{RequestID: "scim-outbox-projection-" + user.ExternalID + "-" + user.UserName, Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES (?,?,?,?,0,1)
			ON CONFLICT(subject) DO UPDATE SET username=excluded.username,password_phc=excluded.password_phc,disabled=excluded.disabled`, Args: []any{user.ExternalID, user.UserName, password, map[bool]int64{false: 0, true: 1}[disabled]}},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?,?,1,0)
			ON CONFLICT(subject) DO UPDATE SET mode=excluded.mode`, Args: []any{user.ExternalID, mode}},
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxEnqueueCoalescesAndNeverStoresToken(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{Action: ActionCreated}, nil }), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
	now := time.UnixMilli(1000)
	first, err := o.Enqueue(ctx, "client-1", Request{User: testUser()}, now)
	if err != nil {
		t.Fatal(err)
	}
	updated := testUser()
	updated.UserName = "alice-2"
	second, err := o.Enqueue(ctx, "client-1", Request{User: updated}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || second.Revision != 2 || second.Request.User.UserName != "alice-2" {
		t.Fatalf("coalesced jobs: first=%+v second=%+v", first, second)
	}
	var count int64
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*),request_json FROM scim_user_outbox WHERE client_id=?`, Args: []any{"client-1"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("rows=%#v err=%v", result.Rows, err)
	}
	count, _ = result.Rows[0][0].(int64)
	encoded, _ := result.Rows[0][1].(string)
	if count != 1 || bytes.Contains([]byte(encoded), []byte("Bearer")) || bytes.Contains([]byte(encoded), []byte("secret")) {
		t.Fatalf("stored outbox state=%q count=%d", encoded, count)
	}
}

func TestOutboxIdenticalEnqueueDoesNotResetTerminalOrRetryState(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(5000)
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			return Result{Action: ActionCreated}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{5}, 128)), RetryBase: time.Second})
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	completed, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || completed.Status != "succeeded" || completed.Revision != 1 {
		t.Fatalf("completed=%+v found=%v err=%v", completed, found, err)
	}
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	unchanged, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || unchanged.Status != completed.Status || unchanged.Revision != completed.Revision || unchanged.Attempts != completed.Attempts || !unchanged.NextAttemptAt.Equal(completed.NextAttemptAt) {
		t.Fatalf("identical enqueue reset completed job: before=%+v after=%+v found=%v err=%v", completed, unchanged, found, err)
	}

	failing := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			return Result{}, errors.New("temporary transport error")
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{6}, 128)), RetryBase: time.Second})
	if _, err := failing.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := failing.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	retry, found, err := failing.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || retry.Status != "pending" || retry.Attempts != 1 {
		t.Fatalf("retry=%+v found=%v err=%v", retry, found, err)
	}
	if _, err := failing.EnqueueUser(ctx, "client-1", testUser(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retryAfter, found, err := failing.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || retryAfter.Status != retry.Status || retryAfter.Revision != retry.Revision || retryAfter.Attempts != retry.Attempts || !retryAfter.NextAttemptAt.Equal(retry.NextAttemptAt) {
		t.Fatalf("identical enqueue reset retry job: before=%+v after=%+v found=%v err=%v", retry, retryAfter, found, err)
	}
}

func TestOutboxStepCASRetryAndDeadLetter(t *testing.T) {
	ctx := context.Background()
	var calls int
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			calls++
			return Result{}, errors.New("temporary transport error")
		}), nil
	}, OutboxConfig{MaxAttempts: 2, RetryBase: time.Millisecond, Random: bytes.NewReader(bytes.Repeat([]byte{2}, 64))})
	now := time.UnixMilli(2000)
	requeued := testUser()
	requeued.UserName = "alice-requeued"
	putOutboxProjection(t, o, requeued, "phc", false, "password")
	if _, err := o.EnqueueUser(ctx, "client-1", requeued, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "pending" || job.Attempts != 1 || !job.NextAttemptAt.After(now) {
		t.Fatalf("after retry job=%+v found=%v err=%v", job, found, err)
	}
	if err := o.Step(ctx, job.NextAttemptAt.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	job, found, err = o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "dead" || job.Attempts != 2 || job.CompletedAt == nil || calls != 2 {
		t.Fatalf("after dead-letter job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxRetriesClientTransportAndServerFailures(t *testing.T) {
	for _, failure := range []string{"503", "drop"} {
		t.Run(failure, func(t *testing.T) {
			var calls int
			first := true
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failure == "503" && first {
					first = false
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if r.Method == http.MethodGet {
					writeList(w, nil)
					return
				}
				w.Header().Set("Content-Type", "application/scim+json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"ext-1","userName":"alice","active":true}`))
			}))
			defer server.Close()
			base := server.Client()
			transport := base.Transport
			client := base
			if failure == "drop" {
				client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						return nil, errors.New("connection reset")
					}
					return transport.RoundTrip(r)
				})}
			}
			scimClient, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return scimClient, nil }, OutboxConfig{RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 128))})
			now := time.UnixMilli(9000)
			if _, err := o.EnqueueUser(context.Background(), "client-1", testUser(), now); err != nil {
				t.Fatal(err)
			}
			if err := o.Step(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			job, found, err := o.Lookup(context.Background(), "client-1", "ext-1")
			if err != nil || !found || job.Status != "pending" || job.Attempts != 1 || !job.NextAttemptAt.After(now) {
				t.Fatalf("retry job=%+v found=%v err=%v", job, found, err)
			}
			if err := o.Step(context.Background(), job.NextAttemptAt); err != nil {
				t.Fatal(err)
			}
			job, found, err = o.Lookup(context.Background(), "client-1", "ext-1")
			if err != nil || !found || job.Status != "succeeded" || job.Attempts != 2 {
				t.Fatalf("completed job=%+v found=%v err=%v", job, found, err)
			}
		})
	}
}

func TestOutboxRetriesPartialClientResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeList(w, nil)
			return
		}
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"ext-1","userName":"alice","active":true}`))
	}))
	defer server.Close()
	first := true
	base := server.Client().Transport
	client, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if first {
			first = false
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/scim+json"}}, Body: &partialReadCloser{data: []byte(`{`), err: io.ErrUnexpectedEOF}, Request: r}, nil
		}
		return base.RoundTrip(r)
	})}})
	if err != nil {
		t.Fatal(err)
	}
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return client, nil }, OutboxConfig{RetryBase: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{11}, 128))})
	now := time.UnixMilli(11000)
	if _, err := o.EnqueueUser(context.Background(), "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(context.Background(), "client-1", "ext-1")
	if err != nil || !found || job.Status != "pending" || job.Attempts != 1 {
		t.Fatalf("retry job=%+v found=%v err=%v", job, found, err)
	}
	if err := o.Step(context.Background(), job.NextAttemptAt); err != nil {
		t.Fatal(err)
	}
	job, found, err = o.Lookup(context.Background(), "client-1", "ext-1")
	if err != nil || !found || job.Status != "succeeded" || job.Attempts != 2 {
		t.Fatalf("completed job=%+v found=%v err=%v", job, found, err)
	}
}

func TestOutboxDeadLettersClientPermanentFailures(t *testing.T) {
	for name, response := range map[string]func(http.ResponseWriter){
		"400": func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadRequest) },
		"malformed": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(`{`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { response(w) }))
			defer server.Close()
			client, err := New(Config{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return client, nil }, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{10}, 128))})
			now := time.UnixMilli(10000)
			if _, err := o.EnqueueUser(context.Background(), "client-1", testUser(), now); err != nil {
				t.Fatal(err)
			}
			if err := o.Step(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			job, found, err := o.Lookup(context.Background(), "client-1", "ext-1")
			if err != nil || !found || job.Status != "dead" || job.Attempts != 1 {
				t.Fatalf("dead job=%+v found=%v err=%v", job, found, err)
			}
		})
	}
}

func TestOutboxMaxAttemptDeadLetterCASKeepsCoalescedRequest(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			return Result{}, errors.New("unused")
		}), nil
	}, OutboxConfig{MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 64))})
	now := time.UnixMilli(2500)
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	candidate, found, err := o.nextCandidate(ctx, now)
	if err != nil || !found {
		t.Fatalf("candidate=%+v found=%v err=%v", candidate, found, err)
	}
	updated := testUser()
	updated.UserName = "alice-new"
	putOutboxProjection(t, o, updated, "phc", false, "password")
	if _, err := o.EnqueueUser(ctx, "client-1", updated, now); err != nil {
		t.Fatal(err)
	}
	if _, err := o.deadLetterExpired(ctx, candidate, now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", updated.ExternalID)
	if err != nil || !found || job.Status == "dead" || job.Revision != 2 || job.Request.User.UserName != "alice-new" {
		t.Fatalf("coalesced request was dead-lettered: job=%+v found=%v err=%v", job, found, err)
	}
}

func TestOutboxOrderingUsesRequestTypeForHashedGroups(t *testing.T) {
	ctx := context.Background()
	var order []bool
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			order = append(order, request.Group.ExternalID != "")
			return Result{}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{9}, 128))})
	now := time.UnixMilli(2750)
	if _, err := o.EnqueueGroup(ctx, "client-1", Group{ExternalID: strings.Repeat("g", maxIdentifierBytes), DisplayName: "Engineering"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] || !order[1] {
		t.Fatalf("job ordering=%v, want user then group", order)
	}
}

func TestOutboxDeliversGroupWithDeterministicRetry(t *testing.T) {
	ctx := context.Background()
	var calls int
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			calls++
			if request.Group.ExternalID != "group-1" || len(request.Group.Members) != 2 {
				t.Fatalf("unexpected group request: %#v", request)
			}
			if calls == 1 {
				return Result{}, errors.New("temporary provider failure")
			}
			return Result{Action: ActionCreated}, nil
		}), nil
	}, OutboxConfig{RetryBase: time.Millisecond, Random: bytes.NewReader(bytes.Repeat([]byte{21}, 64))})
	now := time.UnixMilli(3200)
	group := Group{ExternalID: "group-1", DisplayName: "Engineering", Members: []GroupMember{{Value: "remote-b"}, {Value: "remote-a"}}}
	if _, err := o.EnqueueGroup(ctx, "client-1", group, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.LookupGroup(ctx, "client-1", group.ExternalID)
	if err != nil || !found || job.Status != "pending" || job.Attempts != 1 || !job.NextAttemptAt.After(now) {
		t.Fatalf("group retry state=%+v found=%v err=%v", job, found, err)
	}
	if err := o.Step(ctx, job.NextAttemptAt); err != nil {
		t.Fatal(err)
	}
	job, found, err = o.LookupGroup(ctx, "client-1", group.ExternalID)
	if err != nil || !found || job.Status != "succeeded" || job.Attempts != 2 || calls != 2 {
		t.Fatalf("group completion state=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxLookupDoesNotTreatUserExternalIDGroupPrefixAsGroup(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, nil }), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{10}, 64))})
	now := time.UnixMilli(3000)
	user := testUser()
	user.ExternalID = "group:alice"
	userJob, err := o.EnqueueUser(ctx, "client-1", user, now)
	if err != nil {
		t.Fatal(err)
	}
	groupJob, err := o.EnqueueGroup(ctx, "client-1", Group{ExternalID: "alice", DisplayName: "Engineering"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if userJob.ID == groupJob.ID {
		t.Fatalf("user and group jobs collided: user=%+v group=%+v", userJob, groupJob)
	}
	gotUser, found, err := o.Lookup(ctx, "client-1", user.ExternalID)
	if err != nil || !found || gotUser.Request.User.ExternalID != user.ExternalID || gotUser.Request.Group.ExternalID != "" {
		t.Fatalf("user lookup=%+v found=%v err=%v", gotUser, found, err)
	}
	gotGroup, found, err := o.LookupGroup(ctx, "client-1", "alice")
	if err != nil || !found || gotGroup.Request.Group.ExternalID != "alice" {
		t.Fatalf("group lookup=%+v found=%v err=%v", gotGroup, found, err)
	}
}

func TestOutboxSerializesConcurrentStepsForOneUser(t *testing.T) {
	ctx := context.Background()
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	resolve := func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			close(entered)
			<-release
			return Result{Action: ActionCreated}, nil
		}), nil
	}
	o := newOutboxTest(t, resolve, OutboxConfig{LeaseDuration: time.Minute, Random: &lockedReader{r: bytes.NewReader(bytes.Repeat([]byte{3}, 128))}})
	now := time.UnixMilli(3000)
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- o.Step(ctx, now) }()
	<-entered
	secondDone := make(chan error, 1)
	go func() { secondDone <- o.Step(ctx, now) }()
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("reconcile calls=%d want 1", calls)
	}
}

func TestOutboxGenericDeleteIsRejected(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3500)
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			calls++
			return Result{Action: ActionDeleted}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{11}, 64))})
	if _, err := o.Enqueue(ctx, "client-1", Request{User: testUser(), Delete: true, DeletePolicy: DeleteRemote}, now); !errors.Is(err, ErrOutboxInvalid) {
		t.Fatalf("generic delete err=%v", err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := o.Lookup(ctx, "client-1", testUser().ExternalID); err != nil || found || calls != 0 {
		t.Fatalf("generic delete was delivered found=%v calls=%d err=%v", found, calls, err)
	}
}

func TestOutboxEnqueueTombstoneDeleteFence(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3400)
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, nil }), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{18}, 64))})
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-enqueue-fence", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,?,1,?,?)`, Args: []any{"ext-1", "alice", int64(1), "AAAAAAAAAAAAAAAAAAAAAA", now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(UnlinkRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	job, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), UnlinkRemote, "AAAAAAAAAAAAAAAAAAAAAA", now)
	if err != nil || !admitted || !job.Request.Delete || job.Request.DeletePolicy != UnlinkRemote {
		t.Fatalf("exact tombstone enqueue job=%+v admitted=%v err=%v", job, admitted, err)
	}
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT request_json FROM scim_user_outbox WHERE job_id=?`, Args: []any{job.ID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || !strings.Contains(result.Rows[0][0].(string), `"tombstoneGeneration":"AAAAAAAAAAAAAAAAAAAAAA"`) {
		t.Fatalf("stored tombstone generation rows=%#v err=%v", result.Rows, err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err := o.Lookup(ctx, "client-1", testUser().ExternalID); err != nil || !found || job.Status != "succeeded" {
		t.Fatalf("exact tombstone generation was not claimed: job=%+v found=%v err=%v", job, found, err)
	}

	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-enqueue-cleanup", SQL: `DELETE FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{"ext-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), UnlinkRemote, "AAAAAAAAAAAAAAAAAAAAAA", now); err != nil || admitted {
		t.Fatalf("cleaned tombstone admitted=%v err=%v", admitted, err)
	}

	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-enqueue-replaced", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,?,1,?,?)`, Args: []any{"ext-1", "alice", int64(1), "BBBBBBBBBBBBBBBBBBBBBB", now.UnixMilli()}},
		{SQL: `UPDATE scim_user_tombstone_providers SET delete_policy=? WHERE local_external_id=? AND client_id=?`, Args: []any{int64(DeleteRemote), "ext-1", "client-1"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), UnlinkRemote, "BBBBBBBBBBBBBBBBBBBBBB", now); err != nil || admitted {
		t.Fatalf("changed provider snapshot admitted=%v err=%v", admitted, err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), DeleteRemote, "", now); !errors.Is(err, ErrOutboxInvalid) || admitted {
		t.Fatalf("legacy generation admitted=%v err=%v", admitted, err)
	}
}

func TestOutboxClaimRejectsLegacyAndStaleTombstoneDeletes(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3450)
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			calls++
			return Result{Action: ActionDeleted}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{19}, 128))})

	legacy := testUser()
	legacy.ExternalID = "legacy-delete"
	legacy.UserName = "legacy-alice"
	encoded, digest, err := encodeRequest(Request{User: legacy, Delete: true, DeletePolicy: DeleteRemote})
	if err != nil {
		t.Fatal(err)
	}
	legacyID := outboxJobID("client-1", legacy.ExternalID)
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-raw-legacy-delete", SQL: `INSERT INTO scim_user_outbox (job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,'pending',0,?,1,?,?)`, Args: []any{legacyID, "client-1", legacy.ExternalID, encoded, digest, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	putOutboxProjection(t, o, legacy, "phc", false, "password")
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err := o.Lookup(ctx, "client-1", legacy.ExternalID); err != nil || !found || job.Status != "pending" || job.Attempts != 0 || calls != 0 {
		t.Fatalf("legacy delete was claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-delay-legacy-delete", SQL: `UPDATE scim_user_outbox SET next_attempt_at_unix_ms=? WHERE job_id=?`, Args: []any{now.Add(time.Hour).UnixMilli(), legacyID}}); err != nil {
		t.Fatal(err)
	}

	stale := testUser()
	stale.ExternalID = "stale-delete"
	stale.UserName = "stale-alice"
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-stale-generation", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,?,1,?,?)`, Args: []any{stale.ExternalID, stale.UserName, int64(1), "EEEEEEEEEEEEEEEEEEEEEE", now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{stale.ExternalID, "client-1", int64(DeleteRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", stale, DeleteRemote, "EEEEEEEEEEEEEEEEEEEEEE", now); err != nil || !admitted {
		t.Fatalf("exact generation admitted=%v err=%v", admitted, err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-replace-generation", SQL: `UPDATE scim_user_tombstones SET generation=? WHERE local_external_id=?`, Args: []any{"FFFFFFFFFFFFFFFFFFFFFF", stale.ExternalID}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err := o.Lookup(ctx, "client-1", stale.ExternalID); err != nil || !found || job.Status != "pending" || job.Attempts != 0 || calls != 0 {
		t.Fatalf("stale generation delete was claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxStaleCreateDoesNotMapOrAcknowledgeDelete(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3600)
	entered := make(chan struct{})
	release := make(chan struct{})
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			if !request.Delete {
				return Result{Action: ActionCreated, RemoteID: "remote-1"}, nil
			}
			return Result{Action: ActionNoop}, nil
		}), nil
	}, OutboxConfig{Random: &lockedReader{r: bytes.NewReader(bytes.Repeat([]byte{12}, 128))}})
	o.Mapping = NewUserMappingStore(o.DB)
	o.beforeFinish = func() { close(entered); <-release }
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- o.Step(ctx, now) }()
	<-entered
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-stale-create-tombstone", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,?,1,?,?)`, Args: []any{"ext-1", "alice", int64(1), "GGGGGGGGGGGGGGGGGGGGGG", now.UnixMilli()}},
		{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{"ext-1", "client-1", int64(UnlinkRemote)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", testUser(), UnlinkRemote, "GGGGGGGGGGGGGGGGGGGGGG", now.Add(time.Millisecond)); err != nil || !admitted {
		t.Fatalf("tombstone delete admitted=%v err=%v", admitted, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "pending" || !job.Request.Delete || job.Revision != 2 {
		t.Fatalf("stale completion acknowledged delete: job=%+v found=%v err=%v", job, found, err)
	}
	if _, found, err := o.Mapping.Lookup(ctx, "client-1", "ext-1"); err != nil || found {
		t.Fatalf("stale create wrote mapping: found=%v err=%v", found, err)
	}
}

func TestOutboxMappingFailureRollsBackTerminalizationAndRetries(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3800)
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			return Result{Action: ActionCreated, RemoteID: "remote-1"}, nil
		}), nil
	}, OutboxConfig{LeaseDuration: 2 * time.Second, RequestTimeout: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{13}, 128))})
	o.Mapping = NewUserMappingStore(o.DB)
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-map-abort", SQL: `CREATE TRIGGER scim_map_abort BEFORE INSERT ON scim_user_mappings BEGIN SELECT RAISE(ABORT, 'mapping unavailable'); END`}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err == nil {
		t.Fatal("mapping write failure acknowledged delivery")
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "processing" {
		t.Fatalf("failed mapping transaction job=%+v found=%v err=%v", job, found, err)
	}
	if _, found, err := o.Mapping.Lookup(ctx, "client-1", "ext-1"); err != nil || found {
		t.Fatalf("failed mapping transaction persisted link: found=%v err=%v", found, err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-map-drop-abort", SQL: `DROP TRIGGER scim_map_abort`}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	job, found, err = o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "succeeded" {
		t.Fatalf("mapping retry job=%+v found=%v err=%v", job, found, err)
	}
}

func TestOutboxClaimDoesNotRecreateTombstonedLiveUser(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3900)
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			calls++
			return Result{Action: ActionCreated, RemoteID: "remote-1"}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{14}, 64))})
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	o.beforeClaim = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { done <- o.Step(ctx, now) }()
	<-entered
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-race", SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{"ext-1", "alice", int64(1), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "pending" || job.Attempts != 0 || calls != 0 {
		t.Fatalf("tombstoned live sync was claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxClaimsLegacyLiveRequestWithoutOperation(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3925)
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) {
			calls++
			return Result{Action: ActionCreated}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{17}, 64))})
	job, err := o.EnqueueUser(ctx, "client-1", testUser(), now)
	if err != nil {
		t.Fatal(err)
	}
	legacy, digest, err := encodeRequestVersion(Request{User: testUser()}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-legacy-live-request", SQL: `UPDATE scim_user_outbox SET request_json=?,request_digest=? WHERE job_id=?`, Args: []any{legacy, digest, job.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err := o.Lookup(ctx, "client-1", testUser().ExternalID); err != nil || !found || job.Status != "succeeded" || calls != 1 {
		t.Fatalf("legacy live request was not claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxClaimRejectsStaleLiveProjectionAfterTombstoneCleanup(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(3950)
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			calls++
			return Result{Action: ActionCreated, RemoteID: request.User.UserName}, nil
		}), nil
	}, OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{16}, 128))})
	stale := testUser()
	if _, err := o.EnqueueUser(ctx, "client-1", stale, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-stale-delete", Statements: []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_authentication_modes WHERE subject=?`, Args: []any{stale.ExternalID}},
		{SQL: `DELETE FROM identity_users WHERE subject=?`, Args: []any{stale.ExternalID}},
		{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,deleted_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{stale.ExternalID, stale.UserName, int64(1), now.UnixMilli()}},
		{SQL: `DELETE FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{stale.ExternalID}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	job, found, err := o.Lookup(ctx, "client-1", stale.ExternalID)
	if err != nil || !found || job.Status != "pending" || job.Attempts != 0 || calls != 0 {
		t.Fatalf("deleted projection was claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
	recreated := stale
	recreated.UserName = "alice-recreated"
	putOutboxProjection(t, o, recreated, "", false, "passkey")
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err = o.Lookup(ctx, "client-1", stale.ExternalID); err != nil || !found || job.Status != "pending" || job.Attempts != 0 || calls != 0 {
		t.Fatalf("different projection claimed stale job: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
	if _, err := o.EnqueueUser(ctx, "client-1", recreated, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if job, found, err = o.Lookup(ctx, "client-1", stale.ExternalID); err != nil || !found || job.Status != "succeeded" || job.Request.User.ExternalID != recreated.ExternalID || job.Request.User.UserName != recreated.UserName || job.Request.User.Active != recreated.Active || calls != 1 {
		t.Fatalf("fresh projection was not claimed: job=%+v found=%v calls=%d err=%v", job, found, calls, err)
	}
}

func TestOutboxCleanupIsBounded(t *testing.T) {
	ctx := context.Background()
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(context.Context, Request) (Result, error) { return Result{}, nil }), nil
	}, OutboxConfig{Retention: time.Millisecond, CleanupLimit: 1, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 128))})
	now := time.UnixMilli(4000)
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	second := testUser()
	second.ExternalID = "ext-2"
	second.UserName = "alice-2"
	putOutboxProjection(t, o, second, "phc", false, "password")
	if _, err := o.EnqueueUser(ctx, "client-1", second, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	deleted, err := o.Cleanup(ctx, now.Add(2*time.Millisecond), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	deleted, err = o.Cleanup(ctx, now.Add(2*time.Millisecond), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("second cleanup deleted=%d err=%v", deleted, err)
	}
}

func TestOutboxCleanupKeepsTerminalDeletesOwnedByTombstones(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(4500)
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(_ context.Context, request Request) (Result, error) {
			if request.User.ExternalID == "ext-dead" {
				return Result{}, errors.New("permanent delete failure")
			}
			return Result{Action: ActionDeleted}, nil
		}), nil
	}, OutboxConfig{MaxAttempts: 1, Retention: time.Millisecond, Random: bytes.NewReader(bytes.Repeat([]byte{15}, 128))})

	succeeded := testUser()
	succeeded.ExternalID = "ext-succeeded"
	dead := testUser()
	dead.ExternalID = "ext-dead"
	nonDelete := testUser()
	nonDelete.ExternalID = "ext-non-delete"
	nonDelete.UserName = "alice-non-delete"
	putOutboxProjection(t, o, nonDelete, "phc", false, "password")
	for i, user := range []User{succeeded, dead} {
		generation := []string{"CCCCCCCCCCCCCCCCCCCCCC", "DDDDDDDDDDDDDDDDDDDDDD"}[i]
		if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-" + user.ExternalID, Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,?,1,?,?)`, Args: []any{user.ExternalID, user.UserName, int64(1), generation, now.UnixMilli()}},
			{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{user.ExternalID, "client-1", int64(DeleteRemote)}},
		}}); err != nil {
			t.Fatal(err)
		}
		if _, admitted, err := o.EnqueueTombstoneDelete(ctx, "client-1", user, DeleteRemote, generation, now); err != nil || !admitted {
			t.Fatalf("tombstone delete admitted=%v err=%v", admitted, err)
		}
	}
	if _, err := o.EnqueueUser(ctx, "client-1", nonDelete, now); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := o.Step(ctx, now); err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := o.Cleanup(ctx, now.Add(2*time.Millisecond), 3)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup with tombstones deleted=%d err=%v", deleted, err)
	}
	for _, externalID := range []string{succeeded.ExternalID, dead.ExternalID} {
		job, found, err := o.Lookup(ctx, "client-1", externalID)
		if err != nil || !found || !job.Request.Delete || (externalID == dead.ExternalID && job.Status != "dead") || (externalID == succeeded.ExternalID && job.Status != "succeeded") {
			t.Fatalf("preserved delete externalID=%q job=%+v found=%v err=%v", externalID, job, found, err)
		}
		if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-tombstone-remove-" + externalID, SQL: `DELETE FROM scim_user_tombstones WHERE local_external_id=?`, Args: []any{externalID}}); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err = o.Cleanup(ctx, now.Add(2*time.Millisecond), 3)
	if err != nil || deleted != 2 {
		t.Fatalf("cleanup after tombstone removal deleted=%d err=%v", deleted, err)
	}
}

func TestOutboxLeaseTimeoutAndClaimAttemptLimit(t *testing.T) {
	ctx := context.Background()
	calls := 0
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) {
		return fakeReconciler(func(ctx context.Context, _ Request) (Result, error) {
			calls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("reconcile context has no deadline")
			}
			return Result{}, errors.New("bounded transport")
		}), nil
	}, OutboxConfig{LeaseDuration: 2 * time.Second, RequestTimeout: time.Second, MaxAttempts: 1, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 128))})
	now := time.UnixMilli(5000)
	if _, err := o.EnqueueUser(ctx, "client-1", testUser(), now); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("reconcile calls=%d want 1", calls)
	}
	job, found, err := o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || !found || job.Status != "dead" || job.Attempts != 1 {
		t.Fatalf("job after timeout=%+v found=%v err=%v", job, found, err)
	}

	requeued := testUser()
	requeued.UserName = "alice-requeued"
	putOutboxProjection(t, o, requeued, "phc", false, "password")
	if _, err := o.EnqueueUser(ctx, "client-1", requeued, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: "scim-test-expired", SQL: `UPDATE scim_user_outbox SET status='processing',attempts=?,lease_token='old',lease_until_unix_ms=? WHERE job_id=?`, Args: []any{int64(1), now.Add(-time.Millisecond).UnixMilli(), job.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := o.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	job, _, err = o.Lookup(ctx, "client-1", "ext-1")
	if err != nil || job.Status != "dead" || job.Attempts != 1 || calls != 1 {
		t.Fatalf("expired max-attempt job=%+v calls=%d err=%v", job, calls, err)
	}
}

func TestOutboxRejectsLeaseTimeoutConfig(t *testing.T) {
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{LeaseDuration: time.Second, RequestTimeout: time.Second})
	if err := o.valid(); err == nil {
		t.Fatal("request timeout equal to lease was accepted")
	}
}

func TestOutboxBoundsConfigAndRetryDelay(t *testing.T) {
	o := newOutboxTest(t, func(context.Context, string) (Reconciler, error) { return fakeReconciler(nil), nil }, OutboxConfig{LeaseDuration: 25 * time.Hour})
	if err := o.valid(); err == nil {
		t.Fatal("oversized lease was accepted")
	}
	o.LeaseDuration = time.Minute
	o.RequestTimeout = 10 * time.Second
	o.RetryBase = time.Hour + time.Nanosecond
	if err := o.valid(); err == nil {
		t.Fatal("oversized retry base was accepted")
	}
	o.RetryBase = time.Second
	o.MaxAttempts = 1001
	if err := o.valid(); err == nil {
		t.Fatal("oversized attempt count was accepted")
	}
	o.RetryBase = time.Hour
	o.MaxAttempts = 1000
	if got := o.retryDelay(Job{ID: "job"}, 1000); got > time.Hour {
		t.Fatalf("retry delay=%s exceeds one hour", got)
	}
}
