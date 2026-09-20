package scim

// The outbox stores desired SCIM operations, never SCIM credentials. Runtime
// wiring is intentionally outside this library slice. A
// resolver supplies a configured Client at Step time so a Bearer token cannot
// accidentally become durable job state.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	defaultOutboxLease    = time.Minute
	defaultRequestTimeout = 10 * time.Second
	defaultRetryBase      = time.Second
	defaultMaxAttempts    = 5
	defaultCleanupLimit   = 128
	defaultRetention      = 24 * time.Hour
	maxOutboxLease        = 24 * time.Hour
	maxRequestTimeout     = time.Hour
	maxRetryBase          = time.Hour
	maxRetention          = 365 * 24 * time.Hour
	maxAttempts           = 1000
	maxRetryDelay         = time.Hour
	maxOutboxErrorLength  = 256
)

var (
	ErrOutboxInvalid = errors.New("scim: invalid outbox configuration or request")
	ErrOutboxLease   = errors.New("scim: outbox lease was lost")
)

// Reconciler is deliberately narrower than Client: Step only needs one
// request boundary and cannot access the client's token.
type Reconciler interface {
	Reconcile(context.Context, Request) (Result, error)
}

// ClientResolver loads a configured SCIM client using a durable client ID.
// Implementations should obtain secrets from runtime configuration or a
// secret manager, rather than from the outbox row.
type ClientResolver func(context.Context, string) (Reconciler, error)

// OutboxConfig controls deterministic worker behavior. Zero values select
// conservative production defaults.
type OutboxConfig struct {
	Resolve        ClientResolver
	Mapping        *UserMappingStore
	LeaseDuration  time.Duration
	RequestTimeout time.Duration
	RetryBase      time.Duration
	MaxAttempts    int
	Retention      time.Duration
	CleanupLimit   int
	Now            func() time.Time
	Random         io.Reader
}

// Job is the durable state of one coalesced client/externalId operation.
// Request contains only SCIM data and policy; it has no authentication data.
type Job struct {
	ID            string
	ClientID      string
	Request       Request
	Status        string
	Attempts      int
	NextAttemptAt time.Time
	Revision      int64
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CompletedAt   *time.Time
	leaseToken    string
	requestDigest string
}

// Outbox persists and executes SCIM work.
type Outbox struct {
	DB             *rhiza.DB
	Resolve        ClientResolver
	Mapping        *UserMappingStore
	LeaseDuration  time.Duration
	RequestTimeout time.Duration
	RetryBase      time.Duration
	MaxAttempts    int
	Retention      time.Duration
	CleanupLimit   int
	Now            func() time.Time
	Random         io.Reader
	cleanupSeq     uint64
	mutationSeq    uint64
	beforeFinish   func() // test seam for the post-delivery CAS boundary
	beforeClaim    func() // test seam for the tombstone/claim boundary
}

// NewOutbox constructs a Rhiza-backed SCIM outbox.
func NewOutbox(db *rhiza.DB, resolve ClientResolver, configs ...OutboxConfig) *Outbox {
	config := OutboxConfig{Resolve: resolve}
	if len(configs) != 0 {
		config = configs[0]
		if config.Resolve == nil {
			config.Resolve = resolve
		}
	}
	o := &Outbox{DB: db, Resolve: config.Resolve, Mapping: config.Mapping, LeaseDuration: config.LeaseDuration, RequestTimeout: config.RequestTimeout, RetryBase: config.RetryBase, MaxAttempts: config.MaxAttempts, Retention: config.Retention, CleanupLimit: config.CleanupLimit, Now: config.Now, Random: config.Random}
	o.defaults()
	return o
}

func (o *Outbox) defaults() {
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = defaultOutboxLease
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = defaultRequestTimeout
		if o.RequestTimeout >= o.LeaseDuration {
			o.RequestTimeout = o.LeaseDuration / 2
		}
	}
	if o.RetryBase <= 0 {
		o.RetryBase = defaultRetryBase
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = defaultMaxAttempts
	}
	if o.Retention <= 0 {
		o.Retention = defaultRetention
	}
	if o.CleanupLimit <= 0 {
		o.CleanupLimit = defaultCleanupLimit
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Random == nil {
		o.Random = rand.Reader
	}
}

// Enqueue coalesces work by client ID and immutable externalId. A desired
// update arriving during an in-flight attempt bumps revision; the old attempt
// then releases the row back to pending instead of acknowledging new data.
func (o *Outbox) Enqueue(ctx context.Context, clientID string, request Request, now time.Time) (Job, error) {
	if err := o.valid(); err != nil || !validOutboxClientID(clientID) || ctx == nil {
		return Job{}, ErrOutboxInvalid
	}
	if request.Group.ExternalID != "" {
		members, err := canonicalMembersChecked(request.Group.Members)
		if err != nil {
			return Job{}, err
		}
		request.Group.Members = members
	}
	if err := validateRequest(request); err != nil {
		return Job{}, err
	}
	if request.Delete {
		return Job{}, ErrOutboxInvalid
	}
	now = o.time(now)
	if !validOutboxTime(now) {
		return Job{}, ErrOutboxInvalid
	}
	encoded, digest, err := encodeRequest(request)
	if err != nil {
		return Job{}, err
	}
	externalID := requestExternalID(request)
	// Keep already-durable v37 user rows addressable while new rows use a
	// disjoint user/group namespace.
	if request.Group.ExternalID == "" {
		legacyID := request.User.ExternalID
		if _, found, err := o.lookup(ctx, outboxJobID(clientID, legacyID)); err != nil {
			return Job{}, err
		} else if found {
			externalID = legacyID
		}
	}
	jobID := outboxJobID(clientID, externalID)
	requestID := o.mutationID("sco/e", jobID, digest, fmt.Sprint(now.UnixMilli()))
	_, writeErr := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO scim_user_outbox
		(job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms)
		VALUES (?,?,?,?,?,'pending',0,?,1,?,?)
		ON CONFLICT(client_id,external_id) DO UPDATE SET
			request_json=excluded.request_json, request_digest=excluded.request_digest,
			revision=scim_user_outbox.revision+1,
			status=CASE WHEN scim_user_outbox.status='processing' THEN 'processing' ELSE 'pending' END,
			attempts=CASE WHEN scim_user_outbox.status='processing' THEN scim_user_outbox.attempts ELSE 0 END,
			next_attempt_at_unix_ms=CASE WHEN scim_user_outbox.status='processing' THEN scim_user_outbox.next_attempt_at_unix_ms ELSE excluded.next_attempt_at_unix_ms END,
			lease_token=CASE WHEN scim_user_outbox.status='processing' THEN scim_user_outbox.lease_token ELSE NULL END,
			lease_until_unix_ms=CASE WHEN scim_user_outbox.status='processing' THEN scim_user_outbox.lease_until_unix_ms ELSE NULL END,
			last_error=NULL, completed_at_unix_ms=NULL, updated_at_unix_ms=excluded.updated_at_unix_ms
			WHERE scim_user_outbox.request_digest <> excluded.request_digest`, Args: []any{jobID, clientID, externalID, encoded, digest, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()}})
	if writeErr != nil {
		return Job{}, writeErr
	}
	job, found, readErr := o.lookup(ctx, jobID)
	if readErr != nil {
		return Job{}, readErr
	}
	if !found {
		return Job{}, errors.New("scim outbox enqueue committed without a row")
	}
	return job, nil
}

// EnqueueUser is the compact form for the common sync operation.
func (o *Outbox) EnqueueUser(ctx context.Context, clientID string, user User, now time.Time) (Job, error) {
	return o.Enqueue(ctx, clientID, Request{User: user}, now)
}

func (o *Outbox) EnqueueGroup(ctx context.Context, clientID string, group Group, now time.Time) (Job, error) {
	return o.Enqueue(ctx, clientID, Request{Group: group}, now)
}

// SupersedeGroupProjection returns the statement that repoints every queued
// projection of one removed local group at a provider-scoped delete. The job
// key is unchanged, so the delete supersedes a pending or in-flight sync for
// the same provider while the row that proves a remote group exists is kept.
// guard is the caller's local-deletion predicate; it is ANDed into the rewrite
// so a projection is superseded only when that deletion commits, and guardArgs
// follows this statement's own arguments in predicate order.
//
// A group removal is always DeleteRemote: unlinking a remote group without
// removing it stays a separate, explicit operation.
func SupersedeGroupProjection(externalID, displayName, guard string, guardArgs []any, now time.Time) (rhiza.SQLStatement, error) {
	if !validIdentifier(externalID) || !validIdentifier(displayName) || strings.TrimSpace(guard) == "" || !validOutboxTime(now.UTC()) {
		return rhiza.SQLStatement{}, ErrOutboxInvalid
	}
	encoded, digest, err := encodeRequest(Request{Group: Group{ExternalID: externalID, DisplayName: displayName}, Delete: true, DeletePolicy: DeleteRemote})
	if err != nil {
		return rhiza.SQLStatement{}, err
	}
	now = now.UTC().Truncate(time.Millisecond)
	// The release semantics mirror Enqueue: an in-flight attempt keeps its
	// lease but loses the CAS on the bumped revision, so it returns the row to
	// pending with the delete instead of acknowledging the superseded sync.
	sql := `UPDATE scim_user_outbox SET request_json=?,request_digest=?,revision=revision+1,
		status=CASE WHEN status='processing' THEN 'processing' ELSE 'pending' END,
		attempts=CASE WHEN status='processing' THEN attempts ELSE 0 END,
		next_attempt_at_unix_ms=CASE WHEN status='processing' THEN next_attempt_at_unix_ms ELSE ? END,
		lease_token=CASE WHEN status='processing' THEN lease_token ELSE NULL END,
		lease_until_unix_ms=CASE WHEN status='processing' THEN lease_until_unix_ms ELSE NULL END,
		last_error=NULL,completed_at_unix_ms=NULL,updated_at_unix_ms=?
		WHERE json_type(request_json,'$.group')='object' AND json_extract(request_json,'$.group.externalId')=? AND request_digest<>? AND ` + guard
	args := append([]any{encoded, digest, now.UnixMilli(), now.UnixMilli(), externalID, digest}, guardArgs...)
	return rhiza.SQLStatement{SQL: sql, Args: args}, nil
}

// EnqueueTombstoneDelete admits a delete only while its exact tombstone
// generation and provider snapshot still exist. The boolean reports admission;
// a false result means cleanup or replacement won the race.
func (o *Outbox) EnqueueTombstoneDelete(ctx context.Context, clientID string, user User, policy DeletePolicy, deletionGeneration string, now time.Time) (Job, bool, error) {
	request := Request{User: user, Delete: true, DeletePolicy: policy}
	if err := o.valid(); err != nil || ctx == nil || !validOutboxClientID(clientID) || !validTombstoneGeneration(deletionGeneration) {
		return Job{}, false, ErrOutboxInvalid
	}
	if err := validateRequest(request); err != nil {
		return Job{}, false, err
	}
	now = o.time(now)
	if !validOutboxTime(now) {
		return Job{}, false, ErrOutboxInvalid
	}
	encoded, digest, err := encodeRequestWithTombstoneGeneration(request, deletionGeneration)
	if err != nil {
		return Job{}, false, err
	}
	externalID := requestExternalID(request)
	jobID := outboxJobID(clientID, externalID)
	response, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: o.mutationID("sco/t", jobID, digest, deletionGeneration, fmt.Sprint(now.UnixMilli())), Statements: []rhiza.SQLStatement{{SQL: `INSERT INTO scim_user_outbox
		(job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,created_at_unix_ms,updated_at_unix_ms)
		SELECT ?,?,?,?,?, 'pending',0,?,1,?,?
		WHERE EXISTS (SELECT 1 FROM scim_user_tombstones t JOIN scim_user_tombstone_providers p ON p.local_external_id=t.local_external_id
			WHERE t.local_external_id=? AND t.generation=? AND t.provider_snapshot_complete=1
			AND p.client_id=? AND p.delete_policy=? AND (t.hard_delete=0 OR p.delete_policy=?))
		ON CONFLICT(client_id,external_id) DO UPDATE SET
			request_json=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN excluded.request_json ELSE scim_user_outbox.request_json END,
			request_digest=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN excluded.request_digest ELSE scim_user_outbox.request_digest END,
			revision=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN scim_user_outbox.revision+1 ELSE scim_user_outbox.revision END,
			status=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest AND scim_user_outbox.status<>'processing' THEN 'pending' ELSE scim_user_outbox.status END,
			attempts=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest AND scim_user_outbox.status<>'processing' THEN 0 ELSE scim_user_outbox.attempts END,
			next_attempt_at_unix_ms=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest AND scim_user_outbox.status<>'processing' THEN excluded.next_attempt_at_unix_ms ELSE scim_user_outbox.next_attempt_at_unix_ms END,
			lease_token=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest AND scim_user_outbox.status<>'processing' THEN NULL ELSE scim_user_outbox.lease_token END,
			lease_until_unix_ms=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest AND scim_user_outbox.status<>'processing' THEN NULL ELSE scim_user_outbox.lease_until_unix_ms END,
			last_error=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN NULL ELSE scim_user_outbox.last_error END,
			completed_at_unix_ms=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN NULL ELSE scim_user_outbox.completed_at_unix_ms END,
			updated_at_unix_ms=CASE WHEN scim_user_outbox.request_digest <> excluded.request_digest THEN excluded.updated_at_unix_ms ELSE scim_user_outbox.updated_at_unix_ms END
		RETURNING job_id`, Args: []any{jobID, clientID, externalID, encoded, digest, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), user.ExternalID, deletionGeneration, clientID, int64(policy), int64(DeleteRemote)}, WantRows: true}}})
	if err != nil {
		return Job{}, false, err
	}
	if len(response.Statements) != 1 || len(response.Statements[0].Rows) > 1 {
		return Job{}, false, ErrOutboxInvalid
	}
	if len(response.Statements[0].Rows) == 0 {
		return Job{}, false, nil
	}
	job, found, err := o.lookup(ctx, jobID)
	if err != nil {
		return Job{}, true, err
	}
	if !found {
		return Job{}, true, errors.New("scim tombstone enqueue committed without a row")
	}
	return job, true, nil
}

// Step claims and reconciles at most one due job. It is safe for concurrent
// workers; success, retry, and dead-letter writes all use the lease token and
// revision as compare-and-swap guards. Delivery is at-least-once across a
// process suspension or crash; externalId reconciliation recovers duplicates.
func (o *Outbox) Step(ctx context.Context, now time.Time) error {
	if err := o.valid(); err != nil {
		return err
	}
	if o.Resolve == nil || ctx == nil {
		return ErrOutboxInvalid
	}
	if now.IsZero() {
		now = o.Now()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now = o.time(now)
	if !validOutboxTime(now) {
		return ErrOutboxInvalid
	}
	attemptCtx, cancel := context.WithTimeout(ctx, o.RequestTimeout)
	defer cancel()
	job, found, err := o.claim(attemptCtx, now, ctx)
	if err != nil || !found {
		return err
	}
	client, err := o.Resolve(attemptCtx, job.ClientID)
	if err != nil || client == nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return o.finish(ctx, job, now, false, false, "client unavailable")
	}
	request := job.Request
	mappedID := ""
	if request.Group.ExternalID == "" && request.Delete && o.Mapping != nil {
		mappedID, _, err = o.Mapping.Lookup(attemptCtx, job.ClientID, request.User.ExternalID)
		if err != nil {
			return o.finish(ctx, job, now, false, false, "remote user mapping unavailable")
		}
		request.remoteID = mappedID
	}
	result, err := client.Reconcile(attemptCtx, request)
	if err == nil {
		if o.beforeFinish != nil {
			o.beforeFinish()
		}
		if job.Request.Group.ExternalID == "" && !job.Request.Delete && o.Mapping != nil && validRemoteID(result.RemoteID) != nil {
			return o.finish(ctx, job, now, false, true, "missing or invalid remote user id")
		}
		return o.finishSuccess(ctx, job, result.RemoteID, mappedID, now)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Client transport failures and HTTP 429/5xx are ErrRetryable; generic
	// reconciler failures retain the conservative historical retry behavior.
	permanent := !errors.Is(err, ErrRetryable) && (errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrInvalidUser) || errors.Is(err, ErrProtocol) || errors.Is(err, ErrAmbiguous) || errors.Is(err, ErrIdentifierChanged))
	return o.finish(ctx, job, now, false, permanent, "reconcile failed")
}

// Cleanup removes at most limit terminal rows older than Retention. Completed
// user deletes stay until their tombstone is gone so the tombstone remains the
// durable record of the associated remote-delete outcome. A group projection
// stays while its local group or role exists, because that row is the durable
// evidence a remote group exists and a later local deletion turns it into a
// provider-scoped delete.
func (o *Outbox) Cleanup(ctx context.Context, now time.Time, limit int) (int, error) {
	if err := o.valid(); err != nil {
		return 0, err
	}
	if ctx == nil {
		return 0, ErrOutboxInvalid
	}
	if limit <= 0 {
		limit = o.CleanupLimit
	}
	if limit <= 0 || limit > 4096 {
		return 0, ErrOutboxInvalid
	}
	now = o.time(now)
	if !validOutboxTime(now) {
		return 0, ErrOutboxInvalid
	}
	cutoff := now.Add(-o.Retention).UnixMilli()
	randomID, err := o.randomToken()
	if err != nil {
		return 0, err
	}
	seq := atomic.AddUint64(&o.cleanupSeq, 1)
	response, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: o.mutationID("sco/x", randomID, fmt.Sprint(seq), fmt.Sprint(cutoff), fmt.Sprint(limit)), SQL: `DELETE FROM scim_user_outbox WHERE job_id IN
		(SELECT job_id FROM scim_user_outbox WHERE status IN ('succeeded','dead') AND completed_at_unix_ms <= ?
			AND NOT (json_type(request_json,'$.group') IS NULL AND json_extract(request_json,'$.delete')=1
				AND EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id=json_extract(request_json,'$.user.externalId')))
			AND NOT (json_type(request_json,'$.group')='object' AND (
				EXISTS (SELECT 1 FROM rbac_groups g WHERE json_extract(request_json,'$.group.externalId')='group:'||g.id)
				OR EXISTS (SELECT 1 FROM rbac_roles r WHERE json_extract(request_json,'$.group.externalId')='role:'||r.id)))
			ORDER BY completed_at_unix_ms,job_id LIMIT ?)`, Args: []any{cutoff, int64(limit)}})
	if err != nil {
		return 0, err
	}
	return int(response.MutationReceipt.RowsAffected), nil
}

// Lookup returns one coalesced job by client and externalId.
func (o *Outbox) Lookup(ctx context.Context, clientID, externalID string) (Job, bool, error) {
	if err := o.valid(); err != nil || ctx == nil || !validOutboxClientID(clientID) || !validIdentifier(externalID) {
		return Job{}, false, ErrOutboxInvalid
	}
	job, found, err := o.lookup(ctx, outboxJobID(clientID, userStorageKey(externalID)))
	if err != nil || found {
		return job, found, err
	}
	job, found, err = o.lookup(ctx, outboxJobID(clientID, externalID))
	if err != nil || found {
		return job, found, err
	}
	return o.lookup(ctx, outboxJobID(clientID, groupStorageKey(externalID)))
}

func (o *Outbox) LookupGroup(ctx context.Context, clientID, externalID string) (Job, bool, error) {
	if !validIdentifier(externalID) {
		return Job{}, false, ErrOutboxInvalid
	}
	return o.lookup(ctx, outboxJobID(clientID, groupStorageKey(externalID)))
}

type outboxCandidate struct {
	jobID, clientID, externalID, requestDigest string
	revision                                   int64
}

func (o *Outbox) nextCandidate(ctx context.Context, now time.Time) (outboxCandidate, bool, error) {
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT job_id,client_id,external_id,request_digest,revision FROM scim_user_outbox
		WHERE ((status='pending' AND next_attempt_at_unix_ms <= ?) OR (status='processing' AND lease_until_unix_ms <= ?))
		AND ` + claimableUserSQL() + `
		ORDER BY CASE WHEN json_type(request_json,'$.group')='object' THEN 1 ELSE 0 END,next_attempt_at_unix_ms,job_id LIMIT 1`, Args: []any{now.UnixMilli(), now.UnixMilli()}, Consistency: rhiza.ConsistencyLocal})
	if err != nil {
		return outboxCandidate{}, false, err
	}
	if len(result.Rows) == 0 {
		return outboxCandidate{}, false, nil
	}
	if len(result.Rows[0]) != 5 {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	c := outboxCandidate{}
	var ok bool
	if c.jobID, ok = result.Rows[0][0].(string); !ok || c.jobID == "" {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	if c.clientID, ok = result.Rows[0][1].(string); !ok || !validOutboxClientID(c.clientID) {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	if c.externalID, ok = result.Rows[0][2].(string); !ok || !validIdentifier(c.externalID) {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	if c.requestDigest, ok = result.Rows[0][3].(string); !ok || c.requestDigest == "" {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	if c.revision, ok = result.Rows[0][4].(int64); !ok || c.revision <= 0 {
		return outboxCandidate{}, false, ErrOutboxInvalid
	}
	return c, true, nil
}

func (o *Outbox) claim(ctx context.Context, now time.Time, stateContexts ...context.Context) (Job, bool, error) {
	c, found, err := o.nextCandidate(ctx, now)
	if err != nil || !found {
		return Job{}, false, err
	}
	if o.beforeClaim != nil {
		o.beforeClaim()
	}
	lease, err := o.randomToken()
	if err != nil {
		return Job{}, false, err
	}
	response, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: o.mutationID("sco/c", c.jobID, lease, fmt.Sprint(now.UnixMilli())), SQL: `UPDATE scim_user_outbox SET status='processing',attempts=attempts+1,lease_token=?,lease_until_unix_ms=?,updated_at_unix_ms=?
		WHERE job_id=? AND attempts < ? AND ((status='pending' AND next_attempt_at_unix_ms <= ?) OR (status='processing' AND lease_until_unix_ms <= ?)) AND ` + claimableUserSQL(), Args: []any{lease, now.Add(o.LeaseDuration).UnixMilli(), now.UnixMilli(), c.jobID, int64(o.MaxAttempts), now.UnixMilli(), now.UnixMilli()}})
	if err != nil {
		return Job{}, false, err
	}
	if response.MutationReceipt.RowsAffected != 1 {
		// A crashed final attempt must not be reclaimed into an endless loop.
		stateCtx := ctx
		if len(stateContexts) != 0 && stateContexts[0] != nil {
			stateCtx = stateContexts[0]
		}
		_, deadErr := o.deadLetterExpired(stateCtx, c, now)
		if deadErr != nil {
			return Job{}, false, deadErr
		}
		return Job{}, false, nil
	}
	job, found, err := o.lookupOwned(ctx, c.jobID, lease)
	if err != nil || !found {
		return Job{}, false, err
	}
	job.leaseToken = lease
	return job, true, nil
}

func (o *Outbox) deadLetterExpired(ctx context.Context, c outboxCandidate, now time.Time) (rhiza.ExecuteResponse, error) {
	where := `job_id=? AND request_digest=? AND revision=? AND attempts >= ? AND ((status='pending' AND next_attempt_at_unix_ms <= ?) OR (status='processing' AND lease_until_unix_ms <= ?)) AND ` + claimableUserSQL()
	args := []any{c.jobID, c.requestDigest, c.revision, int64(o.MaxAttempts), now.UnixMilli(), now.UnixMilli()}
	// This read supplies the payload only. Every witness is checked again in
	// the transaction; a stale candidate remains a successful no-op.
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,last_error,created_at_unix_ms,updated_at_unix_ms,completed_at_unix_ms,lease_token FROM scim_user_outbox WHERE ` + where, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) == 0 {
		return rhiza.ExecuteResponse{}, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 14 {
		return rhiza.ExecuteResponse{}, ErrOutboxInvalid
	}
	job, err := decodeJob(result.Rows[0][:13])
	if err != nil {
		return rhiza.ExecuteResponse{}, err
	}
	where += ` AND attempts=? AND created_at_unix_ms=? AND lease_token IS ?`
	args = append(args, int64(job.Attempts), job.CreatedAt.UnixMilli(), result.Rows[0][13])
	requestID := outboxRequestID("sco/d", rand.Text())
	event, err := eventlog.ScimFailure(requestID, job.ClientID, scimFailureAction(job.Request), int64(job.Attempts), now).Statement(`EXISTS (SELECT 1 FROM scim_user_outbox WHERE `+where+`)`, args...)
	if err != nil {
		return rhiza.ExecuteResponse{}, err
	}
	stmt := rhiza.SQLStatement{SQL: `UPDATE scim_user_outbox SET status='dead',lease_token=NULL,lease_until_unix_ms=NULL,last_error='maximum attempts reached',completed_at_unix_ms=?,updated_at_unix_ms=? WHERE ` + where, Args: append([]any{now.UnixMilli(), now.UnixMilli()}, args...)}
	return storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: requestID, Statements: []rhiza.SQLStatement{event, stmt}})
}

// claimableUserSQL deliberately permits group and deletion work. A live-user
// job must still exactly match the current identity projection: tombstone
// cleanup may remove its marker before an old queued projection is claimed.
func claimableUserSQL() string {
	return `(json_type(request_json,'$.group')='object' OR
		(json_extract(request_json,'$.delete')=1 AND EXISTS (SELECT 1 FROM scim_user_tombstones t JOIN scim_user_tombstone_providers p ON p.local_external_id=t.local_external_id
			WHERE t.local_external_id=json_extract(request_json,'$.user.externalId')
			AND json_extract(request_json,'$.tombstoneGeneration') IS NOT NULL
			AND length(json_extract(request_json,'$.tombstoneGeneration'))=22
			AND t.generation=json_extract(request_json,'$.tombstoneGeneration')
			AND t.provider_snapshot_complete=1 AND p.client_id=scim_user_outbox.client_id
			AND p.delete_policy=json_extract(request_json,'$.deletePolicy')
			AND (t.hard_delete=0 OR p.delete_policy=1))) OR
		((json_type(request_json,'$.delete') IS NULL OR json_extract(request_json,'$.delete')=0)
		AND EXISTS (SELECT 1 FROM identity_users u JOIN identity_authentication_modes m ON m.subject=u.subject
			WHERE u.subject=json_extract(request_json,'$.user.externalId')
			AND u.username=json_extract(request_json,'$.user.userName')
			AND json_extract(request_json,'$.user.active')=CASE WHEN u.disabled=0 AND (m.mode='passkey' OR (m.mode='password' AND u.password_phc<>'')) THEN 1 ELSE 0 END)
		AND NOT EXISTS (SELECT 1 FROM scim_user_tombstones WHERE local_external_id=json_extract(request_json,'$.user.externalId'))))`
}

func (o *Outbox) finish(ctx context.Context, job Job, now time.Time, success, permanent bool, reason string) error {
	if success {
		return o.finishSuccess(ctx, job, "", "", now)
	}
	attempts := job.Attempts
	dead := permanent || attempts >= o.MaxAttempts
	status := "pending"
	if dead {
		status = "dead"
	}
	next := now.Add(o.retryDelay(job, attempts)).UnixMilli()
	completed := "NULL"
	if dead {
		completed = "?"
	}
	sql := fmt.Sprintf(`UPDATE scim_user_outbox SET status=CASE WHEN revision=? THEN '%s' ELSE 'pending' END,
		attempts=CASE WHEN revision=? THEN ? ELSE 0 END,next_attempt_at_unix_ms=CASE WHEN revision=? THEN ? ELSE ? END,lease_token=NULL,lease_until_unix_ms=NULL,last_error=CASE WHEN revision=? THEN ? ELSE NULL END,
		completed_at_unix_ms=CASE WHEN revision=? THEN %s ELSE NULL END,updated_at_unix_ms=?
		WHERE job_id=? AND status='processing' AND lease_token=?`, status, completed)
	args := []any{job.Revision, job.Revision, attempts, job.Revision, next, now.UnixMilli(), job.Revision, safeOutboxError(reason), job.Revision}
	if dead {
		args = append(args, now.UnixMilli())
	}
	args = append(args, now.UnixMilli(), job.ID, job.leaseToken)
	one := int64(1)
	// Each completion invocation has an independent identity, including after
	// outbox cleanup/recreation. Rhiza retries this same request; the lease and
	// revision predicates, not a time-derived ID, decide which event can commit.
	request := rhiza.ExecuteRequest{RequestID: outboxRequestID("sco/f", rand.Text()), Statements: []rhiza.SQLStatement{{SQL: sql, Args: args, ExpectedRowsAffected: &one}}}
	if attempts >= o.MaxAttempts {
		event, eventErr := eventlog.ScimFailure(request.RequestID, job.ClientID, scimFailureAction(job.Request), int64(attempts), now).Statement(`EXISTS (SELECT 1 FROM scim_user_outbox WHERE job_id=? AND status='processing' AND lease_token=? AND revision=? AND request_digest=? AND attempts=? AND `+claimableUserSQL()+`)`, job.ID, job.leaseToken, job.Revision, job.requestDigest, int64(attempts))
		if eventErr != nil {
			return eventErr
		}
		request.Statements = []rhiza.SQLStatement{event, request.Statements[0]}
	}
	response, err := storage.Execute(ctx, o.DB, request)
	if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return ErrOutboxLease
	}
	if err != nil {
		return err
	}
	return nil
}

func scimFailureAction(request Request) string {
	if request.Group.ExternalID != "" {
		action := "GroupCreateUpdate"
		if request.Delete {
			action = "GroupDelete"
		}
		return action + "(" + strconv.Quote(request.Group.ExternalID) + ")"
	}
	if request.Delete {
		return "UserDelete(" + strconv.Quote(request.User.ExternalID) + ")"
	}
	return "UserCreateUpdate(" + strconv.Quote(request.User.ExternalID) + ")"
}

// finishSuccess atomically applies the provider-scoped mapping and releases
// the lease. A stale completion can only release its row back to pending: its
// mapping statement is fenced by the original digest, revision, and lease.
func (o *Outbox) finishSuccess(ctx context.Context, job Job, remoteID, mappedID string, now time.Time) error {
	statements := make([]rhiza.SQLStatement, 0, 2)
	where := `job_id=? AND status='processing' AND lease_token=?`
	terminalArgs := []any{job.Revision, job.Revision, now.UnixMilli(), job.Revision, now.UnixMilli(), now.UnixMilli(), job.ID, job.leaseToken}
	terminal := `UPDATE scim_user_outbox SET status=CASE WHEN revision=? THEN 'succeeded' ELSE 'pending' END,
		attempts=CASE WHEN revision=? THEN attempts ELSE 0 END,next_attempt_at_unix_ms=?,lease_token=NULL,lease_until_unix_ms=NULL,last_error=NULL,
		completed_at_unix_ms=CASE WHEN revision=? THEN ? ELSE NULL END,updated_at_unix_ms=? WHERE ` + where
	if job.Request.Group.ExternalID == "" && o.Mapping != nil {
		if o.Mapping.DB != o.DB {
			return ErrOutboxInvalid
		}
		fence := `EXISTS (SELECT 1 FROM scim_user_outbox WHERE job_id=? AND status='processing' AND lease_token=? AND revision=? AND request_digest=?)`
		fenceArgs := []any{job.ID, job.leaseToken, job.Revision, job.requestDigest}
		if job.Request.Delete && mappedID != "" {
			statements = append(statements, rhiza.SQLStatement{SQL: `DELETE FROM scim_user_mappings WHERE client_id=? AND local_external_id=? AND remote_user_id=? AND ` + fence, Args: append([]any{job.ClientID, job.Request.User.ExternalID, mappedID}, fenceArgs...)})
			terminal += ` AND (revision<>? OR NOT EXISTS (SELECT 1 FROM scim_user_mappings WHERE client_id=? AND local_external_id=?))`
			terminalArgs = append(terminalArgs, job.Revision, job.ClientID, job.Request.User.ExternalID)
		} else if !job.Request.Delete {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO scim_user_mappings (client_id,local_external_id,remote_user_id,updated_at_unix_ms)
				SELECT ?,?,?,? WHERE ` + fence + ` ON CONFLICT(client_id,local_external_id) DO UPDATE SET updated_at_unix_ms=excluded.updated_at_unix_ms WHERE remote_user_id=excluded.remote_user_id`, Args: append([]any{job.ClientID, job.Request.User.ExternalID, remoteID, now.UnixMilli()}, fenceArgs...)})
			terminal += ` AND (revision<>? OR EXISTS (SELECT 1 FROM scim_user_mappings WHERE client_id=? AND local_external_id=? AND remote_user_id=?))`
			terminalArgs = append(terminalArgs, job.Revision, job.ClientID, job.Request.User.ExternalID, remoteID)
		}
	}
	statements = append(statements, rhiza.SQLStatement{SQL: terminal, Args: terminalArgs})
	response, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{RequestID: o.mutationID("sco/s", job.ID, fmt.Sprint(job.Revision)), Statements: statements})
	if err != nil {
		return err
	}
	// Mapping and terminal statements share one receipt, whose count is their
	// sum. A positive total is sufficient: the terminal predicate is identical
	// to the mapping fence (or is the sole statement).
	if response.MutationReceipt.RowsAffected == 0 {
		return ErrOutboxLease
	}
	return nil
}

func (o *Outbox) retryDelay(job Job, attempt int) time.Duration {
	if o.RetryBase <= 0 {
		return 0
	}
	// Deterministic bounded exponential delay avoids synchronized retries
	// without adding another random source to persisted state.
	d := o.RetryBase
	for i := 1; i < attempt && d < maxRetryDelay; i++ {
		if d > maxRetryDelay/2 {
			d = maxRetryDelay
			break
		}
		d *= 2
	}
	if d > maxRetryDelay {
		d = maxRetryDelay
	}
	sum := sha256.Sum256([]byte(job.ID + "/" + fmt.Sprint(attempt)))
	remaining := maxRetryDelay - d
	jitterBase := o.RetryBase
	if jitterBase > remaining {
		jitterBase = remaining
	}
	return d + time.Duration(uint64(sum[0])%uint64(jitterBase+1))
}

func (o *Outbox) lookup(ctx context.Context, jobID string) (Job, bool, error) {
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT job_id,client_id,external_id,request_json,request_digest,status,attempts,next_attempt_at_unix_ms,revision,last_error,created_at_unix_ms,updated_at_unix_ms,completed_at_unix_ms FROM scim_user_outbox WHERE job_id=?`, Args: []any{jobID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Job{}, false, err
	}
	if len(result.Rows) == 0 {
		return Job{}, false, nil
	}
	job, err := decodeJob(result.Rows[0])
	return job, err == nil, err
}

func (o *Outbox) lookupOwned(ctx context.Context, jobID, lease string) (Job, bool, error) {
	job, found, err := o.lookup(ctx, jobID)
	if err != nil || !found {
		return Job{}, found, err
	}
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT lease_token FROM scim_user_outbox WHERE job_id=? AND status='processing' AND lease_token=?`, Args: []any{jobID, lease}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Job{}, false, err
	}
	return job, len(result.Rows) == 1, nil
}

func decodeJob(row []any) (Job, error) {
	if len(row) != 13 {
		return Job{}, ErrOutboxInvalid
	}
	job := Job{}
	var ok bool
	if job.ID, ok = row[0].(string); !ok || job.ID == "" {
		return Job{}, ErrOutboxInvalid
	}
	if job.ClientID, ok = row[1].(string); !ok || !validOutboxClientID(job.ClientID) {
		return Job{}, ErrOutboxInvalid
	}
	externalID, ok := row[2].(string)
	if !ok || !validIdentifier(externalID) {
		return Job{}, ErrOutboxInvalid
	}
	if job.ID != outboxJobID(job.ClientID, externalID) {
		return Job{}, ErrOutboxInvalid
	}
	encodedRequest, encodedOK := row[3].(string)
	if !encodedOK {
		return Job{}, ErrOutboxInvalid
	}
	request, err := decodeRequest(encodedRequest)
	if err != nil || (requestExternalID(request) != externalID && !(request.Group.ExternalID == "" && request.User.ExternalID == externalID)) {
		return Job{}, ErrOutboxInvalid
	}
	storedDigest, digestOK := row[4].(string)
	if !digestOK || storedDigest != digestString(encodedRequest) {
		return Job{}, ErrOutboxInvalid
	}
	job.Request = request
	job.requestDigest = storedDigest
	if job.Status, ok = row[5].(string); !ok || (job.Status != "pending" && job.Status != "processing" && job.Status != "succeeded" && job.Status != "dead") {
		return Job{}, ErrOutboxInvalid
	}
	if job.Attempts, ok = intValue(row[6]); !ok || job.Attempts < 0 {
		return Job{}, ErrOutboxInvalid
	}
	next, ok := row[7].(int64)
	if !ok || next < 0 {
		return Job{}, ErrOutboxInvalid
	}
	job.NextAttemptAt = time.UnixMilli(next).UTC()
	if job.Revision, ok = row[8].(int64); !ok || job.Revision <= 0 {
		return Job{}, ErrOutboxInvalid
	}
	if row[9] != nil {
		if job.LastError, ok = row[9].(string); !ok {
			return Job{}, ErrOutboxInvalid
		}
	}
	created, createdOK := row[10].(int64)
	updated, updatedOK := row[11].(int64)
	if !createdOK || !updatedOK || created < 0 || updated < created {
		return Job{}, ErrOutboxInvalid
	}
	job.CreatedAt, job.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	if row[12] != nil {
		completed, completedOK := row[12].(int64)
		if !completedOK || completed < created {
			return Job{}, ErrOutboxInvalid
		}
		value := time.UnixMilli(completed).UTC()
		job.CompletedAt = &value
	}
	return job, nil
}

type encodedRequest struct {
	Operation           string       `json:"operation,omitempty"`
	User                User         `json:"user"`
	Group               *Group       `json:"group,omitempty"`
	Delete              bool         `json:"delete,omitempty"`
	DeletePolicy        DeletePolicy `json:"deletePolicy,omitempty"`
	TombstoneGeneration string       `json:"tombstoneGeneration,omitempty"`
}

func encodeRequest(request Request) (string, string, error) {
	return encodeRequestWithTombstoneGenerationVersion(request, "", true)
}

func encodeRequestVersion(request Request, operation bool) (string, string, error) {
	return encodeRequestWithTombstoneGenerationVersion(request, "", operation)
}

func encodeRequestWithTombstoneGeneration(request Request, generation string) (string, string, error) {
	return encodeRequestWithTombstoneGenerationVersion(request, generation, true)
}

func encodeRequestWithTombstoneGenerationVersion(request Request, generation string, operation bool) (string, string, error) {
	if err := validateRequest(request); err != nil {
		return "", "", err
	}
	if generation != "" && (!request.Delete || !validTombstoneGeneration(generation)) {
		return "", "", ErrOutboxInvalid
	}
	var group *Group
	if request.Group.ExternalID != "" {
		group = &request.Group
	}
	op := ""
	if operation {
		op = "sync"
		if request.Delete {
			op = "delete"
		}
	}
	b, err := json.Marshal(encodedRequest{Operation: op, User: request.User, Group: group, Delete: request.Delete, DeletePolicy: request.DeletePolicy, TombstoneGeneration: generation})
	if err != nil {
		return "", "", ErrOutboxInvalid
	}
	if len(b) > 16384 {
		if group != nil {
			// Only a group projection grows with the size of its local
			// membership, so the oversize request is a group size failure.
			return "", "", fmt.Errorf("%w: %w", ErrOutboxInvalid, ErrGroupTooLarge)
		}
		return "", "", ErrOutboxInvalid
	}
	return string(b), digestString(string(b)), nil
}

func decodeRequest(value any) (Request, error) {
	encoded, ok := value.(string)
	if !ok || len(encoded) > 16384 {
		return Request{}, ErrOutboxInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var stored encodedRequest
	if err := decoder.Decode(&stored); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Request{}, ErrOutboxInvalid
	}
	request := Request{User: stored.User, Delete: stored.Delete, DeletePolicy: stored.DeletePolicy}
	if stored.Group != nil {
		request.Group = *stored.Group
	}
	wantOperation := "sync"
	if request.Delete {
		wantOperation = "delete"
	}
	if stored.Operation != "" && stored.Operation != wantOperation {
		return Request{}, ErrOutboxInvalid
	}
	if _, digest, err := encodeRequestWithTombstoneGenerationVersion(request, stored.TombstoneGeneration, stored.Operation != ""); err != nil || digest != digestString(encoded) {
		return Request{}, ErrOutboxInvalid
	}
	return request, nil
}

func validateRequest(request Request) error {
	if request.Group.ExternalID != "" {
		if err := validateGroup(request.Group); err != nil {
			return err
		}
	} else if err := validateUser(request.User); err != nil {
		return err
	}
	if request.Delete && request.DeletePolicy != DeleteRemote && request.DeletePolicy != UnlinkRemote {
		return ErrOutboxInvalid
	}
	if !request.Delete && request.DeletePolicy != 0 {
		return ErrOutboxInvalid
	}
	return nil
}

func requestExternalID(request Request) string {
	if request.Group.ExternalID != "" {
		return groupStorageKey(request.Group.ExternalID)
	}
	return userStorageKey(request.User.ExternalID)
}

func userStorageKey(externalID string) string { return storageKey("user:", externalID) }

func groupStorageKey(externalID string) string { return storageKey("group:", externalID) }

func storageKey(prefix, externalID string) string {
	key := prefix + externalID
	if len(key) <= 512 {
		return key
	}
	return prefix[:1] + digestString(externalID)
}

func (o *Outbox) valid() error {
	if o == nil {
		return ErrOutboxInvalid
	}
	o.defaults()
	if o.DB == nil || o.LeaseDuration <= 0 || o.LeaseDuration > maxOutboxLease || o.RequestTimeout <= 0 || o.RequestTimeout >= o.LeaseDuration || o.RequestTimeout > maxRequestTimeout || o.RetryBase <= 0 || o.RetryBase > maxRetryBase || o.MaxAttempts <= 0 || o.MaxAttempts > maxAttempts || o.Retention <= 0 || o.Retention > maxRetention {
		return ErrOutboxInvalid
	}
	return nil
}

func validOutboxTime(value time.Time) bool {
	ms := value.UnixMilli()
	return ms >= 0 && ms <= math.MaxInt64-int64(maxOutboxLease/time.Millisecond)
}

func (o *Outbox) time(now time.Time) time.Time {
	if now.IsZero() {
		now = o.Now()
	}
	return now.UTC().Truncate(time.Millisecond)
}

func (o *Outbox) randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(o.Random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func outboxJobID(clientID, externalID string) string {
	return digestString(clientID + "\x00" + externalID)
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func outboxRequestID(prefix string, values ...string) string {
	return prefix + "/" + digestString(strings.Join(values, "\x00"))[:32]
}

func (o *Outbox) mutationID(prefix string, values ...string) string {
	seq := atomic.AddUint64(&o.mutationSeq, 1)
	return outboxRequestID(prefix, append(values, fmt.Sprint(seq))...)
}

func validOutboxClientID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}

func validTombstoneGeneration(value string) bool {
	return len(value) == 22 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}

func intValue(value any) (int, bool) {
	n, ok := value.(int64)
	if !ok || n < 0 || n > int64(^uint(0)>>1) {
		return 0, false
	}
	return int(n), true
}

func safeOutboxError(value string) string {
	if len(value) > maxOutboxErrorLength {
		value = value[:maxOutboxErrorLength]
	}
	return value
}
