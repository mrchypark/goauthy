package notify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type RhizaQueue struct {
	DB      *rhiza.DB
	allowed map[string]bool
}

// cleanupBatchSize bounds a single replicated delivery-cleanup mutation.
const cleanupBatchSize = 1000

// NewRhizaQueue reconciles the persisted destinations with the configured set
// under a durable configuration generation. The generation is claimed and
// applied in one replicated request, so a pod that restarts on a superseded
// configuration reconciles nothing: it can neither re-enable a destination the
// current generation retired nor resurrect its old level. Bump
// GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION whenever the destination set or a
// level changes; an unchanged generation keeps the last-writer-wins behaviour
// that a single-deployment restart needs to re-apply its own configuration.
func NewRhizaQueue(ctx context.Context, db *rhiza.DB, targets []Target, generation int64) (*RhizaQueue, error) {
	if db == nil {
		return nil, errors.New("notification queue requires database")
	}
	if ctx == nil {
		return nil, errors.New("notification queue requires context")
	}
	if generation < 1 {
		return nil, errors.New("notification queue requires a positive configuration generation")
	}
	seen := map[string]bool{}
	stmts := make([]rhiza.SQLStatement, 0, len(targets)+2)
	allowed := map[string]bool{}
	names := make([]any, 0, len(targets))
	// The generation claim runs first so the guarded writes below observe the
	// stored generation this request already advanced.
	stmts = append(stmts, claimGeneration(generation))
	for _, t := range targets {
		if t.Name == "" || t.Kind == "" || !t.Level.Valid() {
			return nil, errors.New("invalid notification target")
		}
		if seen[t.Name] {
			return nil, errors.New("duplicate notification target")
		}
		seen[t.Name] = true
		allowed[t.Name] = true
		names = append(names, t.Name)
		// The gate sits in the SELECT so a superseded generation inserts nothing
		// and updates nothing: with no candidate row the conflict clause never
		// runs, which keeps a retired destination disabled and its old level gone.
		// The row also carries the claimed generation, because v109 rejects at the
		// database boundary any destination write that does not: a legacy binary's
		// unconditional upsert cannot name this column, so it aborts instead of
		// re-enabling a retired destination or rolling a level back.
		stmts = append(stmts, rhiza.SQLStatement{SQL: `INSERT INTO event_notification_targets(target,level,enabled,generation) SELECT ?,?,1,? WHERE ` + currentGenerationSQL + ` ON CONFLICT(target) DO UPDATE SET level=excluded.level,enabled=1,generation=excluded.generation WHERE ` + currentGenerationSQL, Args: []any{t.Name, int64(t.Level.Rank()), generation, generation, generation}})
	}
	// A destination dropped from configuration must stop queueing: the enqueue
	// trigger reads this table, so a still-enabled row keeps replicating
	// deliveries that no worker can claim.
	stmts = append(stmts, retireTargets(names, generation))
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "notify-config/" + base64.RawURLEncoding.EncodeToString(token), Statements: stmts}); err != nil {
		return nil, err
	}
	return &RhizaQueue{DB: db, allowed: allowed}, nil
}

// currentGenerationSQL gates a reconciliation write on the stored configuration
// generation. A statement whose generation is no longer current matches no row,
// so a pod that restarts on a superseded configuration leaves the destinations
// the current generation retired disabled (GA66-NOTIFY-003).
const currentGenerationSQL = `(SELECT generation FROM event_notification_config_generation WHERE config_id=1) = ?`

// claimGeneration moves the stored configuration generation forward. max() keeps
// it monotonic, so a stale pod can never lower it and then satisfy its own gate,
// while the row itself always exists to be claimed: a missing singleton rejects
// the whole request instead of silently reconciling nothing.
func claimGeneration(generation int64) rhiza.SQLStatement {
	one := int64(1)
	return rhiza.SQLStatement{SQL: `UPDATE event_notification_config_generation SET generation=max(generation,?) WHERE config_id=1`, Args: []any{generation}, ExpectedRowsAffected: &one}
}

// retireTargets disables persisted destinations that are absent from the
// configured set, including every destination when none is configured. Pending
// snapshots of a retired destination are left for Cleanup to age out instead of
// being deleted, so a concurrent pod sharing the destination keeps its work.
func retireTargets(names []any, generation int64) rhiza.SQLStatement {
	args := make([]any, 0, len(names)+1)
	// Retirement stamps the stored generation for the same reason the upsert
	// above names it: the v109 trigger admits only a destination write that
	// carries the stored generation, and a retired row still carries the
	// generation that retired it.
	const stamp = `,generation=(SELECT generation FROM event_notification_config_generation WHERE config_id=1)`
	// The gate's placeholder comes first, then the names.
	args = append(args, generation)
	args = append(args, names...)
	if len(names) == 0 {
		return rhiza.SQLStatement{SQL: `UPDATE event_notification_targets SET enabled=0` + stamp + ` WHERE enabled=1 AND ` + currentGenerationSQL, Args: args}
	}
	return rhiza.SQLStatement{SQL: `UPDATE event_notification_targets SET enabled=0` + stamp + ` WHERE enabled=1 AND ` + currentGenerationSQL + ` AND target NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(names)), ",") + `)`, Args: args}
}

func (q *RhizaQueue) Targets(ctx context.Context) ([]Target, error) {
	r, err := q.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT target,level FROM event_notification_targets WHERE enabled=1 ORDER BY target`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(r.Rows))
	for _, x := range r.Rows {
		n, ok := x[0].(string)
		lv, ok2 := x[1].(int64)
		if !ok || !ok2 || lv < 0 || lv > 3 {
			return nil, errors.New("invalid notification target row")
		}
		if !q.allowed[n] {
			continue
		}
		kind := strings.SplitN(n, ":", 2)[0]
		out = append(out, Target{Name: n, Kind: kind, Level: []eventlog.Level{eventlog.Info, eventlog.Notice, eventlog.Warning, eventlog.Critical}[lv]})
	}
	return out, nil
}
func (q *RhizaQueue) Claim(ctx context.Context, target string, now time.Time, limit int, lease time.Duration) ([]Delivery, error) {
	if limit < 1 || limit > 1000 || lease <= 0 {
		return nil, errors.New("invalid notification claim")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	tok := base64.RawURLEncoding.EncodeToString(token)
	until := now.Add(lease).UnixMilli()
	// Eligibility is part of the claim so a backlog below the configured
	// threshold can never delay an event that must be delivered. A changed
	// threshold affects queued rows through this predicate; explicit Test events
	// stay deliverable at every threshold.
	req := rhiza.ExecuteRequest{RequestID: "notify-claim/" + tok, SQL: `UPDATE event_notification_deliveries SET lease_token=?,lease_until_unix_ms=?,attempts=attempts+1 WHERE rowid IN (SELECT d.rowid FROM event_notification_deliveries d WHERE d.target=? AND d.delivered_at_unix_ms IS NULL AND d.next_attempt_at_unix_ms<=? AND (d.lease_until_unix_ms IS NULL OR d.lease_until_unix_ms<?) AND (d.typ='Test' OR d.level>=(SELECT level FROM event_notification_targets WHERE target=d.target)) ORDER BY d.timestamp,d.event_id LIMIT ?)`, Args: []any{tok, until, target, now.UnixMilli(), now.UnixMilli(), int64(limit)}}
	if _, err := storage.Execute(ctx, q.DB, req); err != nil {
		return nil, err
	}
	r, err := q.DB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT event_id,timestamp,level,typ,ip,data,text,attempts,lease_token FROM event_notification_deliveries WHERE target=? AND lease_token=?`, Args: []any{target, tok}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(r.Rows))
	for _, x := range r.Rows {
		e, err := rowEvent(x)
		if err != nil {
			return nil, err
		}
		a, _ := x[7].(int64)
		out = append(out, Delivery{Event: e, Lease: tok, Attempts: int(a)})
	}
	return out, nil
}
func (q *RhizaQueue) Ack(ctx context.Context, target, id, lease string, now time.Time) error {
	_, err := storage.Execute(ctx, q.DB, rhiza.ExecuteRequest{RequestID: "notify-ack/" + shortID(lease+id), SQL: `UPDATE event_notification_deliveries SET delivered_at_unix_ms=?,lease_token=NULL,lease_until_unix_ms=NULL WHERE target=? AND event_id=? AND lease_token=?`, Args: []any{now.UnixMilli(), target, id, lease}})
	return err
}

// Cleanup removes one bounded batch of delivery snapshots that are terminal or
// can no longer be delivered: acknowledged rows past retention, rows below the
// target threshold, and undelivered rows past retention. The last rule is the
// failed-delivery aging policy, because a row that keeps failing is never
// terminal. A live lease is kept so an in-flight send never loses its payload,
// while an expired lease is abandoned: a worker that died after claiming holds
// no work, so its token must not keep a payload no destination can receive
// (GA66-NOTIFY-001).
func (q *RhizaQueue) Cleanup(ctx context.Context, now time.Time, retention time.Duration) (int, error) {
	if q == nil || q.DB == nil || ctx == nil || now.IsZero() || retention <= 0 {
		return 0, errors.New("notification cleanup requires queue, context, time, and positive retention")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	leaseDeadline := now.UTC().UnixMilli()
	cutoff := now.UTC().Add(-retention).UnixMilli()
	response, err := storage.Execute(ctx, q.DB, rhiza.ExecuteRequest{
		RequestID: "notify-cleanup/" + base64.RawURLEncoding.EncodeToString(nonce[:]),
		SQL: `DELETE FROM event_notification_deliveries WHERE rowid IN (
			SELECT d.rowid FROM event_notification_deliveries d
			LEFT JOIN event_notification_targets t ON t.target=d.target
			WHERE (d.lease_token IS NULL OR d.lease_until_unix_ms<?) AND (
				(d.delivered_at_unix_ms IS NOT NULL AND d.delivered_at_unix_ms<?)
				OR (d.delivered_at_unix_ms IS NULL AND d.timestamp<?)
				OR (d.typ<>'Test' AND (t.target IS NULL OR d.level<t.level))
			)
			ORDER BY d.timestamp ASC, d.event_id ASC LIMIT ?
		)`,
		Args: []any{leaseDeadline, cutoff, cutoff, int64(cleanupBatchSize)},
	})
	if err != nil {
		return 0, err
	}
	return int(response.MutationReceipt.RowsAffected), nil
}

func (q *RhizaQueue) Fail(ctx context.Context, target, id, lease string, now time.Time, delay time.Duration, last string) error {
	if len(last) > 256 {
		last = last[:256]
	}
	_, err := storage.Execute(ctx, q.DB, rhiza.ExecuteRequest{RequestID: "notify-fail/" + shortID(lease+id), SQL: `UPDATE event_notification_deliveries SET next_attempt_at_unix_ms=?,lease_token=NULL,lease_until_unix_ms=NULL,last_error=? WHERE target=? AND event_id=? AND lease_token=?`, Args: []any{now.Add(delay).UnixMilli(), last, target, id, lease}})
	return err
}
func shortID(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:8]) }
func rowEvent(x []any) (eventlog.Event, error) {
	if len(x) != 9 {
		return eventlog.Event{}, errors.New("invalid notification row")
	}
	id, ok := x[0].(string)
	ts, ok2 := x[1].(int64)
	lv, ok3 := x[2].(int64)
	typ, ok4 := x[3].(string)
	if !ok || !ok2 || !ok3 || !ok4 || lv < 0 || lv > 3 {
		return eventlog.Event{}, errors.New("invalid notification row")
	}
	e := eventlog.Event{ID: id, Timestamp: ts, Level: []eventlog.Level{eventlog.Info, eventlog.Notice, eventlog.Warning, eventlog.Critical}[lv], Type: eventlog.Type(typ)}
	if x[4] != nil {
		v, ok := x[4].(string)
		if !ok {
			return e, errors.New("invalid notification ip")
		}
		e.IP = &v
	}
	if x[5] != nil {
		v, ok := x[5].(int64)
		if !ok {
			return e, errors.New("invalid notification data")
		}
		e.Data = &v
	}
	if x[6] != nil {
		v, ok := x[6].(string)
		if !ok {
			return e, errors.New("invalid notification text")
		}
		e.Text = &v
	}
	if _, err := e.Statement("1=1"); err != nil {
		return eventlog.Event{}, errors.New("invalid notification event")
	}
	return e, nil
}
