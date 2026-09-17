// Package audit stores the narrow durable, append-only security-event slice.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/mrchypark/rhiza"
)

const maxPageSize = 32

var ErrInvalid = errors.New("invalid audit event")

type Event struct {
	Sequence            int64
	ID                  string
	OccurredAtUnixMilli int64
	Type                string
	Action              string
	Outcome             string
	ActorKind           string
	ActorHash           string
	TargetHash          string
}

type Cursor struct {
	Sequence int64
}

type Store struct{ db *rhiza.DB }

func NewStore(db *rhiza.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Store{db: db}, nil
}

func eventIDHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func EventID(requestID string) string {
	return eventIDHash("goauthy/audit-event-id/v1\x00" + requestID)
}

// Pseudonym is domain-separated and keyed by the persisted secret digest, so
// an Events:read principal cannot dictionary-guess API-key names.
func Pseudonym(secretDigest, domain, value string) string {
	h := hmac.New(sha256.New, []byte(secretDigest))
	_, _ = h.Write([]byte("goauthy/audit/" + domain + "/v1\x00" + value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func NewEvent(requestID, eventType, action, actorKind, actorHash, targetHash string, occurredAt time.Time) Event {
	return Event{ID: EventID(requestID), OccurredAtUnixMilli: occurredAt.UTC().UnixMilli(), Type: eventType, Action: action, Outcome: "success", ActorKind: actorKind, ActorHash: actorHash, TargetHash: targetHash}
}

// Statement appends the validated event only when condition is true. Callers
// put it in the same replicated mutation as the security state change.
func (e Event) Statement(condition string, conditionArgs ...any) (rhiza.SQLStatement, error) {
	if !valid(e) || condition == "" {
		return rhiza.SQLStatement{}, ErrInvalid
	}
	args := []any{e.ID, e.OccurredAtUnixMilli, e.Type, e.Action, e.Outcome, e.ActorKind, nullable(e.ActorHash), e.TargetHash}
	args = append(args, conditionArgs...)
	return rhiza.SQLStatement{SQL: `INSERT INTO audit_events(event_id,sequence,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash) SELECT ?,(SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events),?,?,?,?,?,?,? WHERE ` + condition, Args: args}, nil
}

func (s *Store) List(ctx context.Context, cursor *Cursor, limit int) ([]Event, *Cursor, error) {
	return s.ListWhen(ctx, "1=1", nil, cursor, limit)
}

// ListWhen applies a trusted internal predicate in the same linearizable SQL
// query as pagination. It is for stores that can safely compose a guard.
func (s *Store) ListWhen(ctx context.Context, condition string, conditionArgs []any, cursor *Cursor, limit int) ([]Event, *Cursor, error) {
	if s == nil || s.db == nil || limit < 1 || limit > maxPageSize || cursor != nil && cursor.Sequence < 1 {
		return nil, nil, ErrInvalid
	}
	if condition == "" {
		return nil, nil, ErrInvalid
	}
	sql := `SELECT sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash FROM audit_events WHERE (` + condition + `)`
	args := append([]any(nil), conditionArgs...)
	if cursor != nil {
		sql += ` AND sequence<?`
		args = append(args, cursor.Sequence)
	}
	sql += ` ORDER BY sequence DESC LIMIT ?`
	args = append(args, int64(limit))
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, nil, err
	}
	events := make([]Event, 0, len(result.Rows))
	for _, row := range result.Rows {
		event, err := rowEvent(row)
		if err != nil {
			return nil, nil, ErrInvalid
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		return events, nil, nil
	}
	last := events[len(events)-1]
	return events, &Cursor{Sequence: last.Sequence}, nil
}

// ListGuarded returns an authorization marker and its page from one
// linearizable query, avoiding an authorization-read window before the page.
func (s *Store) ListGuarded(ctx context.Context, condition string, conditionArgs []any, cursor *Cursor, limit int) ([]Event, *Cursor, bool, error) {
	if s == nil || s.db == nil || condition == "" || limit < 1 || limit > maxPageSize || cursor != nil && cursor.Sequence < 1 {
		return nil, nil, false, ErrInvalid
	}
	pageCondition := ""
	args := append([]any(nil), conditionArgs...)
	if cursor != nil {
		pageCondition = ` AND sequence<?`
		args = append(args, cursor.Sequence)
	}
	args = append(args, int64(limit))
	sql := `WITH authorized AS (SELECT 1 AS ok WHERE (` + condition + `)), page AS (SELECT sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash FROM audit_events WHERE EXISTS (SELECT 1 FROM authorized)` + pageCondition + ` ORDER BY sequence DESC LIMIT ?) SELECT sequence,event_id,occurred_at_unix_ms,event_type,action,outcome,actor_kind,actor_hash,target_hash,0 AS marker FROM page UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1 AS marker FROM authorized`
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, nil, false, err
	}
	events := make([]Event, 0, len(result.Rows))
	authorized := false
	for _, row := range result.Rows {
		if len(row) != 10 {
			return nil, nil, false, ErrInvalid
		}
		marker, ok := row[9].(int64)
		if !ok {
			return nil, nil, false, ErrInvalid
		}
		if marker == 1 {
			authorized = true
			continue
		}
		if marker != 0 {
			return nil, nil, false, ErrInvalid
		}
		event, err := rowEvent(row[:9])
		if err != nil {
			return nil, nil, false, ErrInvalid
		}
		events = append(events, event)
	}
	if !authorized || len(events) == 0 {
		return events, nil, authorized, nil
	}
	last := events[len(events)-1]
	return events, &Cursor{Sequence: last.Sequence}, authorized, nil
}

func valid(e Event) bool {
	return validHash(e.ID) && e.OccurredAtUnixMilli >= 0 && validTypeAction(e.Type, e.Action) && e.Outcome == "success" && (e.ActorKind == "browser_admin" && e.ActorHash == "" || e.ActorKind == "api_key" && validHash(e.ActorHash)) && (!retirementEventType(e.Type) || e.ActorKind == "api_key") && validHash(e.TargetHash)
}

func retirementEventType(eventType string) bool {
	return eventType == "master_key_retirement.prepared" || eventType == "master_key_retirement.fenced" || eventType == "master_key_retirement.ready" || eventType == "master_key_retirement.aborted"
}

func validTypeAction(eventType, action string) bool {
	return eventType == "api_key.created" && action == "create" || eventType == "api_key.updated" && action == "update" || eventType == "api_key.deleted" && action == "delete" || eventType == "api_key.rotated" && action == "rotate" ||
		eventType == "master_key_retirement.prepared" && action == "prepare" || eventType == "master_key_retirement.fenced" && action == "fence" || eventType == "master_key_retirement.ready" && action == "ready" || eventType == "master_key_retirement.aborted" && action == "abort"
}
func validHash(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func rowEvent(row []any) (Event, error) {
	if len(row) != 9 {
		return Event{}, ErrInvalid
	}
	e := Event{}
	var ok bool
	if e.Sequence, ok = row[0].(int64); !ok || e.Sequence < 1 {
		return e, ErrInvalid
	}
	if e.ID, ok = row[1].(string); !ok {
		return e, ErrInvalid
	}
	if e.OccurredAtUnixMilli, ok = row[2].(int64); !ok {
		return e, ErrInvalid
	}
	if e.Type, ok = row[3].(string); !ok {
		return e, ErrInvalid
	}
	if e.Action, ok = row[4].(string); !ok {
		return e, ErrInvalid
	}
	if e.Outcome, ok = row[5].(string); !ok {
		return e, ErrInvalid
	}
	if e.ActorKind, ok = row[6].(string); !ok {
		return e, ErrInvalid
	}
	if row[7] != nil {
		if e.ActorHash, ok = row[7].(string); !ok {
			return e, ErrInvalid
		}
	}
	if e.TargetHash, ok = row[8].(string); !ok || !valid(e) {
		return e, ErrInvalid
	}
	return e, nil
}
