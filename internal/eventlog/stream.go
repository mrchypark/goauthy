package eventlog

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mrchypark/rhiza"
)

type StreamPage struct {
	Events     []Event
	Cursor     int64
	More       bool
	Authorized bool
}

// StreamPageGuarded reads a bounded, sequence-based page and an authorization
// marker from one linearizable snapshot. The caller supplies only a trusted SQL
// authorization predicate; user values belong in args.
func (s *Store) StreamPageGuarded(ctx context.Context, after int64, latest int, level Level, condition string, args ...any) (StreamPage, error) {
	if s == nil || s.db == nil || ctx == nil || after < -1 || latest < 0 || latest > 1000 || !level.Valid() || strings.TrimSpace(condition) == "" {
		return StreamPage{}, errors.New("invalid event stream query")
	}
	page := ""
	pageArgs := []any{}
	order := "DESC"
	if after >= 0 {
		page = ` AND o.sequence>? AND o.sequence<=h.highwater ORDER BY o.sequence ASC LIMIT 100`
		pageArgs = append(pageArgs, after)
		order = "ASC"
	} else {
		page = ` AND o.sequence<=h.highwater ORDER BY o.sequence DESC LIMIT 100`
	}
	sql := `WITH authorized AS (SELECT 1 AS ok WHERE (` + condition + `)), highwater AS (SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='event_log_order'),0) AS highwater), page AS (SELECT o.sequence,e.id,e.timestamp,e.level,e.typ,e.ip,e.data,e.text FROM event_log_order o JOIN event_log e ON e.id=o.event_id CROSS JOIN highwater h WHERE EXISTS (SELECT 1 FROM authorized)` + page + `) SELECT sequence,id,timestamp,level,typ,ip,data,text,0 AS marker,highwater FROM page CROSS JOIN highwater UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1 AS marker,highwater FROM authorized CROSS JOIN highwater ORDER BY marker ASC,sequence ` + order
	bind := append([]any(nil), args...)
	bind = append(bind, pageArgs...)
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: bind, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return StreamPage{}, err
	}
	out := StreamPage{Events: make([]Event, 0)}
	records := make([]streamRecord, 0)
	var highwater int64
	var scannedMax int64
	for _, row := range result.Rows {
		if len(row) != 10 {
			return StreamPage{}, fmt.Errorf("invalid event stream row")
		}
		marker, ok := row[8].(int64)
		if !ok {
			return StreamPage{}, fmt.Errorf("invalid event stream marker")
		}
		hw, ok := row[9].(int64)
		if !ok {
			return StreamPage{}, fmt.Errorf("invalid event stream highwater")
		}
		highwater = hw
		if marker == 1 {
			out.Authorized = true
			continue
		}
		if marker != 0 {
			return StreamPage{}, fmt.Errorf("invalid event stream marker")
		}
		seq, ok := row[0].(int64)
		if !ok {
			return StreamPage{}, fmt.Errorf("invalid event stream sequence")
		}
		if seq > scannedMax {
			scannedMax = seq
		}
		e, err := streamEvent(row[1:8])
		if err != nil {
			return StreamPage{}, err
		}
		if e.Level.Rank() >= level.Rank() {
			records = append(records, streamRecord{sequence: seq, event: e})
		}
	}
	out.Cursor = highwater
	if after >= 0 {
		out.Cursor = after
		if scannedMax > out.Cursor {
			out.Cursor = scannedMax
		}
		// Retention may delete every remaining row, including the tail. An
		// empty authorized page has exhausted this snapshot, not more work.
		if out.Authorized && scannedMax == 0 && highwater > out.Cursor {
			out.Cursor = highwater
		}
		out.More = out.Cursor < highwater
		plain := make([]Event, len(records))
		for i := range records {
			plain[i] = records[i].event
		}
		out.Events = plain
		return out, nil
	}
	if latest > len(records) {
		latest = len(records)
	}
	if latest == 0 {
		return out, nil
	}
	// Initial SQL is newest-first; return the requested newest records chronologically.
	records = records[:latest]
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	out.Events = make([]Event, len(records))
	for i := range records {
		out.Events[i] = records[i].event
	}
	return out, nil
}

type streamRecord struct {
	sequence int64
	event    Event
}

// SequenceForID returns the commit sequence for an event ID, or -1 if the ID
// is not found. The caller must not trust user-supplied IDs for authorization;
// this is purely a cursor resolution helper.
func (s *Store) SequenceForID(ctx context.Context, eventID string) (int64, error) {
	if s == nil || s.db == nil || ctx == nil || eventID == "" {
		return -1, errors.New("invalid sequence lookup")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:       `SELECT o.sequence FROM event_log_order o WHERE o.event_id=?`,
		Args:      []any{eventID},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return -1, err
	}
	if len(result.Rows) == 0 {
		return -1, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return -1, fmt.Errorf("unexpected sequence lookup result")
	}
	seq, ok := result.Rows[0][0].(int64)
	if !ok {
		return -1, fmt.Errorf("invalid sequence value")
	}
	return seq, nil
}

func streamEvent(row []any) (Event, error) {
	if len(row) != 7 {
		return Event{}, errors.New("invalid event stream event")
	}
	id, ok := row[0].(string)
	if !ok {
		return Event{}, errors.New("invalid event id")
	}
	ts, ok := row[1].(int64)
	if !ok {
		return Event{}, errors.New("invalid event timestamp")
	}
	lv, ok := row[2].(int64)
	if !ok || lv < 0 || lv > 3 {
		return Event{}, errors.New("invalid event level")
	}
	typ, ok := row[3].(string)
	if !ok {
		return Event{}, errors.New("invalid event type")
	}
	e := Event{ID: id, Timestamp: ts, Level: []Level{Info, Notice, Warning, Critical}[lv], Type: Type(typ)}
	if row[4] != nil {
		v, ok := row[4].(string)
		if !ok {
			return Event{}, errors.New("invalid event ip")
		}
		e.IP = &v
	}
	if row[5] != nil {
		v, ok := row[5].(int64)
		if !ok {
			return Event{}, errors.New("invalid event data")
		}
		e.Data = &v
	}
	if row[6] != nil {
		v, ok := row[6].(string)
		if !ok {
			return Event{}, errors.New("invalid event text")
		}
		e.Text = &v
	}
	if !e.valid() {
		return Event{}, errors.New("invalid event stream event")
	}
	return e, nil
}
