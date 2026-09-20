// Package eventlog stores public lifecycle event records. It is deliberately
// separate from audit, whose identifiers and privacy rules are different.
package eventlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/rhiza"
)

const minUnixSecond int64 = 1719784800

type Level string

const (
	Info     Level = "info"
	Notice   Level = "notice"
	Warning  Level = "warning"
	Critical Level = "critical"
)

func (l Level) Valid() bool { return l == Info || l == Notice || l == Warning || l == Critical }
func (l Level) Rank() int {
	switch l {
	case Info:
		return 0
	case Notice:
		return 1
	case Warning:
		return 2
	case Critical:
		return 3
	}
	return -1
}

type Type string

const (
	InvalidLogins           Type = "InvalidLogins"
	IpBlacklisted           Type = "IpBlacklisted"
	IpBlacklistRemoved      Type = "IpBlacklistRemoved"
	JwksRotated             Type = "JwksRotated"
	NewUserRegistered       Type = "NewUserRegistered"
	NewRauthyAdmin          Type = "NewRauthyAdmin"
	NewRauthyVersion        Type = "NewRauthyVersion"
	PossibleBruteForce      Type = "PossibleBruteForce"
	RauthyStarted           Type = "RauthyStarted"
	RauthyHealthy           Type = "RauthyHealthy"
	RauthyUnhealthy         Type = "RauthyUnhealthy"
	SecretsMigrated         Type = "SecretsMigrated"
	UserEmailChange         Type = "UserEmailChange"
	UserPasswordReset       Type = "UserPasswordReset"
	Test                    Type = "Test"
	BackchannelLogoutFailed Type = "BackchannelLogoutFailed"
	ScimTaskFailed          Type = "ScimTaskFailed"
	ForcedLogout            Type = "ForcedLogout"
	UserLoginRevoke         Type = "UserLoginRevoke"
	SuspiciousApiScan       Type = "SuspiciousApiScan"
	LoginNewLocation        Type = "LoginNewLocation"
	TokenIssued             Type = "TokenIssued"
	CredentialStuffing      Type = "CredentialStuffing"
	EmailSendError          Type = "EmailSendError"
)

var validTypes = map[Type]bool{InvalidLogins: true, IpBlacklisted: true, IpBlacklistRemoved: true, JwksRotated: true, NewUserRegistered: true, NewRauthyAdmin: true, NewRauthyVersion: true, PossibleBruteForce: true, RauthyStarted: true, RauthyHealthy: true, RauthyUnhealthy: true, SecretsMigrated: true, UserEmailChange: true, UserPasswordReset: true, Test: true, BackchannelLogoutFailed: true, ScimTaskFailed: true, ForcedLogout: true, UserLoginRevoke: true, SuspiciousApiScan: true, LoginNewLocation: true, TokenIssued: true, CredentialStuffing: true, EmailSendError: true}

func (t Type) Valid() bool { return validTypes[t] }

type Event struct {
	ID            string  `json:"id"`
	Timestamp     int64   `json:"timestamp"`
	Level         Level   `json:"level"`
	Type          Type    `json:"typ"`
	IP            *string `json:"ip"`
	Data          *int64  `json:"data"`
	Text          *string `json:"text"`
	PrevHash      string  `json:"prev_hash"`
	IntegrityHash string  `json:"integrity_hash"`
}

func Creation(requestID, email, ip string, administrator bool, at time.Time) Event {
	t := NewUserRegistered
	level := Info
	if administrator {
		t, level = NewRauthyAdmin, Notice
	}
	var ipp *string
	if ip != "" {
		ipp = &ip
	}
	var text *string
	if email != "" {
		text = &email
	}
	return Event{ID: eventID(requestID, t), Timestamp: at.UTC().UnixMilli(), Level: level, Type: t, IP: ipp, Text: text}
}

func eventID(operationID string, typ Type) string {
	h := sha256.Sum256([]byte("goauthy/eventlog/v1\x00" + operationID + "\x00" + string(typ)))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestEvent(requestID, ip string, at time.Time) Event {
	var ipp *string
	if ip != "" {
		ipp = &ip
	}
	text := "This is a Test-Event"
	return Event{ID: eventID(requestID, Test), Timestamp: at.UTC().UnixMilli(), Level: Info, Type: Test, IP: ipp, Text: &text}
}

func PasswordReset(operationID, text, ip string, at time.Time) Event {
	var ipp *string
	if ip != "" {
		ipp = &ip
	}
	return Event{ID: eventID(operationID, UserPasswordReset), Timestamp: at.UTC().UnixMilli(), Level: Notice, Type: UserPasswordReset, IP: ipp, Text: &text}
}

func JWKSRotated(operationID string, at time.Time) Event {
	return Event{ID: eventID(operationID, JwksRotated), Timestamp: at.UTC().UnixMilli(), Level: Notice, Type: JwksRotated}
}

func BackchannelFailure(operationID, clientID, subject string, attempts int64, at time.Time) Event {
	text := clientID + " / " + subject
	return Event{ID: eventID(operationID, BackchannelLogoutFailed), Timestamp: at.UTC().UnixMilli(), Level: Critical, Type: BackchannelLogoutFailed, Data: &attempts, Text: &text}
}

func IPBlacklisted(operationID, ip string, expiresAt int64, at time.Time) Event {
	return Event{ID: eventID(operationID, IpBlacklisted), Timestamp: at.UTC().UnixMilli(), Level: Warning, Type: IpBlacklisted, IP: &ip, Data: &expiresAt}
}

func InvalidLogin(operationID, ip string, failures uint32, at time.Time) Event {
	level := Info
	switch {
	case failures >= 20:
		level = Critical
	case failures >= 10:
		level = Warning
	case failures >= 7:
		level = Notice
	}
	count := int64(failures)
	return Event{ID: eventID(operationID, InvalidLogins), Timestamp: at.UTC().UnixMilli(), Level: level, Type: InvalidLogins, IP: &ip, Data: &count}
}

func (e Event) computeHash() string {
	var ip, data, text string
	if e.IP != nil {
		ip = *e.IP
	}
	if e.Data != nil {
		data = fmt.Sprintf("%d", *e.Data)
	}
	if e.Text != nil {
		text = *e.Text
	}
	input := e.ID + "\x00" + fmt.Sprintf("%d", e.Timestamp) + "\x00" + string(e.Level) + "\x00" + string(e.Type) + "\x00" + ip + "\x00" + data + "\x00" + text + "\x00" + e.PrevHash
	h := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (e *Event) Seal(prevHash string) {
	e.PrevHash = prevHash
	e.IntegrityHash = e.computeHash()
}

func (e Event) Statement(condition string, args ...any) (rhiza.SQLStatement, error) {
	if !e.valid() || strings.TrimSpace(condition) == "" {
		return rhiza.SQLStatement{}, errors.New("invalid event")
	}
	var ip, data, text any
	if e.IP != nil {
		ip = *e.IP
	}
	if e.Data != nil {
		data = *e.Data
	}
	if e.Text != nil {
		text = *e.Text
	}
	a := []any{e.ID, e.Timestamp, e.Level.Rank(), string(e.Type), ip, data, text, e.PrevHash, e.IntegrityHash}
	a = append(a, args...)
	return rhiza.SQLStatement{SQL: `INSERT INTO event_log(id,timestamp,level,typ,ip,data,text,prev_hash,integrity_hash) SELECT ?,?,?,?,?,?,?,?,? WHERE ` + condition, Args: a}, nil
}
func (e Event) valid() bool {
	if !validID(e.ID) || e.Timestamp < 0 || !e.Level.Valid() || !e.Type.Valid() || e.Text != nil && (len(*e.Text) > 4096 || !utf8.ValidString(*e.Text)) {
		return false
	}
	if e.IP != nil {
		ip, err := netip.ParseAddr(*e.IP)
		if err != nil || ip.Zone() != "" || len(*e.IP) > 45 {
			return false
		}
	}
	return true
}

func validID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == id
}

type Query struct {
	From  int64  `json:"from"`
	Until *int64 `json:"until"`
	Level Level  `json:"level"`
	Type  *Type  `json:"typ"`
}

// maxEncodedEventRowBytes bounds the JSON encoding of one returned event row.
// Rhiza rejects the whole result once its encoding passes 16 MiB and its encoder
// escapes a byte like "<" to six bytes, so the raw 4,096-byte text limit is worth
// 6 * 4096 + 2 = 24,578 here; the schema adds a 43-character id (45), two hashes
// of the same size (90), the longest type name (24), an address (47), a timestamp
// and a data value (39), the level and the marker (2) and the array punctuation
// (11) for 24,836 in total. The margin covers the rest of the envelope.
const maxEncodedEventRowBytes = 24_900

// MaxPageSize bounds one event page. The query returns the page plus one
// look-ahead row and the authorization marker, so the page is sized from the
// worst-case encoded row instead of the raw text limit: 16 MiB allows 673 such
// rows, and the page keeps one of them for the look-ahead row. Every accepted
// limit therefore stays inside the Rhiza 10,000-row and 16 MiB result budgets
// and can still return a page together with its continuation.
//
// ponytail: a page of short texts could be larger than this; retry with a
// smaller page on the encoded-byte error instead if page count ever matters
// more than the extra round trips and non-deterministic page sizes.
const MaxPageSize = 16<<20/maxEncodedEventRowBytes - 1

// Cursor is the keyset position of the last row of a page. Pages are ordered by
// timestamp DESC, id DESC, so this position is stable: an insert that sorts
// before it is never returned by a later page, and retained rows are never
// repeated or skipped when older rows are inserted or deleted in between.
type Cursor struct {
	Timestamp int64
	ID        string
}

// Token renders the cursor for the continuation_token wire field. It is a
// position, not a capability: every page re-checks authorization in the same
// snapshot as the page itself.
func (c Cursor) Token() string {
	return "e1." + strconv.FormatInt(c.Timestamp, 10) + "." + c.ID
}

// ParseCursor accepts only a canonical Token value.
func ParseCursor(token string) (*Cursor, error) {
	rest, ok := strings.CutPrefix(token, "e1.")
	if !ok {
		return nil, errors.New("invalid event cursor")
	}
	stamp, id, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, errors.New("invalid event cursor")
	}
	timestamp, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || timestamp < 0 || strconv.FormatInt(timestamp, 10) != stamp || !validID(id) {
		return nil, errors.New("invalid event cursor")
	}
	return &Cursor{Timestamp: timestamp, ID: id}, nil
}

func (q Query) Validate() error {
	if q.From < minUnixSecond || q.From > math.MaxInt64/1000 || !q.Level.Valid() {
		return errors.New("invalid event query")
	}
	if q.Until != nil && (*q.Until < minUnixSecond || *q.Until > math.MaxInt64/1000) {
		return errors.New("invalid event query")
	}
	if q.Type != nil && !q.Type.Valid() {
		return errors.New("invalid event query")
	}
	return nil
}

type Store struct{ db *rhiza.DB }

func NewStore(db *rhiza.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("eventlog store requires database")
	}
	return &Store{db: db}, nil
}

// ListGuarded returns one bounded page and the authorization marker of the same
// linearizable snapshot. The caller supplies only a trusted SQL authorization
// predicate; user values belong in args. The marker is returned even when the
// page is empty, and a cursor is returned only when a further row exists, so a
// missing continuation is the end of the retained result.
func (s *Store) ListGuarded(ctx context.Context, q Query, now time.Time, cursor *Cursor, limit int, condition string, args ...any) ([]Event, *Cursor, bool, error) {
	if s == nil || s.db == nil || ctx == nil || q.Validate() != nil || strings.TrimSpace(condition) == "" || now.IsZero() || limit < 1 || limit > MaxPageSize || cursor != nil && (cursor.Timestamp < 0 || !validID(cursor.ID)) {
		return nil, nil, false, errors.New("invalid event query")
	}
	// Rauthy defaults until to whole Unix seconds before conversion to ms.
	untilSeconds := now.Unix()
	if q.Until != nil {
		untilSeconds = *q.Until
	}
	if untilSeconds < 0 || untilSeconds > math.MaxInt64/1000 {
		return nil, nil, false, errors.New("invalid event query clock")
	}
	from, until := q.From*1000, untilSeconds*1000
	filter := `timestamp>=? AND timestamp<=? AND level>=?`
	filterArgs := []any{from, until, q.Level.Rank()}
	if q.Type != nil {
		filter += ` AND typ=?`
		filterArgs = append(filterArgs, string(*q.Type))
	}
	bind := append([]any(nil), args...)
	bind = append(bind, filterArgs...)
	page := ""
	if cursor != nil {
		page = ` AND (timestamp<? OR (timestamp=? AND id<?))`
		bind = append(bind, cursor.Timestamp, cursor.Timestamp, cursor.ID)
	}
	// One extra row only decides whether a continuation exists; it is never
	// returned, so a continuation always has at least one following row.
	bind = append(bind, int64(limit)+1)
	sql := `WITH authorized AS (SELECT 1 AS ok WHERE (` + condition + `)), page AS (SELECT id,timestamp,level,typ,ip,data,text,prev_hash,integrity_hash FROM event_log WHERE EXISTS (SELECT 1 FROM authorized) AND ` + filter + page + ` ORDER BY timestamp DESC,id DESC LIMIT ?) SELECT id,timestamp,level,typ,ip,data,text,prev_hash,integrity_hash,0 AS marker FROM page UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1 AS marker FROM authorized ORDER BY marker ASC,timestamp DESC,id DESC`
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: bind, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, nil, false, err
	}
	out := make([]Event, 0)
	authorized := false
	for _, row := range r.Rows {
		if len(row) != 10 {
			return nil, nil, false, fmt.Errorf("invalid event row")
		}
		marker, ok := row[9].(int64)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid event marker")
		}
		if marker == 1 {
			authorized = true
			continue
		}
		if marker != 0 {
			return nil, nil, false, errors.New("invalid event marker")
		}
		id, ok := row[0].(string)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid event id")
		}
		ts, ok := row[1].(int64)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid event timestamp")
		}
		lv, ok := row[2].(int64)
		if !ok || lv < 0 || lv > 3 {
			return nil, nil, false, fmt.Errorf("invalid event level")
		}
		typ, ok := row[3].(string)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid event type")
		}
		e := Event{ID: id, Timestamp: ts, Level: []Level{Info, Notice, Warning, Critical}[lv], Type: Type(typ)}
		if row[4] != nil {
			v, ok := row[4].(string)
			if !ok {
				return nil, nil, false, fmt.Errorf("invalid event ip")
			}
			e.IP = &v
		}
		if row[5] != nil {
			v, ok := row[5].(int64)
			if !ok {
				return nil, nil, false, fmt.Errorf("invalid event data")
			}
			e.Data = &v
		}
		if row[6] != nil {
			v, ok := row[6].(string)
			if !ok {
				return nil, nil, false, fmt.Errorf("invalid event text")
			}
			e.Text = &v
		}
		if row[7] != nil {
			v, ok := row[7].(string)
			if !ok {
				return nil, nil, false, fmt.Errorf("invalid event prev_hash")
			}
			e.PrevHash = v
		}
		if row[8] != nil {
			v, ok := row[8].(string)
			if !ok {
				return nil, nil, false, fmt.Errorf("invalid event integrity_hash")
			}
			e.IntegrityHash = v
		}
		if !e.valid() {
			return nil, nil, false, errors.New("invalid stored event")
		}
		out = append(out, e)
	}
	if len(out) <= limit {
		return out, nil, authorized, nil
	}
	out = out[:limit]
	last := out[len(out)-1]
	return out, &Cursor{Timestamp: last.Timestamp, ID: last.ID}, authorized, nil
}

func (s *Store) VerifyIntegrity(ctx context.Context) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, errors.New("nil store")
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT e.id,e.timestamp,e.level,e.typ,e.ip,e.data,e.text,e.prev_hash,e.integrity_hash FROM event_log_order o JOIN event_log e ON e.id=o.event_id ORDER BY o.sequence ASC`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	var prevHash string
	for _, row := range r.Rows {
		if len(row) != 9 {
			return false, fmt.Errorf("invalid event row")
		}
		id, ok := row[0].(string)
		if !ok {
			return false, fmt.Errorf("invalid event id")
		}
		ts, ok := row[1].(int64)
		if !ok {
			return false, fmt.Errorf("invalid event timestamp")
		}
		lv, ok := row[2].(int64)
		if !ok || lv < 0 || lv > 3 {
			return false, fmt.Errorf("invalid event level")
		}
		typ, ok := row[3].(string)
		if !ok {
			return false, fmt.Errorf("invalid event type")
		}
		e := Event{ID: id, Timestamp: ts, Level: []Level{Info, Notice, Warning, Critical}[lv], Type: Type(typ)}
		if row[4] != nil {
			v, ok := row[4].(string)
			if !ok {
				return false, fmt.Errorf("invalid event ip")
			}
			e.IP = &v
		}
		if row[5] != nil {
			v, ok := row[5].(int64)
			if !ok {
				return false, fmt.Errorf("invalid event data")
			}
			e.Data = &v
		}
		if row[6] != nil {
			v, ok := row[6].(string)
			if !ok {
				return false, fmt.Errorf("invalid event text")
			}
			e.Text = &v
		}
		if row[7] != nil {
			v, ok := row[7].(string)
			if !ok {
				return false, fmt.Errorf("invalid event prev_hash")
			}
			e.PrevHash = v
		}
		if row[8] != nil {
			v, ok := row[8].(string)
			if !ok {
				return false, fmt.Errorf("invalid event integrity_hash")
			}
			e.IntegrityHash = v
		}
		if !e.valid() {
			return false, errors.New("invalid stored event")
		}
		expected := e.computeHash()
		if e.IntegrityHash != expected {
			return false, nil
		}
		if e.PrevHash != prevHash {
			return false, nil
		}
		prevHash = e.IntegrityHash
	}
	return true, nil
}
