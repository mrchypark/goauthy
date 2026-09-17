package rbac

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/rhiza"
)

type Session struct {
	ID       string  `json:"id"`
	UserID   *string `json:"user_id,omitempty"`
	IsMFA    bool    `json:"is_mfa"`
	State    string  `json:"state"`
	Exp      int64   `json:"exp"`
	LastSeen int64   `json:"last_seen"`
	RemoteIP *string `json:"remote_ip"`
}
type SessionListOptions struct {
	PageSize  uint16
	Offset    uint16
	Backwards bool
	Cursor    string
	State     string
}
type sessionCursor struct {
	Exp int64
	ID  string
}

func (s *Store) listSessions(ctx context.Context, guard string, args []any, o SessionListOptions, threshold uint16) ([]Session, int64, string, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(guard) == "" || threshold == 0 {
		return nil, 0, "", ErrInvalid
	}
	if o.State == "" {
		o.State = "Auth"
	}
	switch o.State {
	case "Init", "Auth", "LoggedOut", "Unknown":
	default:
		return nil, 0, "", ErrInvalid
	}
	pageSize := o.PageSize
	if pageSize == 0 {
		pageSize = 20
	}
	if pageSize < threshold {
		pageSize = threshold
	}
	var c *sessionCursor
	var err error
	if o.Cursor != "" {
		c, err = decodeSessionCursor(o.Cursor)
		if err != nil {
			return nil, 0, "", err
		}
	}
	where := "state=?"
	qargs := append([]any{}, args...)
	qargs = append(qargs, o.State)
	if c != nil {
		op := "<"
		if o.Backwards {
			op = ">"
		}
		where += " AND ((SELECT count FROM total) < ? OR exp " + op + " ? OR (exp=? AND id " + op + " ?))"
		qargs = append(qargs, int64(threshold), c.Exp, c.Exp, c.ID)
	}
	order := "DESC"
	if o.Backwards {
		order = "ASC"
	}
	qargs = append(qargs, int64(threshold), int64(pageSize), int64(threshold), int64(o.Offset))
	query := `WITH authorized AS (SELECT 1 ok WHERE (` + guard + `)),
allsessions AS (
 SELECT b.token_digest id, NULLIF(b.subject,'') user_id,
 CASE WHEN b.auth_method='mfa' THEN 1 ELSE 0 END is_mfa,
 CASE WHEN b.revoked_at_unix_ms IS NOT NULL THEN 'LoggedOut'
 WHEN b.subject='' AND b.auth_method='' THEN 'Init'
 WHEN b.auth_method IN ('pwd','webauthn','mfa','external') THEN 'Auth' ELSE 'Unknown' END state,
 b.expires_at_unix_ms/1000 exp, b.last_seen_at_unix_ms/1000 last_seen, NULLIF(b.peer_ip,'') remote_ip
 FROM browser_sessions b CROSS JOIN authorized
), total AS (SELECT COUNT(*) count FROM identity_users CROSS JOIN authorized),
page AS (
 SELECT * FROM allsessions WHERE ` + where + ` ORDER BY exp ` + order + `, id ` + order + `
 LIMIT CASE WHEN (SELECT count FROM total) < ? THEN -1 ELSE ? END
 OFFSET CASE WHEN (SELECT count FROM total) < ? THEN 0 ELSE ? END
), combined AS (
 SELECT id,user_id,is_mfa,state,exp,last_seen,remote_ip,(SELECT count FROM total) count,1 authorized FROM page
 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT count FROM total),EXISTS(SELECT 1 FROM authorized)
)
SELECT * FROM combined ORDER BY exp DESC,id DESC`
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: qargs, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, 0, "", err
	}
	if len(r.Rows) == 0 {
		return nil, 0, "", ErrUnauthorized
	}
	out := make([]Session, 0, len(r.Rows))
	var count int64
	for _, row := range r.Rows {
		if len(row) != 9 {
			return nil, 0, "", errors.New("invalid session list response")
		}
		if row[8] != int64(1) {
			return nil, 0, "", ErrUnauthorized
		}
		var ok bool
		count, ok = row[7].(int64)
		if !ok || count < 0 {
			return nil, 0, "", errors.New("invalid session list count")
		}
		if row[0] == nil {
			continue
		}
		id, idOK := row[0].(string)
		uid, uidOK := nullableString(row[1])
		mfa, mfaOK := row[2].(int64)
		state, stateOK := row[3].(string)
		exp, expOK := row[4].(int64)
		last, lastOK := row[5].(int64)
		ip, ipOK := nullableString(row[6])
		if !idOK || !uidOK || !mfaOK || (mfa != 0 && mfa != 1) || !stateOK || !expOK || exp < 0 || !lastOK || last < 0 || !ipOK {
			return nil, 0, "", errors.New("invalid session list row")
		}
		out = append(out, Session{ID: id, UserID: uid, IsMFA: mfa == 1, State: state, Exp: exp, LastSeen: last, RemoteIP: ip})
	}
	var token string
	if count >= int64(threshold) && len(out) > 0 {
		i := len(out) - 1
		if o.Backwards {
			i = 0
		}
		token, err = encodeSessionCursor(sessionCursor{Exp: out[i].Exp, ID: out[i].ID})
		if err != nil {
			return nil, 0, "", err
		}
	}
	return out, count, token, nil
}
func encodeSessionCursor(c sessionCursor) (string, error) {
	if c.Exp < 0 || !validSubjectID(c.ID) || !utf8.ValidString(c.ID) || strings.ContainsFunc(c.ID, unicode.IsControl) {
		return "", ErrInvalid
	}
	b := make([]byte, 8+len(c.ID))
	binary.BigEndian.PutUint64(b, uint64(c.Exp))
	copy(b[8:], c.ID)
	return "s1." + base64.RawURLEncoding.EncodeToString(b), nil
}
func decodeSessionCursor(v string) (*sessionCursor, error) {
	if len(v) > 700 || !strings.HasPrefix(v, "s1.") {
		return nil, ErrInvalid
	}
	b, e := base64.RawURLEncoding.DecodeString(v[3:])
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != v[3:] || len(b) < 9 || len(b) > 520 {
		return nil, ErrInvalid
	}
	c := sessionCursor{Exp: int64(binary.BigEndian.Uint64(b)), ID: string(b[8:])}
	if canonical, err := encodeSessionCursor(c); err != nil || canonical != v {
		return nil, ErrInvalid
	}
	return &c, nil
}
