package rbac

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"strings"

	"github.com/mrchypark/rhiza"
)

type UserListOptions struct {
	PageSize  uint16
	Offset    uint16
	Backwards bool
	Cursor    string
}

type UserResponseSimple struct {
	ID         string  `json:"id"`
	Email      string  `json:"email"`
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	CreatedAt  int64   `json:"created_at"`
	LastLogin  *int64  `json:"last_login"`
	PictureID  *string `json:"picture_id"`
}

type userListResult struct {
	Users             []UserResponseSimple
	Count             int64
	PageSize          uint16
	Paginated         bool
	ContinuationToken string
}

type userListCursor struct {
	Created int64
	Subject string
}

func (s *Store) listUsers(ctx context.Context, guard string, args []any, options UserListOptions, threshold uint16) (userListResult, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(guard) == "" || threshold < 1 {
		return userListResult{}, ErrInvalid
	}
	pageSize := options.PageSize
	if pageSize == 0 {
		pageSize = 20
	}
	if pageSize < threshold {
		pageSize = threshold
	}
	var cursor *userListCursor
	if options.Cursor != "" {
		var err error
		cursor, err = decodeUserListCursor(options.Cursor)
		if err != nil {
			return userListResult{}, err
		}
	}
	order := "ASC"
	if options.Backwards {
		order = "DESC"
	}
	pageWhere := "(SELECT count FROM total) < ?"
	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, int64(threshold))
	if cursor != nil {
		if options.Backwards {
			pageWhere += " OR (allusers.created_at_unix_ms < ? OR (allusers.created_at_unix_ms = ? AND allusers.subject < ?))"
		} else {
			pageWhere += " OR (allusers.created_at_unix_ms > ? OR (allusers.created_at_unix_ms = ? AND allusers.subject > ?))"
		}
		queryArgs = append(queryArgs, cursor.Created, cursor.Created, cursor.Subject)
	} else {
		pageWhere += " OR (SELECT count FROM total) >= ?"
		queryArgs = append(queryArgs, int64(threshold))
	}
	limitExpr := "CASE WHEN (SELECT count FROM total) < ? THEN -1 ELSE ? END"
	offsetExpr := "CASE WHEN (SELECT count FROM total) < ? THEN 0 ELSE ? END"
	queryArgs = append(queryArgs, int64(threshold), int64(pageSize), int64(threshold), int64(options.Offset))
	sql := `WITH authorized AS (SELECT 1 AS ok WHERE ` + guard + `),
allusers AS (
 SELECT u.subject, u.created_at_unix_ms, u.last_login_at_unix_ms,
        COALESCE(p.email, r.email, '') AS email, p.given_name, p.family_name
 FROM identity_users u
 LEFT JOIN identity_user_profiles p ON p.subject=u.subject
 LEFT JOIN identity_recovery_emails r ON r.subject=u.subject
 CROSS JOIN authorized
), total AS (SELECT COUNT(*) AS count FROM allusers),
page AS (
 SELECT allusers.* FROM allusers CROSS JOIN total
 WHERE ` + pageWhere + `
 ORDER BY allusers.created_at_unix_ms ` + order + `, allusers.subject ` + order + `
 LIMIT ` + limitExpr + ` OFFSET ` + offsetExpr + `
), combined AS (
	 SELECT page.subject,page.email,page.given_name,page.family_name,page.created_at_unix_ms,page.last_login_at_unix_ms,total.count,1 AS item,1 AS authorized
	 FROM page CROSS JOIN total
	 UNION ALL
	 SELECT NULL,NULL,NULL,NULL,NULL,NULL,total.count,0 AS item,EXISTS (SELECT 1 FROM authorized) AS authorized FROM total
)
SELECT * FROM combined ORDER BY item ASC, created_at_unix_ms ASC, subject ASC`
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: sql, Args: queryArgs, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return userListResult{}, err
	}
	if len(result.Rows) == 0 || len(result.Rows[0]) != 9 {
		return userListResult{}, errors.New("invalid user list response")
	}
	count, ok := result.Rows[0][6].(int64)
	if !ok {
		return userListResult{}, errors.New("invalid user list count")
	}
	if result.Rows[0][8] == int64(0) {
		return userListResult{}, ErrUnauthorized
	}
	out := userListResult{PageSize: pageSize, Count: count, Users: make([]UserResponseSimple, 0, len(result.Rows)-1)}
	keys := make([]userListCursor, 0, len(result.Rows))
	for _, row := range result.Rows[1:] {
		if len(row) != 9 {
			return userListResult{}, errors.New("invalid user list row")
		}
		id, ok := row[0].(string)
		if !ok {
			return userListResult{}, errors.New("invalid user list subject")
		}
		email, ok := row[1].(string)
		if !ok {
			return userListResult{}, errors.New("invalid user list email")
		}
		created, ok := row[4].(int64)
		if !ok || created < 0 {
			return userListResult{}, errors.New("invalid user list creation time")
		}
		last, ok := nullableInt64(row[5])
		if !ok {
			return userListResult{}, errors.New("invalid user list login time")
		}
		given, ok := nullableString(row[2])
		if !ok {
			return userListResult{}, errors.New("invalid user list given name")
		}
		family, ok := nullableString(row[3])
		if !ok {
			return userListResult{}, errors.New("invalid user list family name")
		}
		if last != nil {
			v := *last / 1000
			last = &v
		}
		out.Users = append(out.Users, UserResponseSimple{ID: id, Email: email, GivenName: given, FamilyName: family, CreatedAt: created / 1000, LastLogin: last, PictureID: nil})
		keys = append(keys, userListCursor{Created: created, Subject: id})
		if row[6] != count {
			return userListResult{}, errors.New("inconsistent user list count")
		}
	}
	out.Paginated = out.Count >= int64(threshold)
	if out.Paginated && len(out.Users) > 0 {
		boundary := keys[len(keys)-1]
		if options.Backwards {
			boundary = keys[0]
		}
		var err error
		out.ContinuationToken, err = encodeUserListCursor(boundary)
		if err != nil {
			return userListResult{}, err
		}
	}
	return out, nil
}

func nullableString(v any) (*string, bool) {
	if v == nil {
		return nil, true
	}
	s, ok := v.(string)
	return &s, ok
}
func nullableInt64(v any) (*int64, bool) {
	if v == nil {
		return nil, true
	}
	n, ok := v.(int64)
	return &n, ok && n >= 0
}

func encodeUserListCursor(c userListCursor) (string, error) {
	if c.Created < 0 || !validSubjectID(c.Subject) {
		return "", ErrInvalid
	}
	b := make([]byte, 8+len(c.Subject))
	binary.BigEndian.PutUint64(b, uint64(c.Created))
	copy(b[8:], c.Subject)
	return "u1." + base64.RawURLEncoding.EncodeToString(b), nil
}
func decodeUserListCursor(value string) (*userListCursor, error) {
	if len(value) > 700 || !strings.HasPrefix(value, "u1.") {
		return nil, ErrInvalid
	}
	encoded := strings.TrimPrefix(value, "u1.")
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != encoded || len(b) < 9 || len(b) > 520 {
		return nil, ErrInvalid
	}
	n := binary.BigEndian.Uint64(b[:8])
	if n > math.MaxInt64 {
		return nil, ErrInvalid
	}
	subject := string(b[8:])
	if !validSubjectID(subject) {
		return nil, ErrInvalid
	}
	return &userListCursor{Created: int64(n), Subject: subject}, nil
}
