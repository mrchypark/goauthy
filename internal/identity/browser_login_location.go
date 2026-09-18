package identity

import (
	"context"
	"errors"
	"net/netip"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var ErrInvalidUserAgent = errors.New("invalid user agent")

// RecordBrowserLoginLocation records a login and reports whether it inserted
// a location that was not already known for the browser or, without a browser
// ID, the IP address.
func (s *Store) RecordBrowserLoginLocation(ctx context.Context, subject, browserID, ip, userAgent string, location *string) (bool, error) {
	if err := validateSubject(subject); err != nil {
		return false, err
	}
	if ip == "" {
		return false, ErrInvalidIPAddress
	}
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil || parsedIP.Zone() != "" {
		return false, ErrInvalidIPAddress
	}
	if userAgent == "" {
		return false, ErrInvalidUserAgent
	}
	if ctx == nil {
		return false, errors.New("nil context")
	}

	now := s.now().UTC().UnixMilli()
	nonce, err := s.randomID(16)
	if err != nil {
		return false, err
	}
	normalizedIP := parsedIP.String()
	var locationValue any
	if location != nil {
		locationValue = *location
	}

	activeArgs := []any{subject, now}
	active := `EXISTS (SELECT 1 FROM identity_users
		WHERE subject=? AND disabled=0
		AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`

	var update rhiza.SQLStatement
	var insertSQL string
	var insertArgs []any
	if browserID != "" {
		update = rhiza.SQLStatement{
			SQL: `UPDATE identity_login_locations
				SET ip_address=?, last_seen_at_unix_ms=MAX(last_seen_at_unix_ms,?), login_count=login_count+1, location=?
				WHERE subject=? AND browser_id=? AND ` + active,
			Args: []any{normalizedIP, now, locationValue, subject, browserID, subject, now},
		}
		insertSQL = `INSERT INTO identity_login_locations
			(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count,browser_id,user_agent,location)
			SELECT ?,?,?,?,1,?,?,?
			WHERE ` + active + `
			AND NOT EXISTS (SELECT 1 FROM identity_login_locations WHERE subject=? AND browser_id=?)
			RETURNING 1`
		insertArgs = []any{subject, normalizedIP, now, now, browserID, userAgent, locationValue, subject, now, subject, browserID}
	} else {
		update = rhiza.SQLStatement{
			SQL: `UPDATE identity_login_locations
				SET last_seen_at_unix_ms=MAX(last_seen_at_unix_ms,?), login_count=login_count+1, location=?
				WHERE subject=? AND ip_address=? AND ` + active,
			Args: []any{now, locationValue, subject, normalizedIP, subject, now},
		}
		insertSQL = `INSERT INTO identity_login_locations
			(subject,ip_address,first_seen_at_unix_ms,last_seen_at_unix_ms,login_count,browser_id,user_agent,location)
			SELECT ?,?,?,?,1,?,?,?
			WHERE ` + active + `
			AND NOT EXISTS (SELECT 1 FROM identity_login_locations WHERE subject=? AND ip_address=?)
			RETURNING 1`
		insertArgs = []any{subject, normalizedIP, now, now, browserID, userAgent, locationValue, subject, now, subject, normalizedIP}
	}

	request := rhiza.ExecuteRequest{
		RequestID: mutationID("browser-login-location", subject, browserID, normalizedIP, nonce),
		Statements: []rhiza.SQLStatement{
			{SQL: `SELECT 1 FROM identity_users WHERE subject=? AND disabled=0 AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?)`, Args: activeArgs, WantRows: true},
			update,
			{SQL: insertSQL, Args: insertArgs, WantRows: true},
		},
	}
	result, err := storage.Execute(ctx, s.db, request)
	if err != nil {
		return false, err
	}
	if len(result.Statements) != 3 || len(result.Statements[0].Rows) > 1 || len(result.Statements[2].Rows) > 1 {
		return false, errors.New("invalid browser login location result")
	}
	if len(result.Statements[0].Rows) == 0 {
		return false, ErrInactiveSubject
	}
	return len(result.Statements[2].Rows) == 1, nil
}
