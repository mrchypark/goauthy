package identity

import (
	"context"
	"errors"
	"net"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	// maxLoginLocationsPerUser is the maximum number of login locations to retain per user.
	maxLoginLocationsPerUser = 100
	// newLocationWindowDays is the window to consider a location as "new".
	newLocationWindowDays = 30
)

var (
	ErrInvalidIPAddress = errors.New("invalid IP address")
)

// LoginLocation represents a recorded login location.
type LoginLocation struct {
	Subject     string `json:"subject"`
	IPAddress   string `json:"ip_address"`
	FirstSeenAt int64  `json:"first_seen_at_unix_ms"`
	LastSeenAt  int64  `json:"last_seen_at_unix_ms"`
	LoginCount  int64  `json:"login_count"`
}

// LoginLocationResult contains the result of a login location check.
type LoginLocationResult struct {
	IsNewLocation bool           `json:"is_new_location"`
	Location      LoginLocation  `json:"location"`
	PreviousCount int            `json:"previous_location_count"`
}

// RecordLoginLocation records a login location and checks if it's a new location.
func (s *Store) RecordLoginLocation(ctx context.Context, subject, ipAddress string) (*LoginLocationResult, error) {
	if err := validateSubject(subject); err != nil {
		return nil, err
	}
	if ipAddress == "" {
		return nil, ErrInvalidIPAddress
	}
	// Normalize IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, ErrInvalidIPAddress
	}
	normalizedIP := ip.String()

	now := s.now().UTC().UnixMilli()
	windowStart := now - (int64(newLocationWindowDays) * 24 * 60 * 60 * 1000)

	// Check if this IP exists for this user
	existing, err := s.getLoginLocation(ctx, subject, normalizedIP)
	if err != nil {
		return nil, err
	}

	result := &LoginLocationResult{
		IsNewLocation: existing == nil,
	}

	if existing != nil {
		// Update existing location
		err = s.updateLoginLocation(ctx, subject, normalizedIP, now)
		if err != nil {
			return nil, err
		}
		result.Location = *existing
		result.Location.LastSeenAt = now
		result.Location.LoginCount++
	} else {
		// Insert new location
		err = s.insertLoginLocation(ctx, subject, normalizedIP, now)
		if err != nil {
			return nil, err
		}
		result.Location = LoginLocation{
			Subject:     subject,
			IPAddress:   normalizedIP,
			FirstSeenAt: now,
			LastSeenAt:  now,
			LoginCount:  1,
		}
	}

	// Count previous locations within the window
	count, err := s.countLoginLocations(ctx, subject, windowStart)
	if err != nil {
		return nil, err
	}
	result.PreviousCount = count

	// Cleanup old locations if exceeding limit
	if err := s.cleanupLoginLocations(ctx, subject); err != nil {
		// Log but don't fail
		_ = err
	}

	return result, nil
}

// IsNewLoginLocation checks if the given IP is a new location for the user.
func (s *Store) IsNewLoginLocation(ctx context.Context, subject, ipAddress string) (bool, error) {
	if err := validateSubject(subject); err != nil {
		return false, err
	}
	if ipAddress == "" {
		return false, ErrInvalidIPAddress
	}
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false, ErrInvalidIPAddress
	}
	normalizedIP := ip.String()

	now := s.now().UTC().UnixMilli()
	windowStart := now - (int64(newLocationWindowDays) * 24 * 60 * 60 * 1000)

	existing, err := s.getLoginLocation(ctx, subject, normalizedIP)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return true, nil
	}
	// Check if the location was seen within the window
	return existing.LastSeenAt < windowStart, nil
}

// GetLoginLocations returns all login locations for a user.
func (s *Store) GetLoginLocations(ctx context.Context, subject string) ([]LoginLocation, error) {
	if err := validateSubject(subject); err != nil {
		return nil, err
	}

	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject, ip_address, first_seen_at_unix_ms, last_seen_at_unix_ms, login_count
			FROM identity_login_locations
			WHERE subject = ?
			ORDER BY last_seen_at_unix_ms DESC`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}

	locations := make([]LoginLocation, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 5 {
			continue
		}
		subject, _ := row[0].(string)
		ip, _ := row[1].(string)
		firstSeen, _ := row[2].(int64)
		lastSeen, _ := row[3].(int64)
		count, _ := row[4].(int64)
		locations = append(locations, LoginLocation{
			Subject:     subject,
			IPAddress:   ip,
			FirstSeenAt: firstSeen,
			LastSeenAt:  lastSeen,
			LoginCount:  count,
		})
	}
	return locations, nil
}

func (s *Store) getLoginLocation(ctx context.Context, subject, ipAddress string) (*LoginLocation, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject, ip_address, first_seen_at_unix_ms, last_seen_at_unix_ms, login_count
			FROM identity_login_locations
			WHERE subject = ? AND ip_address = ?`,
		Args:        []any{subject, ipAddress},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}
	if len(result.Rows[0]) != 5 {
		return nil, errors.New("invalid login location row")
	}
	subjectStr, _ := result.Rows[0][0].(string)
	ip, _ := result.Rows[0][1].(string)
	firstSeen, _ := result.Rows[0][2].(int64)
	lastSeen, _ := result.Rows[0][3].(int64)
	count, _ := result.Rows[0][4].(int64)
	return &LoginLocation{
		Subject:     subjectStr,
		IPAddress:   ip,
		FirstSeenAt: firstSeen,
		LastSeenAt:  lastSeen,
		LoginCount:  count,
	}, nil
}

func (s *Store) insertLoginLocation(ctx context.Context, subject, ipAddress string, now int64) error {
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("login-location-insert", subject, ipAddress),
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_login_locations (subject, ip_address, first_seen_at_unix_ms, last_seen_at_unix_ms, login_count)
				VALUES (?, ?, ?, ?, 1)`,
				Args: []any{subject, ipAddress, now, now}},
		},
	})
	return err
}

func (s *Store) updateLoginLocation(ctx context.Context, subject, ipAddress string, now int64) error {
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("login-location-update", subject, ipAddress),
		Statements: []rhiza.SQLStatement{
			{SQL: `UPDATE identity_login_locations
				SET last_seen_at_unix_ms = ?, login_count = login_count + 1
				WHERE subject = ? AND ip_address = ?`,
				Args: []any{now, subject, ipAddress}},
		},
	})
	return err
}

func (s *Store) countLoginLocations(ctx context.Context, subject string, since int64) (int, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM identity_login_locations
			WHERE subject = ? AND last_seen_at_unix_ms >= ?`,
		Args:        []any{subject, since},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return 0, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return 0, errors.New("invalid count result")
	}
	count, ok := result.Rows[0][0].(int64)
	if !ok {
		return 0, errors.New("invalid count type")
	}
	return int(count), nil
}

func (s *Store) cleanupLoginLocations(ctx context.Context, subject string) error {
	// Keep only the most recent locations
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: mutationID("login-location-cleanup", subject),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_login_locations
				WHERE subject = ? AND ip_address NOT IN (
					SELECT ip_address FROM identity_login_locations
					WHERE subject = ?
					ORDER BY last_seen_at_unix_ms DESC
					LIMIT ?
				)`,
				Args: []any{subject, subject, maxLoginLocationsPerUser}},
		},
	})
	return err
}
