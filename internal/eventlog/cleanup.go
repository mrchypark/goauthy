package eventlog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const cleanupBatchSize = 1000

// Cleanup removes at most one bounded batch of events older than the strict
// retention cutoff. The timestamp/id ordering makes repeated calls progress
// even when all calls use the same clock value.
func (s *Store) Cleanup(ctx context.Context, now time.Time, retention time.Duration) (int, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || retention <= 0 {
		return 0, errors.New("event cleanup requires store, context, time, and positive retention")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	requestID := "eventlog-cleanup/" + base64.RawURLEncoding.EncodeToString(nonce[:])
	cutoff := now.UTC().Add(-retention).UnixMilli()
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: requestID,
		SQL: `DELETE FROM event_log WHERE id IN (
			SELECT id FROM event_log WHERE timestamp < ? ORDER BY timestamp ASC, id ASC LIMIT ?
		)`,
		Args: []any{cutoff, int64(cleanupBatchSize)},
	})
	if err != nil {
		return 0, err
	}
	return int(response.MutationReceipt.RowsAffected), nil
}
