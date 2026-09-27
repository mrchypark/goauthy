package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"sync"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const apiKeyAuthFailureEventInterval = time.Second
const apiKeyAuthFailureWriteTimeout = 5 * time.Second

type apiKeyAuthFailureRecorder struct {
	ctx          context.Context
	execute      func(context.Context, rhiza.ExecuteRequest) error
	now          func() time.Time
	logger       *slog.Logger
	metrics      *metrics.Registry
	writeTimeout time.Duration
	mu           sync.Mutex
	nextEvent    time.Time
	inFlight     bool
	// This bounded count is used for the next admitted event's log summary;
	// metric counters expose every suppression even if there is no next event.
	suppressed uint64
}

func newAPIKeyAuthFailureHandler(ctx context.Context, db *rhiza.DB, now func() time.Time, logger *slog.Logger, registry *metrics.Registry) func(context.Context, string) {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	recorder := &apiKeyAuthFailureRecorder{
		ctx: ctx, now: now, logger: logger, metrics: registry, writeTimeout: apiKeyAuthFailureWriteTimeout,
		execute: func(ctx context.Context, request rhiza.ExecuteRequest) error {
			_, err := storage.Execute(ctx, db, request)
			return err
		},
	}
	return recorder.record
}

func (r *apiKeyAuthFailureRecorder) record(requestCtx context.Context, keyName string) {
	now := r.now()
	r.mu.Lock()
	if r.inFlight || now.Before(r.nextEvent) {
		if r.metrics != nil {
			if r.inFlight {
				r.metrics.APIKeyAuthFailureSuppressedBusy()
			} else {
				r.metrics.APIKeyAuthFailureSuppressedInterval()
			}
		}
		if r.suppressed < ^uint64(0) {
			r.suppressed++
		}
		r.mu.Unlock()
		return
	}
	suppressed := r.suppressed
	r.suppressed = 0
	r.nextEvent = now.Add(apiKeyAuthFailureEventInterval)
	r.inFlight = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.inFlight = false
		r.mu.Unlock()
	}()

	if suppressed > 0 {
		r.logger.Warn("API key authentication failure events suppressed", "count", suppressed)
	}
	ip := browser.PeerIPFromContext(requestCtx)
	operationID := "suspicious-api-scan/" + rand.Text()
	event := eventlog.SuspiciousApiScanEvent(operationID, keyName, ip, now)
	statement, err := event.Statement("1=1")
	if err != nil {
		if r.metrics != nil {
			r.metrics.APIKeyAuthFailureStatementFailed()
		}
		r.logger.Error("API key authentication failure event could not be constructed")
		return
	}
	writeCtx, cancel := context.WithTimeout(r.ctx, r.writeTimeout)
	defer cancel()
	if err := r.execute(writeCtx, rhiza.ExecuteRequest{RequestID: operationID, Statements: []rhiza.SQLStatement{statement}}); err != nil {
		if r.metrics != nil {
			r.metrics.APIKeyAuthFailureStorageFailed()
		}
		r.logger.Error("API key authentication failure event was not written")
	} else if r.metrics != nil {
		r.metrics.APIKeyAuthFailureWriteSuccess()
	}
}
