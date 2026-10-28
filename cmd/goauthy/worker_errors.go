package main

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/mrchypark/rhiza"
)

type workerErrorClass struct {
	name         string
	retryability string
}

func classifyWorkerError(err error) workerErrorClass {
	switch {
	case errors.Is(err, rhiza.ErrCommitUnknown):
		return workerErrorClass{name: "write_outcome_unknown", retryability: "uncertain"}
	case errors.Is(err, rhiza.ErrNotReady):
		return workerErrorClass{name: "node_not_ready", retryability: "retryable"}
	case errors.Is(err, rhiza.ErrQuorumUnavailable):
		return workerErrorClass{name: "quorum_unavailable", retryability: "retryable"}
	case errors.Is(err, rhiza.ErrDurabilityUnavailable):
		return workerErrorClass{name: "ack_durability_unavailable", retryability: "retryable"}
	case errors.Is(err, rhiza.ErrRequestConflict):
		return workerErrorClass{name: "request_conflict", retryability: "not_retryable"}
	case errors.Is(err, rhiza.ErrInvalidRequest):
		return workerErrorClass{name: "invalid_request", retryability: "not_retryable"}
	case errors.Is(err, context.DeadlineExceeded):
		return workerErrorClass{name: "deadline", retryability: "retryable"}
	case errors.Is(err, context.Canceled):
		return workerErrorClass{name: "canceled", retryability: "unknown"}
	default:
		var networkError net.Error
		if errors.As(err, &networkError) {
			if networkError.Timeout() {
				return workerErrorClass{name: "network_timeout", retryability: "retryable"}
			}
			return workerErrorClass{name: "network_error", retryability: "unknown"}
		}
		return workerErrorClass{name: "unknown", retryability: "unknown"}
	}
}

func logWorkerFailure(worker, stage string, err error) {
	classification := classifyWorkerError(err)
	slog.Error("background worker step failed",
		"worker", worker,
		"stage", stage,
		"error_class", classification.name,
		"retryability", classification.retryability,
	)
}
