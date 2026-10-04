package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestStartupErrorClass(t *testing.T) {
	const privateMarker = "private-startup-detail-should-not-escape"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"commit unknown direct", rhiza.ErrCommitUnknown, "write_outcome_unknown"},
		{"not ready direct", rhiza.ErrNotReady, "node_not_ready"},
		{"quorum unavailable direct", rhiza.ErrQuorumUnavailable, "quorum_unavailable"},
		{"durability unavailable direct", rhiza.ErrDurabilityUnavailable, "ack_durability_unavailable"},
		{"deadline direct", context.DeadlineExceeded, "deadline"},
		{"canceled direct", context.Canceled, "canceled"},
		{"wrapped commit unknown", fmt.Errorf("open rhiza: %w", rhiza.ErrCommitUnknown), "write_outcome_unknown"},
		{"wrapped not ready", fmt.Errorf("wait: %w", rhiza.ErrNotReady), "node_not_ready"},
		{"wrapped quorum unavailable", fmt.Errorf("tx: %w", rhiza.ErrQuorumUnavailable), "quorum_unavailable"},
		{"wrapped durability unavailable", fmt.Errorf("ack: %w", rhiza.ErrDurabilityUnavailable), "ack_durability_unavailable"},
		{"wrapped deadline", fmt.Errorf("wait for rhiza readiness: %w", context.DeadlineExceeded), "deadline"},
		{"wrapped canceled", fmt.Errorf("shutdown: %w", context.Canceled), "canceled"},
		{"joined commit unknown over deadline", errors.Join(fmt.Errorf("%s: %w", privateMarker, rhiza.ErrCommitUnknown), context.DeadlineExceeded), "write_outcome_unknown"},
		{"joined not ready over quorum", errors.Join(rhiza.ErrNotReady, rhiza.ErrQuorumUnavailable), "node_not_ready"},
		{"joined quorum over durability", errors.Join(rhiza.ErrQuorumUnavailable, rhiza.ErrDurabilityUnavailable), "quorum_unavailable"},
		{"joined deadline over canceled", errors.Join(context.DeadlineExceeded, context.Canceled), "deadline"},
		{"arbitrary private canary unknown", errors.New(privateMarker), "unknown"},
		{"nil handled as unknown", nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := startupErrorClass(tc.err)
			if got != tc.want {
				t.Fatalf("classification=%q want=%q", got, tc.want)
			}
			if strings.Contains(got, privateMarker) {
				t.Fatalf("classification %q leaks raw error text", got)
			}
		})
	}
}
