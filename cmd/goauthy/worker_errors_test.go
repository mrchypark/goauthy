package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestHousekeepingErrorLogIsClassifiedAndSanitized(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	for _, tc := range []struct {
		name       string
		err        error
		secret     string
		wantFields []string
	}{
		{
			name:   "quorum unavailable",
			secret: "synthetic-quorum-secret",
			err:    fmt.Errorf("provider response synthetic-quorum-secret: %w", rhiza.ErrQuorumUnavailable),
			wantFields: []string{
				"worker=housekeeping", "stage=test-job",
				"error_class=quorum_unavailable", "retryability=retryable",
			},
		},
		{
			name:   "commit outcome uncertain",
			secret: "synthetic-commit-secret",
			err:    fmt.Errorf("write response synthetic-commit-secret: %w", rhiza.ErrCommitUnknown),
			wantFields: []string{
				"worker=housekeeping", "stage=test-job",
				"error_class=write_outcome_unknown", "retryability=uncertain",
			},
		},
		{
			name:   "unknown failure",
			secret: "synthetic-unknown-secret",
			err:    fmt.Errorf("provider response synthetic-unknown-secret"),
			wantFields: []string{
				"worker=housekeeping", "stage=test-job",
				"error_class=unknown", "retryability=unknown",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			housekeepingErrorHandler("test-job", tc.err)
			logged := output.String()
			for _, field := range tc.wantFields {
				if !strings.Contains(logged, field) {
					t.Errorf("structured worker log missing field %q", field)
				}
			}
			if strings.Contains(logged, tc.secret) {
				t.Error("worker log included raw error detail")
			}
		})
	}
}
