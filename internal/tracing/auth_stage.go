package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
)

const authStageTracerName = "goauthy/auth-stage"

// authStageNames is the closed allowlist of stage names. Only these fixed
// literals may reach a span name so no caller-supplied value (URL, token,
// identity, peer, SQL) can leak into telemetry.
var authStageNames = map[string]struct{}{
	"credential_lookup":   {},
	"password_verify":     {},
	"subject_revalidate":  {},
	"interaction_consume": {},
	"session_rotate":      {},
	"oauth_issue":         {},
	"authorize_validate":  {},
	"authorize_session":   {},
	"policy_check":        {},
	"policy_allow":        {},
	"policy_account_lock": {},
	"policy_success":      {},
	"session_load":        {},
	"request_resolve":     {},
	"storage_execute":     {},
	"storage_submit":      {},
	"storage_status":      {},
	"storage_replay":      {},
}

// ObserveAuthStage records one auth pipeline stage as a child of the span
// carried by ctx. It is a no-op when the parent context has no recording span,
// and it discards stage names outside the closed allowlist. Recorded spans
// carry no attributes and no error state; only timing and request correlation
// through the parent trace are exported.
func ObserveAuthStage(ctx context.Context, stage string, started time.Time) {
	if ctx == nil {
		return
	}
	if _, ok := authStageNames[stage]; !ok {
		return
	}
	if !trace.SpanFromContext(ctx).IsRecording() {
		return
	}

	_, span := NewTracer(authStageTracerName).Start(ctx, stage,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(started),
	)
	span.End(trace.WithTimestamp(time.Now()))
}
