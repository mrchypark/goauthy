package tracing

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func newStageRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder),
	)
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return recorder
}

func TestObserveAuthStageCorrelatesWithParentAndTimesPastStart(t *testing.T) {
	recorder := newStageRecorder(t)
	tracer := otel.Tracer("goauthy/test")

	parentCtx, parent := tracer.Start(t.Context(), "request")
	parentTrace := parent.SpanContext()
	start := time.Now().Add(-250 * time.Millisecond)

	ObserveAuthStage(parentCtx, "password_verify", start)
	parent.End()

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("recorded %d spans, want 2", len(spans))
	}
	stage := spans[0]
	if stage.Name() != "password_verify" {
		t.Fatalf("stage name = %q, want %q", stage.Name(), "password_verify")
	}
	if got := stage.SpanContext().TraceID(); got != parentTrace.TraceID() {
		t.Fatalf("trace id = %s, want parent %s", got, parentTrace.TraceID())
	}
	if got := stage.Parent().SpanID(); got != parentTrace.SpanID() {
		t.Fatalf("parent span id = %s, want %s", got, parentTrace.SpanID())
	}
	if !stage.StartTime().Equal(start) {
		t.Fatalf("start time = %s, want %s", stage.StartTime(), start)
	}
	if !stage.EndTime().After(stage.StartTime()) {
		t.Fatalf("end time %s not after start %s", stage.EndTime(), stage.StartTime())
	}
	if elapsed := stage.EndTime().Sub(stage.StartTime()); elapsed < 200*time.Millisecond {
		t.Fatalf("stage duration = %s, want at least the 250ms window", elapsed)
	}
}

func TestObserveAuthStageDiscardsUnknownNameAndKeepsSpanEmpty(t *testing.T) {
	recorder := newStageRecorder(t)
	tracer := otel.Tracer("goauthy/test")

	parentCtx, parent := tracer.Start(t.Context(), "request")

	ObserveAuthStage(parentCtx, "token=secret-value", time.Now())
	ObserveAuthStage(parentCtx, "SELECT * FROM users", time.Now())
	ObserveAuthStage(parentCtx, "", time.Now())
	if got := len(recorder.Ended()); got != 0 {
		t.Fatalf("recorded %d spans for unknown stage names, want 0", got)
	}

	ObserveAuthStage(parentCtx, "session_load", time.Now())
	parent.End()

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("recorded %d spans, want 2", len(spans))
	}
	stage := spans[0]
	if len(stage.Attributes()) != 0 {
		t.Fatalf("attributes = %v, want none", stage.Attributes())
	}
	if len(stage.Events()) != 0 {
		t.Fatalf("events = %v, want none", stage.Events())
	}
	if stage.Status().Code != 0 {
		t.Fatalf("status = %v, want unset", stage.Status())
	}
	if stage.SpanKind() != trace.SpanKindInternal {
		t.Fatalf("span kind = %v, want internal", stage.SpanKind())
	}
}

func TestObserveAuthStageWithoutRecordingParentRecordsNothing(t *testing.T) {
	recorder := newStageRecorder(t)

	ObserveAuthStage(t.Context(), "credential_lookup", time.Now())
	if got := len(recorder.Ended()); got != 0 {
		t.Fatalf("recorded %d spans without a parent span, want 0", got)
	}

	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(trace.NewNoopTracerProvider())
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	noopCtx, noop := trace.NewNoopTracerProvider().Tracer("goauthy/test").Start(t.Context(), "request")
	ObserveAuthStage(noopCtx, "session_rotate", time.Now())
	noop.End()
	if got := len(recorder.Ended()); got != 0 {
		t.Fatalf("recorded %d spans with a non-recording parent, want 0", got)
	}
}