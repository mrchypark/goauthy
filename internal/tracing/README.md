# OpenTelemetry Tracing (`internal/tracing`)

## Overview
Configures OpenTelemetry OTLP/HTTP tracing, provides HTTP request tracing middleware that prevents credential leakage in URL paths, and records allowlisted auth pipeline stage spans.

## Interface
- `[middleware.go:Enabled]` — Reports whether `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is non-empty.
- `[middleware.go:Middleware]` — Returns an `http.Handler` middleware that extracts W3C `TraceContext` headers, creates server spans named by matched route pattern (`r.Pattern` or `"unmatched"`), and marks `5xx` responses as errors; returns `next` unchanged when `!Enabled()`.
- `[tracing.go:Init]` — Initializes the OTLP/HTTP `sdktrace.TracerProvider` (defaulting `OTEL_SERVICE_NAME` to `"goauthy"`), registers it globally, and returns its `Shutdown` function.
- `[tracing.go:NewTracer]` — Returns `otel.Tracer(name)`.
- `[auth_stage.go:ObserveAuthStage]` — Records an internal child span for an allowlisted auth stage name (`credential_lookup`, `password_verify`, `session_rotate`, etc.) if the parent context has a recording span.

## Invariants
- `[middleware.go:Middleware]` extracts only W3C `TraceContext` (ignoring baggage) and never records raw request paths or query strings, using `r.Pattern` or `"unmatched"` to avoid leaking path-embedded tokens.
- `[middleware.go:statusRecorder.Unwrap]` preserves `http.ResponseController` access (e.g., deadlines and flushing for SSE streams).
- `[auth_stage.go:ObserveAuthStage]` discards any stage name not in `authStageNames` and records no attributes or error state.

## Side Effects
- `[tracing.go:Init]` normalizes scheme-less `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` env vars via `os.Setenv`, sets the global `otel.SetTracerProvider`, and exports spans over HTTP to the OTLP collector.

## Verification
- Run: `go test ./internal/tracing`
