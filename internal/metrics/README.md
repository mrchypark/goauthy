# metrics

## Overview
`metrics` provides an isolated Prometheus `Registry`, bounded-cardinality HTTP instrumentation middleware, Bearer-authenticated metrics exposition, and typed counters/histograms for database readiness, pool gauges, security outcomes, API-key audit suppression, and authentication stages.

## Interface
- Stage enum: `AuthStage` and its 12 constants (`AuthStageCredentialLookup` through `AuthStagePolicySuccess`) in [metrics.go](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L98-L113).
- Registry and HTTP handlers: `Registry`, `NewRegistry`, `Registry.Handler`, `AuthenticatedHandler`, and `Registry.Instrument` in [metrics.go](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L136-L410).
- Recording methods: `DBReadiness`, `DBPool`, `AuthSuccess`, `AuthFailure`, `TokenOK`, `TokenReject`, `APIKeyAuthFailureSuppressedInterval`, `APIKeyAuthFailureSuppressedBusy`, `APIKeyAuthFailureStatementFailed`, `APIKeyAuthFailureStorageFailed`, `APIKeyAuthFailureWriteSuccess`, `DBQueryDuration`, `AuthStageDuration`, and `AuthStageCanceledCompletion` in [metrics.go](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go).
- Test collector accessors: `AuthSuccessCounter`, `AuthFailureCounter`, `TokenOKCounter`, `AuthStageDurationCollector`, and `TokenRejectCounter` in [metrics.go](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go).

## Invariants
- Never registers collectors on `prometheus.DefaultRegisterer`; every `Registry` owns a private `prometheus.Registry` ([metrics.go:newRegistry](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L179-L185)).
- HTTP labels are strictly bounded (`sanitizeMethod`, `classifyRoute` -> `/`, `/oidc/*`, `/auth/*`, `/other`, and `classifyStatus` -> `1xx`..`5xx`), and `AuthStageDuration` / `AuthStageCanceledCompletion` ignore nil registries, unknown `AuthStage` values, and NaN/Inf/negative durations ([metrics.go:classifyRoute](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L60-L89), [metrics.go:AuthStageDuration](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L524-L539)).
- `AuthenticatedHandler` compares SHA-256 digests in constant time and rejects Bearer tokens containing whitespace, CR/LF, or commas ([metrics.go:AuthenticatedHandler](file:///Users/cypark/Documents/project/goauthy/internal/metrics/metrics.go#L340-L398)).

## Side Effects
- Mutates in-memory Prometheus counters, gauges, and histograms; `Handler` serves text-format metrics over HTTP.

## Verification
- Run: `go test ./internal/metrics`
