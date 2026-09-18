package tracing

import (
	"net/http"
	"os"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func Middleware(next http.Handler) http.Handler {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return next
	}
	return &tracingHandler{next: next}
}

type tracingHandler struct {
	next http.Handler
}

func (h *tracingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	spanCtx, span := trace.SpanFromContext(r.Context()).TracerProvider().
		Tracer("goauthy/http").Start(r.Context(), r.Method+" "+r.URL.Path,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.url", r.URL.String()),
			attribute.String("http.host", r.Host),
			attribute.String("http.user_agent", r.UserAgent()),
		),
	)
	defer span.End()

	sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(sw, r.WithContext(spanCtx))

	span.SetAttributes(
		attribute.Int("http.status_code", sw.status),
	)
	if sw.status >= 500 {
		span.SetAttributes(attribute.Bool("error", true))
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sw *statusRecorder) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
