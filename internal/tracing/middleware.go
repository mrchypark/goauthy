package tracing

import (
	"net/http"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Enabled reports whether trace export is configured. The exporter applies
// standard environment handling, so either the general or the traces-specific
// endpoint may select it.
func Enabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

func Middleware(next http.Handler) http.Handler {
	if !Enabled() {
		return next
	}
	return &tracingHandler{next: next}
}

type tracingHandler struct {
	next http.Handler
}

func (h *tracingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Use the installed provider instead of the request context: an ordinary
	// request carries no span, so the context lookup silently supplied the
	// no-op tracer and produced no request spans.
	spanCtx, span := otel.Tracer("goauthy/http").Start(r.Context(), r.Method+" "+r.URL.Path,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("http.method", r.Method),
			// Path only: query strings can carry authorization codes and tokens.
			attribute.String("http.target", r.URL.Path),
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

// Unwrap lets http.ResponseController reach the underlying writer. Without it,
// SetWriteDeadline and Flush failed inside event streams whenever tracing was
// enabled, so the stream reported itself unavailable.
func (sw *statusRecorder) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}
