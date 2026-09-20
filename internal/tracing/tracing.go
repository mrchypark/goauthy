package tracing

import (
	"context"
	"net"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

func Init(ctx context.Context) (shutdown func(context.Context) error, err error) {
	if !Enabled() {
		return func(context.Context) error { return nil }, nil
	}

	// The exporter reads these variables as URLs. The previous implementation
	// accepted a bare host:port through WithEndpoint, so normalise that legacy
	// form instead of silently exporting to the default destination.
	normalizeLegacyEndpoint("OTEL_EXPORTER_OTLP_ENDPOINT")
	normalizeLegacyEndpoint("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "goauthy"
	}

	// Let the exporter apply standard environment handling. WithEndpoint takes a
	// bare host:port, so passing a full URL broke it, and WithInsecure forced an
	// HTTPS collector configuration to plaintext.
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// normalizeLegacyEndpoint rewrites a bare host:port value into an http URL.
func normalizeLegacyEndpoint(name string) {
	value := os.Getenv(name)
	if value == "" || strings.Contains(value, "://") {
		return
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		_ = os.Setenv(name, "http://"+value)
	}
}

func NewTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
