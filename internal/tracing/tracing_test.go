package tracing

import (
	"os"
	"testing"
)

func TestInitNormalizesSchemeLessLegacyEndpoints(t *testing.T) {
	// url.Parse reads "collector:4317/path" as scheme "collector", so the
	// exporter would receive no usable endpoint and silently keep the default.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_SERVICE_NAME", "goauthy-test")

	shutdown, err := Init(t.Context())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(t.Context()) }()

	if got, want := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "http://collector:4317/v1/traces"; got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
}
