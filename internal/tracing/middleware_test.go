package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMiddlewarePreservesResponseController(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

	var deadlineErr, flushErr error
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		deadlineErr = controller.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(w, "event")
		flushErr = controller.Flush()
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "event" {
		t.Fatalf("body = %q, want %q", body, "event")
	}
	if deadlineErr != nil {
		t.Fatalf("SetWriteDeadline through the tracing middleware: %v", deadlineErr)
	}
	if flushErr != nil {
		t.Fatalf("Flush through the tracing middleware: %v", flushErr)
	}
}

func TestMiddlewareRecordsRequestSpanWithoutQuerySecrets(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	server := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/oidc/token?code=bearer-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	attributes := map[string]string{}
	for _, item := range spans[0].Attributes() {
		attributes[string(item.Key)] = item.Value.Emit()
	}
	if attributes["http.target"] != "/oidc/token" {
		t.Errorf("http.target = %q, want the path only", attributes["http.target"])
	}
	if attributes["http.status_code"] != "418" {
		t.Errorf("http.status_code = %q, want 418", attributes["http.status_code"])
	}
}
