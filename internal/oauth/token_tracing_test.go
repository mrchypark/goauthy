package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTokenHandlerTraceContextAndSafeGrantType(t *testing.T) {
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

	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "token-trace", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(t.Context(), db, randomSecret(t), "machine-client", "client-secret-canary", "http://localhost/callback")
	if err != nil {
		t.Fatal(err)
	}

	canaries := []string{"unknown-grant-canary", "client-secret-canary", "password-canary", "private@example.test"}
	for _, tc := range []struct {
		name, grant, wantGrant string
		wantStatus             int
	}{
		{name: "known grant", grant: "client_credentials", wantGrant: "client_credentials", wantStatus: http.StatusOK},
		{name: "unknown grant", grant: canaries[0], wantGrant: "unknown", wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parentCtx, parent := otel.Tracer("goauthy/oauth-test").Start(t.Context(), "incoming")
			wantParentID := parent.SpanContext().SpanID()
			form := url.Values{
				"grant_type": {tc.grant},
				"scope":      {"goauthy.read"},
				"username":   {canaries[3]},
				"password":   {canaries[2]},
			}
			req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode())).WithContext(parentCtx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth("machine-client", "client-secret-canary")
			response := httptest.NewRecorder()
			start := len(recorder.Ended())
			server.TokenHandler().ServeHTTP(response, req)
			parent.End()
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tc.wantStatus, response.Body.String())
			}

			spans := recorder.Ended()[start:]
			var tokenSpan, fositeSpan sdktrace.ReadOnlySpan
			for _, span := range spans {
				switch span.Name() {
				case "token":
					tokenSpan = span
				case "Fosite.NewAccessRequest":
					fositeSpan = span
				}
			}
			if tokenSpan == nil || fositeSpan == nil {
				t.Fatalf("missing token/Fosite spans: token=%v fosite=%v", tokenSpan != nil, fositeSpan != nil)
			}
			if got := tokenSpan.Parent().SpanID(); got != wantParentID {
				t.Errorf("token parent span ID = %s, want incoming parent %s", got, wantParentID)
			}
			if got := fositeSpan.Parent().SpanID(); got != tokenSpan.SpanContext().SpanID() {
				t.Errorf("Fosite parent span ID = %s, want token span %s", got, tokenSpan.SpanContext().SpanID())
			}
			grantAttribute := ""
			for _, attr := range tokenSpan.Attributes() {
				if string(attr.Key) == "grant_type" {
					grantAttribute = attr.Value.AsString()
				}
			}
			if grantAttribute != tc.wantGrant {
				t.Errorf("grant_type attribute = %q, want %q", grantAttribute, tc.wantGrant)
			}
			for _, span := range spans {
				for _, attr := range span.Attributes() {
					if attr.Value.Type() == attribute.STRING {
						for _, canary := range canaries {
							if strings.Contains(attr.Value.AsString(), canary) {
								t.Errorf("span %q attribute %q contains sensitive canary", span.Name(), attr.Key)
							}
						}
					}
				}
			}
		})
	}
}
