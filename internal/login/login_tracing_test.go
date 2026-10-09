package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestLoginTraceContextAndSensitiveInputPrivacy(t *testing.T) {
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

	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
		t.Fatalf("authorize status=%d", page.Code)
	}
	const usernameCanary = "trace-user-canary"
	const passwordCanary = "trace-password-canary"
	parentCtx, parent := otel.Tracer("goauthy/login-test").Start(t.Context(), "incoming")
	wantParentID := parent.SpanContext().SpanID()
	req := postLogin(page.Result().Cookies()[0], interactionToken(t, page.Body.String()), usernameCanary, passwordCanary).WithContext(parentCtx)
	response := httptest.NewRecorder()
	start := len(recorder.Ended())
	h.Login(response, req)
	parent.End()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("login status=%d want=%d", response.Code, http.StatusUnauthorized)
	}

	spans := recorder.Ended()[start:]
	var loginSpan, credentialLookup, passwordVerify sdktrace.ReadOnlySpan
	for _, span := range spans {
		switch span.Name() {
		case "login":
			loginSpan = span
		case "credential_lookup":
			credentialLookup = span
		case "password_verify":
			passwordVerify = span
		}
	}
	if loginSpan == nil || credentialLookup == nil || passwordVerify == nil {
		t.Fatalf("missing login/auth spans: login=%t lookup=%t verify=%t", loginSpan != nil, credentialLookup != nil, passwordVerify != nil)
	}
	if got := loginSpan.Parent().SpanID(); got != wantParentID {
		t.Errorf("login parent span ID=%s want incoming parent %s", got, wantParentID)
	}
	for _, span := range []sdktrace.ReadOnlySpan{credentialLookup, passwordVerify} {
		if got := span.Parent().SpanID(); got != loginSpan.SpanContext().SpanID() {
			t.Errorf("%s parent span ID=%s want login span %s", span.Name(), got, loginSpan.SpanContext().SpanID())
		}
		for _, attr := range span.Attributes() {
			if attr.Value.Type() == attribute.STRING && (strings.Contains(attr.Value.AsString(), usernameCanary) || strings.Contains(attr.Value.AsString(), passwordCanary)) {
				t.Errorf("span %q attribute %q contains sensitive input", span.Name(), attr.Key)
			}
		}
	}
}
