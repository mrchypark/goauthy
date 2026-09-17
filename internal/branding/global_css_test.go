package branding

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestGlobalCSSHandlerGetAndHead(t *testing.T) {
	handler := GlobalCSSHandler()
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/auth/v1/theme/global.css", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d", get.Code)
	}
	if get.Header().Get("Content-Type") != "text/css" || get.Header().Get("Cache-Control") != globalCSSCacheControl || get.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("GET headers=%v", get.Header())
	}
	if get.Header().Get("Cache-Control") == "immutable" {
		t.Fatal("unversioned stylesheet was marked immutable")
	}
	if get.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) {
		t.Fatalf("GET content length=%q body=%d", get.Header().Get("Content-Length"), get.Body.Len())
	}
	if !strings.Contains(get.Body.String(), "color: hsl(var(--text));") || !strings.Contains(get.Body.String(), "background-color: hsl(var(--bg));") || !strings.Contains(get.Body.String(), "border-radius: var(--border-radius);") {
		t.Fatal("GET body does not contain theme variable usage")
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/auth/v1/theme/global.css", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%d", head.Code, head.Body.Len())
	}
	if head.Header().Get("Content-Type") != "text/css" || head.Header().Get("Cache-Control") != globalCSSCacheControl || head.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) {
		t.Fatalf("HEAD headers=%v", head.Header())
	}
}

func TestGlobalCSSHandlerMethodBoundary(t *testing.T) {
	response := httptest.NewRecorder()
	GlobalCSSHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/auth/v1/theme/global.css", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status=%d headers=%v", response.Code, response.Header())
	}
}
