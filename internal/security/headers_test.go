package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	handler := Middleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = nil
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// HTTPS가 아닌 경우 HSTS가 없어야 함
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should not be set on non-HTTPS")
	}

	// 다른 헤더는 항상 설정되어야 함
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", w.Header().Get("X-Frame-Options"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", w.Header().Get("X-Content-Type-Options"))
	}
	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	}
	if w.Header().Get("Permissions-Policy") == "" {
		t.Error("Permissions-Policy should be set")
	}
	if w.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	}
}

func TestMiddlewareHTTPS(t *testing.T) {
	config := DefaultConfig()
	handler := Middleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// X-Forwarded-Proto로 HTTPS 시뮬레이션
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Strict-Transport-Security") != config.HSTS {
		t.Errorf("HSTS = %q, want %q", w.Header().Get("Strict-Transport-Security"), config.HSTS)
	}
}

func TestAPIConfig(t *testing.T) {
	config := APIConfig()

	handler := Middleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("API Referrer-Policy = %q, want no-referrer", w.Header().Get("Referrer-Policy"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
}

func TestCSRFProtectionMiddleware(t *testing.T) {
	handler := CSRFProtectionMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		fetchSite  string
		wantStatus int
	}{
		{"GET allowed", "GET", "cross-site", http.StatusOK},
		{"HEAD allowed", "HEAD", "cross-site", http.StatusOK},
		{"OPTIONS allowed", "OPTIONS", "cross-site", http.StatusOK},
		{"POST same-origin", "POST", "same-origin", http.StatusOK},
		{"POST cross-site blocked", "POST", "cross-site", http.StatusForbidden},
		{"POST no fetch metadata", "POST", "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	allowedOrigins := []string{"https://example.com", "https://app.example.com"}
	handler := CORSMiddleware(allowedOrigins)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		origin         string
		wantOrigin     string
		wantStatus     int
		wantAllowCreds bool
	}{
		{"allowed origin", "https://example.com", "https://example.com", http.StatusOK, true},
		{"another allowed", "https://app.example.com", "https://app.example.com", http.StatusOK, true},
		{"disallowed origin", "https://evil.com", "", http.StatusOK, false},
		{"preflight", "https://example.com", "https://example.com", http.StatusNoContent, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := "GET"
			if tt.name == "preflight" {
				method = "OPTIONS"
			}
			req := httptest.NewRequest(method, "/", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Errorf("Allow-Origin = %q, want %q", got, tt.wantOrigin)
			}
			if tt.wantAllowCreds {
				if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
					t.Errorf("Allow-Credentials = %q, want true", got)
				}
			}
		})
	}
}

func TestIsSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"same https", "example.com", "https://example.com", true},
		{"same http", "example.com", "http://example.com", true},
		{"different host", "example.com", "https://evil.com", false},
		{"with port same", "example.com:8080", "https://example.com:8080", true},
		{"with port diff", "example.com:8080", "https://example.com:9090", false},
		{"path ignored", "example.com", "https://example.com/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = tt.host
			if got := isSameOrigin(r, tt.origin); got != tt.want {
				t.Errorf("isSameOrigin(%q, %q) = %v, want %v", tt.host, tt.origin, got, tt.want)
			}
		})
	}
}
