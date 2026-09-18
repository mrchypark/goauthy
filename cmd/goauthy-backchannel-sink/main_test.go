package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func controlRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/control", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestTLSFilesFromEnv(t *testing.T) {
	if cert, key, err := tlsFilesFromEnv(func(string) string { return "" }); err != nil || cert != "" || key != "" {
		t.Fatalf("empty TLS config cert=%q key=%q err=%v", cert, key, err)
	}
	if _, _, err := tlsFilesFromEnv(func(name string) string {
		if name == "TLS_CERT_FILE" {
			return "cert"
		}
		return ""
	}); err == nil {
		t.Fatal("accepted incomplete TLS config")
	}
	if cert, key, err := tlsFilesFromEnv(func(name string) string {
		if name == "TLS_CERT_FILE" {
			return "cert"
		}
		return "key"
	}); err != nil || cert != "cert" || key != "key" {
		t.Fatalf("TLS config cert=%q key=%q err=%v", cert, key, err)
	}
}

func TestBackchannelRetriesAndEvents(t *testing.T) {
	s := newSink(1)
	for _, tc := range []struct {
		token string
		want  int
	}{{"first", http.StatusServiceUnavailable}, {"second", http.StatusNoContent}} {
		token, want := tc.token, tc.want
		req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		req.Host = "updated-sink.example:8081"
		req.RemoteAddr = "198.51.100.17:8443"
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("token %q: status = %d, want %d", token, rr.Code, want)
		}
	}

	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/events", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("events response = %d, cache-control = %q", rr.Code, rr.Header().Get("Cache-Control"))
	}
	var got struct{ Events []event }
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 2 || got.Events[0].Host != "updated-sink.example:8081" || got.Events[1].Host != "updated-sink.example:8081" || got.Events[0].Token != "first" || got.Events[0].RemoteIP != "198.51.100.17" || got.Events[0].Status != http.StatusServiceUnavailable || got.Events[1].Token != "second" || got.Events[1].Status != http.StatusNoContent {
		t.Fatalf("events = %#v", got.Events)
	}
}

func TestControlResetsAndConfiguresBackchannel(t *testing.T) {
	s := newSink(1)
	first := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader("logout_token=before"))
	first.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handler().ServeHTTP(httptest.NewRecorder(), first)

	control := httptest.NewRecorder()
	s.handler().ServeHTTP(control, controlRequest(`{"fail_first":0,"delay_first_ms":0,"success_status":200}`))
	if control.Code != http.StatusNoContent || control.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("control response = %d, cache-control = %q", control.Code, control.Header().Get("Cache-Control"))
	}
	req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader("logout_token=after"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("configured success status = %d, want %d", rr.Code, http.StatusOK)
	}

	events := httptest.NewRecorder()
	s.handler().ServeHTTP(events, httptest.NewRequest(http.MethodGet, "/events", nil))
	var got struct{ Events []event }
	if err := json.Unmarshal(events.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || got.Events[0].Attempt != 1 || got.Events[0].Token != "after" || got.Events[0].Status != http.StatusOK {
		t.Fatalf("events after reset = %#v", got.Events)
	}
}

func TestControlRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name, method, path, contentType, body string
		want                                  int
	}{
		{"method", http.MethodGet, "/control", "", "", http.StatusMethodNotAllowed},
		{"query", http.MethodPost, "/control?x=1", "application/json", `{}`, http.StatusBadRequest},
		{"content type", http.MethodPost, "/control", "text/plain", `{}`, http.StatusUnsupportedMediaType},
		{"unknown", http.MethodPost, "/control", "application/json", `{"fail_first":0,"delay_first_ms":0,"success_status":204,"extra":1}`, http.StatusBadRequest},
		{"missing", http.MethodPost, "/control", "application/json", `{"fail_first":0}`, http.StatusBadRequest},
		{"range", http.MethodPost, "/control", "application/json", `{"fail_first":129,"delay_first_ms":0,"success_status":204}`, http.StatusBadRequest},
		{"status", http.MethodPost, "/control", "application/json", `{"fail_first":0,"delay_first_ms":0,"success_status":201}`, http.StatusBadRequest},
		{"size", http.MethodPost, "/control", "application/json", strings.Repeat("x", maxControlBody+1), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSink(1)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rr := httptest.NewRecorder()
			s.handler().ServeHTTP(rr, req)
			if rr.Code != tt.want || rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response = %d, cache-control = %q", rr.Code, rr.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestControlSupportsProductionRetryLimit(t *testing.T) {
	s := newSink(0)
	control := httptest.NewRecorder()
	s.handler().ServeHTTP(control, controlRequest(`{"fail_first":100,"delay_first_ms":0,"success_status":204}`))
	if control.Code != http.StatusNoContent {
		t.Fatalf("control status=%d", control.Code)
	}
	for attempt := 1; attempt <= 101; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader("logout_token=fixture"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, req)
		want := http.StatusServiceUnavailable
		if attempt == 101 {
			want = http.StatusNoContent
		}
		if rr.Code != want {
			t.Fatalf("attempt=%d status=%d want=%d", attempt, rr.Code, want)
		}
	}
}

func TestBackchannelCancellationMarksEventIncomplete(t *testing.T) {
	s := newSink(1)
	control := httptest.NewRecorder()
	s.handler().ServeHTTP(control, controlRequest(`{"fail_first":1,"delay_first_ms":30000,"success_status":204}`))
	if control.Code != http.StatusNoContent {
		t.Fatalf("control status = %d", control.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader("logout_token=cancelled")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handler().ServeHTTP(httptest.NewRecorder(), req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.observations) != 1 || s.observations[0].Token != "cancelled" || s.observations[0].Status != 0 {
		t.Fatalf("observations = %#v", s.observations)
	}
}

func TestBackchannelRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name         string
		method, path string
		contentType  string
		body         string
		want         int
	}{
		{"method", http.MethodGet, "/backchannel", "", "", http.StatusMethodNotAllowed},
		{"query", http.MethodPost, "/backchannel?logout_token=x", "application/x-www-form-urlencoded", "logout_token=x", http.StatusBadRequest},
		{"content type", http.MethodPost, "/backchannel", "application/json", `{"logout_token":"x"}`, http.StatusUnsupportedMediaType},
		{"missing", http.MethodPost, "/backchannel", "application/x-www-form-urlencoded", "", http.StatusBadRequest},
		{"duplicate", http.MethodPost, "/backchannel", "application/x-www-form-urlencoded", "logout_token=x&logout_token=y", http.StatusBadRequest},
		{"extra", http.MethodPost, "/backchannel", "application/x-www-form-urlencoded", "logout_token=x&state=y", http.StatusBadRequest},
		{"oversized", http.MethodPost, "/backchannel", "application/x-www-form-urlencoded", "logout_token=" + strings.Repeat("x", maxRequestBody), http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSink(0)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rr := httptest.NewRecorder()
			s.handler().ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

func TestFailFirstFromEnv(t *testing.T) {
	t.Setenv("FAIL_FIRST", "")
	if got, err := failFirstFromEnv(); err != nil || got != 1 {
		t.Fatalf("default = %d, %v", got, err)
	}
	t.Setenv("FAIL_FIRST", "0")
	if got, err := failFirstFromEnv(); err != nil || got != 0 {
		t.Fatalf("zero = %d, %v", got, err)
	}
	t.Setenv("FAIL_FIRST", "-1")
	if _, err := failFirstFromEnv(); err == nil {
		t.Fatal("negative FAIL_FIRST accepted")
	}
}
