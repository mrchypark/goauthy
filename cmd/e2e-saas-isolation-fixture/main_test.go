package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixtureSlowCancellationDrainsAndKeepsMetricsBounded(t *testing.T) {
	if _, err := parseOptions([]string{"-cert", "cert", "-key", "key"}); err != nil {
		t.Fatalf("token-free metrics-only configuration rejected: %v", err)
	}
	const token = "synthetic-fixture-secret"
	privatePath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(privatePath, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readTokenFile(privatePath)
	if err != nil || got != token {
		t.Fatalf("read private token: got valid=%t err=%v", got == token, err)
	}
	if err := os.Chmod(privatePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(privatePath); err == nil {
		t.Fatal("group/world-readable token file was accepted")
	}

	f := newFixture(token)
	server := httptest.NewServer(f)
	defer server.Close()
	client := server.Client()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/healthy", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer wrong-secret")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusUnauthorized || strings.Contains(string(body), token) {
		t.Fatalf("unauthorized response status=%d leaked-or-read-error=%t", response.StatusCode, readErr != nil || strings.Contains(string(body), token))
	}

	ctx, cancel := context.WithCancel(context.Background())
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/slow-body", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = `{"ok":true,"route":"slow-body","items":[1`
	gotPrefix := make([]byte, len(prefix))
	if _, err := io.ReadFull(response.Body, gotPrefix); err != nil || string(gotPrefix) != prefix {
		cancel()
		_ = response.Body.Close()
		t.Fatalf("slow body prefix: %q, err=%v", gotPrefix, err)
	}
	cancel()
	_ = response.Body.Close()

	deadline := time.Now().Add(time.Second)
	for f.counts["slow-body"].active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := f.counts["slow-body"].active.Load(); got != 0 {
		t.Fatalf("slow handler did not drain: active=%d", got)
	}

	metricsResponse, err := client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer metricsResponse.Body.Close()
	var metrics map[string]map[string]int64
	if err := json.NewDecoder(metricsResponse.Body).Decode(&metrics); err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 4 || metrics["slow-body"]["started"] != 1 || metrics["slow-body"]["active"] != 0 || metrics["slow-body"]["completed"] != 1 {
		t.Fatalf("unexpected bounded route metrics: %#v", metrics)
	}
	if _, ok := metrics["healthy"]; !ok {
		t.Fatalf("healthy route missing from metrics: %#v", metrics)
	}

	metricsOnly := httptest.NewServer(newFixture(""))
	defer metricsOnly.Close()
	response, err = metricsOnly.Client().Get(metricsOnly.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token-free metrics status=%d", response.StatusCode)
	}
	response, err = metricsOnly.Client().Get(metricsOnly.URL + "/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token-free healthy route status=%d", response.StatusCode)
	}
}
