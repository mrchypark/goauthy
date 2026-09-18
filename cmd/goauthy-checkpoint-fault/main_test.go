package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testBlock = "/bucket/checkpoint/blocks/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.block"

func proxyServer(t *testing.T, upstream http.Handler, dataDir string) (*httptest.Server, *fault) {
	t.Helper()
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)
	target, err := url.Parse(upstreamServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	fault := newFault(dataDir, testBlock)
	proxy := httptest.NewServer(newProxy(target, fault))
	t.Cleanup(proxy.Close)
	return proxy, fault
}

func TestInitialReadPassesThroughBeforeRestoreDirectory(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 128)
	dataDir := t.TempDir()
	proxy, fault := proxyServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testBlock {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		w.Write(payload)
	}), dataDir)
	response, err := http.Get(proxy.URL + testBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("passthrough = %d bytes, %v", len(got), err)
	}
	if status := fault.status(); status.Blocked || status.PartialWritten || status.Cancelled || status.Released {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestStallsAfterPrefixAndReportsRestoreFile(t *testing.T) {
	// Keep the client read size independent of the proxy's configured prefix:
	// reverting the proxy to 64 bytes must fail this full-buffer read.
	const clientReadSize = 32 * 1024
	payload := append(bytes.Repeat([]byte("p"), clientReadSize), bytes.Repeat([]byte("q"), 64)...)
	dataDir := t.TempDir()
	restore := filepath.Join(dataDir, ".rhiza-checkpoint-restore-test")
	if err := os.Mkdir(restore, 0700); err != nil {
		t.Fatal(err)
	}
	proxy, fault := proxyServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(payload) }), dataDir)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(proxy.URL + testBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got := make([]byte, clientReadSize)
	if _, err := io.ReadFull(response.Body, got); err != nil || !bytes.Equal(got, payload[:clientReadSize]) {
		t.Fatalf("prefix = %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(restore, "sqlite.db"), got, 0600); err != nil {
		t.Fatal(err)
	}
	if status := fault.status(); !status.Blocked || !status.PartialWritten || status.Cancelled || status.Released {
		t.Fatalf("status = %+v", status)
	}
	type readResult struct {
		bytes []byte
		err   error
	}
	next := make(chan readResult, 1)
	go func() {
		bytes := make([]byte, 1)
		n, err := response.Body.Read(bytes)
		next <- readResult{bytes: bytes[:n], err: err}
	}()
	select {
	case result := <-next:
		t.Fatalf("response continued before release: %q, %v", result.bytes, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	fault.unblock()
	result := <-next
	if result.err != nil || !bytes.Equal(result.bytes, payload[stallBytes:stallBytes+1]) {
		t.Fatalf("first released byte = %q, %v", result.bytes, result.err)
	}
	rest, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(rest, payload[stallBytes+1:]) {
		t.Fatalf("rest = %q, %v", rest, err)
	}
}

func TestShortSuccessfulResponsePassesThroughWithoutClaimingFault(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, ".rhiza-checkpoint-restore-test"), 0700); err != nil {
		t.Fatal(err)
	}
	short := []byte("short checkpoint response")
	full := bytes.Repeat([]byte("f"), stallBytes+64)
	calls := 0
	proxy, fault := proxyServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Write(short)
			return
		}
		w.Write(full)
	}), dataDir)
	response, err := http.Get(proxy.URL + testBlock)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(got, short) {
		t.Fatalf("short response = %q, %v", got, err)
	}
	if status := fault.status(); status.Blocked || status.PartialWritten || status.Cancelled || status.Released {
		t.Fatalf("short response changed status: %+v", status)
	}
	response, err = http.Get(proxy.URL + testBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadFull(response.Body, make([]byte, stallBytes)); err != nil {
		t.Fatal(err)
	}
	if !fault.status().Blocked {
		t.Fatal("short response consumed the one allowed fault")
	}
	fault.unblock()
}

func TestCancellationStopsStallAndNextRequestPassesThrough(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), stallBytes+64)
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, ".rhiza-checkpoint-restore-test"), 0700); err != nil {
		t.Fatal(err)
	}
	proxy, fault := proxyServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(payload) }), dataDir)
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy.URL+testBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, stallBytes)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = response.Body.Read(make([]byte, 1))
	response.Body.Close()
	if err == nil {
		t.Fatal("stalled request unexpectedly completed")
	}
	deadline := time.Now().Add(time.Second)
	for !fault.status().Cancelled && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !fault.status().Cancelled {
		t.Fatal("cancellation was not recorded")
	}
	response, err = http.Get(proxy.URL + testBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("next request = %d bytes, %v", len(got), err)
	}
}

func TestPreservesHostAndDoesNotBlockFailedRequest(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, ".rhiza-checkpoint-restore-test"), 0700); err != nil {
		t.Fatal(err)
	}
	var (
		host string
		mu   sync.Mutex
	)
	proxy, fault := proxyServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		host = r.Host
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}), dataDir)
	request, err := http.NewRequest(http.MethodGet, proxy.URL+testBlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "signed.example.test:9000"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	mu.Lock()
	gotHost := host
	mu.Unlock()
	if gotHost != request.Host {
		t.Fatalf("host = %q, want %q", gotHost, request.Host)
	}
	if status := fault.status(); status.Blocked || status.Cancelled || status.Released {
		t.Fatalf("failed request changed status: %+v", status)
	}
}
