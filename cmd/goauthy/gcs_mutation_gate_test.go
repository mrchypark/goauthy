package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/thanos-io/objstore/providers/gcs"
)

type gateRoundTripper func(*http.Request) (*http.Response, error)

func (f gateRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type gateBody struct {
	io.Reader
	closed bool
}

func (b *gateBody) Close() error { b.closed = true; return nil }
func gateRequest(ctx context.Context, method string) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, method, "https://storage.googleapis.com/upload/storage/v1/b/synthetic/o?ifGenerationMatch=42", nil)
	return r
}

func TestGCSMutationGateCancellationAndReadBypass(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" && r.Method != "HEAD" {
			entered <- struct{}{}
			<-release
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}), time.Second)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = g.RoundTrip(gateRequest(context.Background(), "POST")) }()
	<-entered
	for _, method := range []string{"GET", "HEAD"} {
		if _, e := g.RoundTrip(gateRequest(context.Background(), method)); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &gateBody{Reader: strings.NewReader("private synthetic body")}
	r := gateRequest(ctx, "PUT")
	r.Body = body
	finished := make(chan error, 1)
	go func() { _, e := g.RoundTrip(r); finished <- e }()
	select {
	case e := <-finished:
		if !errors.Is(e, context.Canceled) || !body.closed {
			t.Errorf("cancel=%v closed=%v", e, body.closed)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("canceled admission blocked")
	}
	close(release)
	<-done
}

func TestGCSMutationGateErrorCooldownCASBody(t *testing.T) {
	sentinel := errors.New("synthetic failure")
	var mu sync.Mutex
	var last time.Time
	calls := 0
	interval := 20 * time.Millisecond
	g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if !last.IsZero() && time.Since(last) < interval {
			t.Error("cooldown violated")
		}
		data, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if string(data) != "payload" || r.URL.Query().Get("ifGenerationMatch") != "42" || r.Header.Get("X-Test") != "preserve" {
			t.Error("request changed")
		}
		calls++
		time.Sleep(time.Millisecond)
		last = time.Now()
		return nil, sentinel
	}), interval)
	var wg sync.WaitGroup
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		wg.Add(1)
		go func(method string) {
			defer wg.Done()
			r := gateRequest(context.Background(), method)
			r.Body = io.NopCloser(strings.NewReader("payload"))
			r.Header.Set("X-Test", "preserve")
			resp, e := g.RoundTrip(r)
			if resp != nil || e != sentinel {
				t.Error("response/error changed")
			}
		}(method)
	}
	wg.Wait()
	if calls != 4 {
		t.Fatal(calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	body := &gateBody{Reader: strings.NewReader("payload")}
	r := gateRequest(ctx, "PUT")
	r.Body = body
	go func() { time.Sleep(time.Millisecond); cancel() }()
	_, err := g.RoundTrip(r)
	if !errors.Is(err, context.Canceled) || !body.closed {
		t.Fatalf("cooldown cancel=%v closed=%v", err, body.closed)
	}
}

func TestGCSMutationGateConfig(t *testing.T) {
	config := rhiza.Config{ObjStoreProvider: "gcs", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck}
	for _, tc := range []struct {
		raw, profile, provider string
		grpc, want, fail       bool
	}{
		{"", "standalone", "gcs", false, false, false}, {"false", "cluster", "s3", true, false, false},
		{"true", "standalone", "gcs", false, true, false}, {"true", "cluster", "gcs", false, false, true},
		{"true", "dev", "gcs", false, false, true}, {"true", "standalone", "s3", false, false, true},
		{"true", "standalone", "gcs", true, false, true}, {"bad", "standalone", "gcs", false, false, true},
	} {
		t.Run(fmt.Sprintf("%s/%s/%s/grpc=%v", tc.raw, tc.profile, tc.provider, tc.grpc), func(t *testing.T) {
			c := config
			c.ObjStoreProvider = tc.provider
			getenv := func(k string) string {
				if k == gcsMutationGateEnv {
					return tc.raw
				}
				return tc.profile
			}
			got, e := gcsMutationGateEnabled(getenv, c, tc.grpc)
			if got != tc.want || (e != nil) != tc.fail {
				t.Fatalf("enabled=%v err=%v", got, e)
			}
		})
	}
	cfg := gcs.DefaultConfig
	original := gcs.DefaultConfig.HTTPConfig.Transport
	if err := installGCSMutationGate(&cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.HTTPConfig.Transport.(*gcsMutationGate); !ok {
		t.Fatal("not installed")
	}
	if gcs.DefaultConfig.HTTPConfig.Transport != original {
		t.Fatal("test mutated global")
	}
}
func TestGCSMutationGateStartupOnce(t *testing.T) {
	if os.Getenv("GOAUTHY_TEST_GCS_GATE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGCSMutationGateStartupOnce$")
		cmd.Env = append(os.Environ(), "GOAUTHY_TEST_GCS_GATE_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("startup child: %v %s", err, out)
		}
		return
	}
	config := rhiza.Config{ObjStoreProvider: "gcs", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck}
	getenv := func(k string) string {
		if k == gcsMutationGateEnv {
			return "true"
		}
		if k == "GOAUTHY_RHIZA_PROFILE" {
			return "standalone"
		}
		return ""
	}
	if err := configureGCSMutationGate(getenv, config); err != nil {
		t.Fatal(err)
	}
	installed := gcs.DefaultConfig.HTTPConfig.Transport
	if _, ok := installed.(*gcsMutationGate); !ok {
		t.Fatal("gate missing")
	}
	if err := configureGCSMutationGate(getenv, config); err != nil {
		t.Fatal(err)
	}
	if gcs.DefaultConfig.HTTPConfig.Transport != installed {
		t.Fatal("gate installed twice")
	}
}

func TestGCSMutationGateInflightCancellationAndResponse(t *testing.T) {
	entered := make(chan struct{})
	response := &http.Response{StatusCode: 412, Body: http.NoBody}
	g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Cancel") == "yes" {
			close(entered)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return response, nil
	}), time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	r := gateRequest(ctx, "PUT")
	r.Header.Set("X-Cancel", "yes")
	done := make(chan error, 1)
	go func() { _, err := g.RoundTrip(r); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("inflight cancellation blocked")
	}
	got, err := g.RoundTrip(gateRequest(context.Background(), "DELETE"))
	if got != response || err != nil {
		t.Fatal("response not preserved")
	}
}
