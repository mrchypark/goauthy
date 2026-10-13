package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cloudstorage "cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func TestGCSMutationGateSDKUploads(t *testing.T) {
	for _, resumable := range []bool{false, true} {
		t.Run(fmt.Sprintf("resumable=%v", resumable), func(t *testing.T) {
			payload := bytes.Repeat([]byte("x"), 64)
			if resumable {
				payload = bytes.Repeat([]byte("r"), 600<<10)
			}
			var received []byte
			posts, puts, retries := 0, 0, 0
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("synthetic SDK request method=%s path=%s uploadType=%s range=%s", r.Method, r.URL.Path, r.URL.Query().Get("uploadType"), r.Header.Get("Content-Range"))
				if r.Method == "POST" && r.URL.Path != "/session" {
					posts++
					if r.URL.Query().Get("ifGenerationMatch") != "42" || r.URL.Query().Get("name") != "synthetic-object" {
						t.Error("missing CAS/name")
					}
					if !resumable && posts == 1 {
						retries++
						_, _ = io.Copy(io.Discard, r.Body)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(429)
						_, _ = io.WriteString(w, `{"error":{"code":429,"message":"synthetic retry","errors":[{"reason":"rateLimitExceeded"}]}}`)
						return
					}
					if r.URL.Query().Get("uploadType") == "resumable" {
						_, _ = io.Copy(io.Discard, r.Body)
						w.Header().Set("Location", server.URL+"/session?upload_id=synthetic")
						w.WriteHeader(200)
						return
					}
					media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
					if e != nil || !strings.HasPrefix(media, "multipart/") {
						t.Error("not multipart")
						w.WriteHeader(400)
						return
					}
					reader := multipart.NewReader(r.Body, params["boundary"])
					if part, e := reader.NextPart(); e == nil {
						_, _ = io.Copy(io.Discard, part)
					} else {
						t.Error(e)
					}
					part, e := reader.NextPart()
					if e != nil {
						t.Error(e)
						w.WriteHeader(400)
						return
					}
					received, _ = io.ReadAll(part)
				} else if r.URL.Path == "/session" && (r.Method == "PUT" || r.Method == "POST") {
					puts++
					data, _ := io.ReadAll(r.Body)
					received = append(received, data...)
					if len(received) < len(payload) {
						w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", len(received)-1))
						w.Header().Set("X-Http-Status-Code-Override", "308")
						w.WriteHeader(200)
						return
					}
				} else {
					t.Errorf("unexpected method %s", r.Method)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"name":"synthetic-object","bucket":"synthetic","generation":"43","size":"%d"}`, len(received))
			}))
			defer server.Close()
			interval := 10 * time.Millisecond
			var mu sync.Mutex
			var completed time.Time
			attempts := 0
			base := http.DefaultTransport.(*http.Transport).Clone()
			defer base.CloseIdleConnections()
			next := gateRoundTripper(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				if !completed.IsZero() && time.Since(completed) < interval {
					t.Error("SDK attempt bypassed cooldown")
				}
				attempts++
				mu.Unlock()
				response, err := base.RoundTrip(r)
				mu.Lock()
				completed = time.Now()
				mu.Unlock()
				return response, err
			})
			gate := newGCSMutationGate(next, interval)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := cloudstorage.NewClient(ctx, option.WithEndpoint(server.URL), option.WithHTTPClient(&http.Client{Transport: gate}), option.WithoutAuthentication())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			writer := client.Bucket("synthetic").Object("synthetic-object").If(cloudstorage.Conditions{GenerationMatch: 42}).NewWriter(ctx)
			writer.ChunkSize = 256 << 10
			if _, err = writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatalf("payload mismatch bytes=%d want=%d", len(received), len(payload))
			}
			if resumable && puts < 3 {
				t.Fatalf("resumable chunks=%d", puts)
			}
			if !resumable && (posts < 2 || retries != 1) {
				t.Fatalf("retry posts=%d retries=%d", posts, retries)
			}
			t.Logf("SDK attempts=%d POST=%d PUT=%d synthetic429=%d", attempts, posts, puts, retries)
		})
	}
}

func TestGCSMutationGateRealSpacingAndReleaseBudget(t *testing.T) {
	var completed time.Time
	var starts []time.Time
	g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
		starts = append(starts, time.Now())
		if !completed.IsZero() && time.Since(completed) < time.Second {
			t.Fatal("less than one second")
		}
		completed = time.Now()
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}), time.Second)
	start := time.Now()
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r := gateRequest(ctx, "POST")
		r.Header.Set("X-Test", strconv.Itoa(i))
		_, err := g.RoundTrip(r)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("three sequential attempts elapsed=%s; uncontended release wait=%s; 5s budget has no contention guarantee", time.Since(start), starts[2].Sub(starts[1]))
}
