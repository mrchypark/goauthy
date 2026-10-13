package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const gateTestPrefix = "fixture/cluster"

func namedGateRequest(ctx context.Context, name string) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, "POST", "https://storage.googleapis.com/upload/storage/v1/b/synthetic/o?uploadType=multipart&name="+url.QueryEscape(name), nil)
	r.Header.Set("Content-Type", "multipart/related; boundary=synthetic")
	return r
}

func TestGCSMutationGatePublicationSchedule(t *testing.T) {
	g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}), time.Second)
	g.bucket, g.prefix = "synthetic", gateTestPrefix
	start := time.Now()
	for _, name := range []string{gateTestPrefix + "/archive/PUBLISH_LOCK", gateTestPrefix + "/archive/extents/new", gateTestPrefix + "/archive/head.bin", gateTestPrefix + "/archive/PUBLISH_LOCK"} {
		if _, err := g.RoundTrip(namedGateRequest(context.Background(), name)); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("publication four attempts elapsed=%s", elapsed)
	if elapsed < time.Second || elapsed >= 2*time.Second {
		t.Fatalf("want one cooldown, got %s", elapsed)
	}
}

func TestGCSMutationGateParser(t *testing.T) {
	g := newGCSMutationGate(nil, time.Second)
	g.bucket, g.prefix = "synthetic", gateTestPrefix
	cases := []struct {
		name   string
		change func(*http.Request)
		want   uint8
	}{
		{"publication", func(r *http.Request) {}, gcsPublicationLane},
		{"head", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("name", gateTestPrefix+"/archive/head.bin")
			r.URL.RawQuery = q.Encode()
		}, gcsHeadLane},
		{"other", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("name", gateTestPrefix+"/checkpoint/PUBLISHER")
			r.URL.RawQuery = q.Encode()
		}, gcsOtherLane},
		{"foreign-prefix", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("name", "foreign/archive/PUBLISH_LOCK")
			r.URL.RawQuery = q.Encode()
		}, gcsAllLanes},
		{"duplicate-name", func(r *http.Request) { r.URL.RawQuery += "&name=x" }, gcsAllLanes},
		{"duplicate-type", func(r *http.Request) { r.URL.RawQuery += "&uploadType=multipart" }, gcsAllLanes},
		{"bad-escape", func(r *http.Request) { r.URL.RawQuery += "&bad=%xy" }, gcsAllLanes},
		{"semicolon", func(r *http.Request) { r.URL.RawQuery += ";bad=x" }, gcsAllLanes},
		{"foreign-bucket", func(r *http.Request) { r.URL.Path = "/upload/storage/v1/b/foreign/o" }, gcsAllLanes},
		{"foreign-host", func(r *http.Request) { r.URL.Host = "example.invalid" }, gcsAllLanes},
		{"host-override", func(r *http.Request) { r.Host = "example.invalid" }, gcsAllLanes},
		{"resumable", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("uploadType", "resumable")
			r.URL.RawQuery = q.Encode()
		}, gcsAllLanes},
		{"upload-id", func(r *http.Request) { r.URL.RawQuery += "&upload_id=" }, gcsAllLanes},
		{"content-range", func(r *http.Request) { r.Header.Set("Content-Range", "bytes 0-2/3") }, gcsAllLanes},
		{"bad-mime", func(r *http.Request) { r.Header.Set("Content-Type", "multipart/related") }, gcsAllLanes},
		{"delete", func(r *http.Request) { r.Method = "DELETE" }, gcsAllLanes},
		{"unnamed", func(r *http.Request) { r.URL.RawQuery = "uploadType=multipart" }, gcsAllLanes},
		{"double-encoded-prefix", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("name", "fixture%2Fcluster/archive/PUBLISH_LOCK")
			r.URL.RawQuery = q.Encode()
		}, gcsAllLanes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := namedGateRequest(context.Background(), gateTestPrefix+"/archive/PUBLISH_LOCK")
			tc.change(r)
			if got := g.requestLanes(r); got != tc.want {
				t.Fatalf("mask=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestGCSMutationGateCrossLaneFences(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sentinel := errors.New("synthetic ambiguous failure")
		g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) { return nil, sentinel }), time.Second)
		g.bucket, g.prefix = "synthetic", gateTestPrefix
		// Named -> unknown -> every named lane. Errors must advance all selected clocks.
		p := gateTestPrefix + "/archive/PUBLISH_LOCK"
		if _, e := g.RoundTrip(namedGateRequest(context.Background(), p)); e != sentinel {
			t.Fatal(e)
		}
		before := time.Now()
		_, _ = g.RoundTrip(gateRequest(context.Background(), "POST"))
		if time.Since(before) != time.Second {
			t.Fatal("named -> unknown lost cooldown")
		}
		done := make(chan time.Duration, 3)
		for _, name := range []string{p, gateTestPrefix + "/archive/head.bin", gateTestPrefix + "/archive/extents/new"} {
			go func(name string) {
				start := time.Now()
				_, _ = g.RoundTrip(namedGateRequest(context.Background(), name))
				done <- time.Since(start)
			}(name)
		}
		for range 3 {
			if elapsed := <-done; elapsed != time.Second {
				t.Fatalf("unknown -> named cooldown=%s", elapsed)
			}
		}
	})
}

func TestGCSMutationGatePartialAcquisitionCancel(t *testing.T) {
	for _, held := range []int{1, 2} {
		t.Run(fmt.Sprint(held), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
				}), time.Second)
				g.bucket, g.prefix = "synthetic", gateTestPrefix
				g.lanes[held].admission <- struct{}{}
				ctx, cancel := context.WithCancel(context.Background())
				r := gateRequest(ctx, "PUT")
				body := &gateBody{Reader: strings.NewReader("synthetic")}
				r.Body = body
				done := make(chan error, 1)
				go func() { _, e := g.RoundTrip(r); done <- e }()
				synctest.Wait()
				for i := 0; i < held; i++ {
					if len(g.lanes[i].admission) != 1 {
						t.Fatalf("lane%d not acquired", i)
					}
				}
				cancel()
				if e := <-done; !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				for i := 0; i < held; i++ {
					if len(g.lanes[i].admission) != 0 || !g.lanes[i].nextAt.IsZero() {
						t.Fatal("leaked permit or changed deadline")
					}
				}
				if !body.closed || calls != 0 {
					t.Fatal("canceled body/dispatched")
				}
				<-g.lanes[held].admission
				if _, e := g.RoundTrip(gateRequest(context.Background(), "PATCH")); e != nil {
					t.Fatal(e)
				}
			})
		})
	}
}

func TestGCSMutationGateIndependentAndUnknownExclusion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		pDone := make(chan struct{})
		g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("X-Hold") == "yes" {
				close(entered)
				<-release
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}), time.Second)
		g.bucket, g.prefix = "synthetic", gateTestPrefix
		p := namedGateRequest(context.Background(), gateTestPrefix+"/archive/PUBLISH_LOCK")
		p.Header.Set("X-Hold", "yes")
		go func() { _, _ = g.RoundTrip(p); close(pDone) }()
		<-entered
		for _, name := range []string{gateTestPrefix + "/archive/head.bin", gateTestPrefix + "/archive/extents/new"} {
			if _, e := g.RoundTrip(namedGateRequest(context.Background(), name)); e != nil {
				t.Fatal(e)
			}
		}
		unknownDone := make(chan struct{})
		go func() { _, _ = g.RoundTrip(gateRequest(context.Background(), "PUT")); close(unknownDone) }()
		synctest.Wait()
		select {
		case <-unknownDone:
			t.Fatal("unknown passed heldP")
		default:
		}
		close(release)
		<-pDone
		<-unknownDone
	})
}

func TestGCSMutationGateMaximumDeadlineAndCooldownCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		g := newGCSMutationGate(gateRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}), time.Second)
		now := time.Now()
		for i := range g.lanes {
			g.lanes[i].nextAt = now.Add(time.Duration(i+1) * time.Second)
		}
		ctx, cancel := context.WithCancel(context.Background())
		body := &gateBody{Reader: strings.NewReader("payload")}
		r := gateRequest(ctx, "POST")
		r.Body = body
		done := make(chan error, 1)
		go func() { _, err := g.RoundTrip(r); done <- err }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		for i := range g.lanes {
			if len(g.lanes[i].admission) != 0 || !g.lanes[i].nextAt.Equal(now.Add(time.Duration(i+1)*time.Second)) {
				t.Fatal("cooldown cancellation leaked/advanced lane")
			}
		}
		if !body.closed || calls != 0 {
			t.Fatal("canceled cooldown dispatched or left body open")
		}
		_, err := g.RoundTrip(gateRequest(context.Background(), "PUT"))
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(now) != 3*time.Second {
			t.Fatalf("must use maximum deadline, got %s", time.Since(now))
		}
	})
}
