package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mrchypark/rhiza"
	"github.com/thanos-io/objstore/exthttp"
	"github.com/thanos-io/objstore/providers/gcs"
)

const gcsMutationGateEnv = "GOAUTHY_GCS_MUTATION_GATE_ENABLED"

var gcsGateStartup struct {
	once sync.Once
	err  error
}

// Rhiza copies this provider default while opening clients. Install before Open,
// never restore it while clients or background workers may still be constructed.
func configureGCSMutationGate(getenv func(string) string, config rhiza.Config) error {
	enabled, err := gcsMutationGateEnabled(getenv, config, gcs.DefaultConfig.UseGRPC)
	if err != nil || !enabled {
		return err
	}
	gcsGateStartup.once.Do(func() { gcsGateStartup.err = installGCSMutationGate(&gcs.DefaultConfig) })
	return gcsGateStartup.err
}

func gcsMutationGateEnabled(getenv func(string) string, config rhiza.Config, grpc bool) (bool, error) {
	raw := getenv(gcsMutationGateEnv)
	if raw == "" {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", gcsMutationGateEnv)
	}
	if !enabled {
		return false, nil
	}
	if getenv("GOAUTHY_RHIZA_PROFILE") != "standalone" || config.ObjStoreProvider != "gcs" || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck || grpc {
		return false, fmt.Errorf("%s requires standalone native GCS HTTP with before-ack durability", gcsMutationGateEnv)
	}
	return true, nil
}

func installGCSMutationGate(config *gcs.Config) error {
	next := config.HTTPConfig.Transport
	if next == nil {
		var err error
		next, err = exthttp.DefaultTransport(config.HTTPConfig)
		if err != nil {
			return err
		}
	}
	config.HTTPConfig.Transport = newGCSMutationGate(next, time.Second)
	return nil
}

type gcsMutationGate struct {
	next      http.RoundTripper
	interval  time.Duration
	admission chan struct{}
	nextAt    time.Time
}

func newGCSMutationGate(next http.RoundTripper, interval time.Duration) *gcsMutationGate {
	return &gcsMutationGate{next: next, interval: interval, admission: make(chan struct{}, 1)}
}

func (g *gcsMutationGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return g.next.RoundTrip(r)
	}
	canceled := func() (*http.Response, error) {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, r.Context().Err()
	}
	select {
	case g.admission <- struct{}{}:
	case <-r.Context().Done():
		return canceled()
	}
	defer func() { <-g.admission }()
	if delay := time.Until(g.nextAt); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return canceled()
		}
	}
	if r.Context().Err() != nil {
		return canceled()
	}
	response, err := g.next.RoundTrip(r)
	// Failed attempts can have committed remotely; they need the same spacing.
	g.nextAt = time.Now().Add(g.interval)
	return response, err
}
