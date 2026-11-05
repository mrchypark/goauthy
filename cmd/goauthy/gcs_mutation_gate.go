package main

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
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
	gcsGateStartup.once.Do(func() { gcsGateStartup.err = installGCSMutationGate(&gcs.DefaultConfig, config) })
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

func installGCSMutationGate(config *gcs.Config, store rhiza.Config) error {
	next := config.HTTPConfig.Transport
	if next == nil {
		var err error
		next, err = exthttp.DefaultTransport(config.HTTPConfig)
		if err != nil {
			return err
		}
	}
	gate := newGCSMutationGate(next, time.Second)
	gate.bucket = store.ObjStoreBucket
	// Match Rhiza's clusterPrefix construction exactly, not URL/path normalization.
	gate.prefix = path.Join(store.ObjStorePrefix, store.ClusterID)
	config.HTTPConfig.Transport = gate
	return nil
}

type gcsMutationGate struct {
	next           http.RoundTripper
	interval       time.Duration
	bucket, prefix string
	origin         string
	lanes          [3]gcsMutationLane
}

type gcsMutationLane struct {
	admission chan struct{}
	nextAt    time.Time
}

const (
	gcsPublicationLane uint8 = 1 << iota
	gcsHeadLane
	gcsOtherLane
	gcsAllLanes = gcsPublicationLane | gcsHeadLane | gcsOtherLane
)

func newGCSMutationGate(next http.RoundTripper, interval time.Duration) *gcsMutationGate {
	g := &gcsMutationGate{next: next, interval: interval, origin: "https://storage.googleapis.com"}
	for i := range g.lanes {
		g.lanes[i].admission = make(chan struct{}, 1)
	}
	return g
}

// Only the pinned SDK's unambiguous named multipart requests take one lane.
// Unknown/resumable requests fence every lane, including subsequent named retries.
func (g *gcsMutationGate) requestLanes(r *http.Request) uint8 {
	if r.Method != http.MethodPost || r.URL == nil || g.bucket == "" || g.prefix == "" ||
		r.URL.Scheme+"://"+r.URL.Host != g.origin || r.URL.User != nil || r.URL.Fragment != "" ||
		(r.Host != "" && r.Host != r.URL.Host) ||
		r.URL.EscapedPath() != "/upload/storage/v1/b/"+url.PathEscape(g.bucket)+"/o" ||
		len(r.Header.Values("Content-Range")) != 0 || len(r.Header.Values("Content-Type")) != 1 {
		return gcsAllLanes
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["name"]) != 1 || len(query["uploadType"]) != 1 || query.Get("uploadType") != "multipart" {
		return gcsAllLanes
	}
	if _, present := query["upload_id"]; present {
		return gcsAllLanes
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/related" || params["boundary"] == "" {
		return gcsAllLanes
	}
	name := query.Get("name")
	if !strings.HasPrefix(name, g.prefix+"/") {
		return gcsAllLanes
	}
	switch name {
	case g.prefix + "/archive/PUBLISH_LOCK":
		return gcsPublicationLane
	case g.prefix + "/archive/head.bin":
		return gcsHeadLane
	default:
		return gcsOtherLane
	}
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
	selected := g.requestLanes(r)
	var acquired uint8
	defer func() {
		for i := len(g.lanes) - 1; i >= 0; i-- {
			if acquired&(1<<i) != 0 {
				<-g.lanes[i].admission
			}
		}
	}()
	var nextAt time.Time
	// One fixed order prevents cycles when fallback needs all three lanes.
	for i := range g.lanes {
		if selected&(1<<i) == 0 {
			continue
		}
		select {
		case g.lanes[i].admission <- struct{}{}:
			acquired |= 1 << i
		case <-r.Context().Done():
			return canceled()
		}
		if g.lanes[i].nextAt.After(nextAt) {
			nextAt = g.lanes[i].nextAt
		}
	}
	if delay := time.Until(nextAt); delay > 0 {
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
	nextAt = time.Now().Add(g.interval)
	for i := range g.lanes {
		if selected&(1<<i) != 0 {
			g.lanes[i].nextAt = nextAt
		}
	}
	return response, err
}
