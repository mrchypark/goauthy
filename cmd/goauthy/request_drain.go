package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// requestDrain lets shutdown keep storage alive until canceled handlers have
// finished bounded cleanup (notably uncertain refresh persistence).
type requestDrain struct {
	next   http.Handler
	mu     sync.Mutex
	active int
	sealed bool
	done   chan struct{}
	cancel context.CancelFunc
}

// newRequestDrain installs the runtime request lifetime before serving. The
// signal stops acceptance, but must not cancel token/identity/commit mid-drain.
func newRequestDrain(ctx context.Context, server *http.Server) *requestDrain {
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &requestDrain{next: server.Handler, done: make(chan struct{}), cancel: cancel}
	server.Handler = d
	server.BaseContext = func(net.Listener) context.Context { return requestCtx }
	return d
}

// runLifecycle returns whether handlers have finished and storage may close.
// Keep this ordering shared with the runtime integration test: inbound drain,
// outbound seal, bounded uncertainty cleanup, then permission to close storage.
func (d *requestDrain) runLifecycle(ctx context.Context, server, metrics *http.Server, appErr, metricsErr <-chan error, closeOutbound func()) (bool, error) {
	lifecycleErr := lifecycle(ctx, server, metrics, appErr, metricsErr)
	drained := d.seal()
	d.cancel()
	_ = server.Close()
	closeOutbound()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	select {
	case <-drained:
		return true, lifecycleErr
	case <-cleanupCtx.Done():
		return false, errors.Join(lifecycleErr, errors.New("request cleanup did not drain"))
	}
}

func (d *requestDrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.sealed {
		d.mu.Unlock()
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	d.active++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		if d.sealed && d.active == 0 {
			close(d.done)
		}
		d.mu.Unlock()
	}()
	d.next.ServeHTTP(w, r)
}

func (d *requestDrain) seal() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.sealed {
		d.sealed = true
		if d.active == 0 {
			close(d.done)
		}
	}
	return d.done
}
