package main

import (
	"net/http"
	"sync"
)

// requestDrain lets shutdown keep storage alive until canceled handlers have
// finished bounded cleanup (notably uncertain refresh persistence).
type requestDrain struct {
	next   http.Handler
	mu     sync.Mutex
	active int
	sealed bool
	done   chan struct{}
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
