package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestDrainSealWaitsForActiveHandlers(t *testing.T) {
	started, cleanup := make(chan struct{}), make(chan struct{})
	d := &requestDrain{done: make(chan struct{}), next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-cleanup
	})}
	go d.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	<-started
	done := d.seal()
	select {
	case <-done:
		t.Fatal("seal completed with an active handler")
	default:
	}
	w := httptest.NewRecorder()
	d.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("new admission after seal")
	}
	close(cleanup)
	<-done
	<-d.seal() // Idempotent, including already drained shutdown.
}
