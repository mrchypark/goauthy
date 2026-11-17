package main

import (
	"errors"
	"sync"
	"time"
)

const (
	terminationGracePeriod = 60 * time.Second
	serverShutdownTimeout  = 10 * time.Second
	requestCleanupTimeout  = 6 * time.Second
	workerShutdownTimeout  = 20 * time.Second
	backupShutdownTimeout  = 3 * time.Second
	rhizaShutdownTimeout   = 5 * time.Second
)

func cancelAndWait(cancel func(), workers *sync.WaitGroup, timeout time.Duration) bool {
	if cancel != nil {
		cancel()
	}
	if workers == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func closeWithin(closeFn func() error, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errors.New("shutdown exceeded its time budget")
	}
}
