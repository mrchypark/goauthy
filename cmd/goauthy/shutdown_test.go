package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestShutdownBudgetFitsTerminationGrace(t *testing.T) {
	maximum := 2*serverShutdownTimeout + requestCleanupTimeout + workerShutdownTimeout + backupShutdownTimeout + rhizaShutdownTimeout
	if maximum >= terminationGracePeriod {
		t.Fatalf("maximum shutdown %s leaves no margin below %s", maximum, terminationGracePeriod)
	}
}

func TestCancelAndWaitIsBounded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-block
	}()
	if cancelAndWait(nil, &workers, 10*time.Millisecond) {
		t.Fatal("worker wait exceeded its budget without reporting it")
	}
}

func TestCloseWithinIsBounded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	err := closeWithin(func() error {
		<-block
		return nil
	}, 10*time.Millisecond)
	if err == nil {
		t.Fatal("close without a deadline reported success")
	}
	if got := closeWithin(func() error { return errors.New("close failed") }, time.Second); got == nil || got.Error() != "close failed" {
		t.Fatalf("bounded close error=%v", got)
	}
}
