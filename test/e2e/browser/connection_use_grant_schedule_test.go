package browser

import (
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestIsolation113FixtureOperationsUseSupportedContract(t *testing.T) {
	operations, err := isolation113FixtureOperations("isolation113-test", "Bearer ", "https://api-key-fixture.e2e.test/healthy")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"account", "slow-headers", "slow-body", "failure"}
	got := make([]string, 0, len(operations))
	for _, operation := range operations {
		got = append(got, operation.ID)
		u, err := url.Parse(operation.URL)
		if err != nil || u.Scheme != "https" || u.Port() != "" {
			t.Fatalf("fixture operation %q has unsupported URL %q", operation.ID, operation.URL)
		}
		if operation.ResponseFields["ok"] != "boolean" {
			t.Fatalf("fixture operation %q response field type=%q", operation.ID, operation.ResponseFields["ok"])
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture operation IDs=%v want=%v", got, want)
	}
}

func TestIsolation113TickLaunchesConcurrentRequests(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls sync.WaitGroup
	launchIsolation113Tick(&calls, func() {
		started <- struct{}{}
		<-release
	}, func() {
		started <- struct{}{}
		<-release
	})

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			calls.Wait()
			t.Fatal("scheduled requests did not start independently")
		}
	}
	close(release)
	calls.Wait()
}
