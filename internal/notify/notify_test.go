package notify

import (
	"testing"
	"time"
)

func TestBackoffBounded(t *testing.T) {
	if Backoff(100) != MaxBackoff || Backoff(0) != time.Second {
		t.Fatal("bad backoff")
	}
}
