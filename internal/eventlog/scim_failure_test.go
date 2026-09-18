package eventlog_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestScimFailurePayloadAndIdentity(t *testing.T) {
	at := time.UnixMilli(1_800_005_000_123)
	e := eventlog.ScimFailure("op-1", "client", `UserCreateUpdate("ext")`, 7, at)
	same := eventlog.ScimFailure("op-1", "other", "UserDelete(\"x\")", 9, at.Add(time.Second))
	different := eventlog.ScimFailure("op-2", "client", `UserCreateUpdate("ext")`, 7, at)
	if e.ID != same.ID || e.ID == different.ID || e.Type != eventlog.ScimTaskFailed || e.Level != eventlog.Critical || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data == nil || *e.Data != 7 || e.Text == nil || *e.Text != `client / UserCreateUpdate("ext")` {
		t.Fatalf("event=%#v same=%#v different=%#v", e, same, different)
	}
	encoded, err := json.Marshal(e)
	if err != nil || !strings.Contains(string(encoded), `"ip":null`) || !strings.Contains(string(encoded), `"text":"client / UserCreateUpdate(\"ext\")"`) {
		t.Fatalf("json=%s err=%v", encoded, err)
	}
}
