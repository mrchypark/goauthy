package eventlog_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestForceLogoutContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123).In(time.FixedZone("fixture", 9*60*60))
	for _, email := range []string{"alice@example.test", ""} {
		e := eventlog.ForceLogout("operation-1", email, at)
		if len(e.ID) != 43 || e.Type != eventlog.ForcedLogout || e.Level != eventlog.Notice || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data != nil || e.Text == nil || *e.Text != email {
			t.Fatalf("event=%+v", e)
		}
		statement, err := e.Statement("1=1")
		if err != nil || len(statement.Args) != 9 || statement.Args[4] != nil || statement.Args[5] != nil || statement.Args[6] != email {
			t.Fatalf("statement=%+v err=%v", statement, err)
		}
		if e.ID != eventlog.ForceLogout("operation-1", email, at.Add(time.Hour)).ID || e.ID == eventlog.ForceLogout("operation-2", email, at).ID {
			t.Fatal("operation identity must survive retries and distinguish independent requests")
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"ip", "data"} {
			if value, present := wire[field]; !present || value != nil {
				t.Fatalf("%s must be present and null: %s", field, encoded)
			}
		}
	}
}
