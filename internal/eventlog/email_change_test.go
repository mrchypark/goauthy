package eventlog_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestEmailChangeContract(t *testing.T) {
	at := time.UnixMilli(1_800_006_000_123).In(time.FixedZone("fixture", 9*60*60))
	for _, text := range []string{"new@example.test", ""} {
		e := eventlog.EmailChange("operation-1", text, at)
		if len(e.ID) != 43 || e.Type != eventlog.UserEmailChange || e.Level != eventlog.Notice || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data != nil || e.Text == nil || *e.Text != text {
			t.Fatalf("event=%+v", e)
		}
		statement, err := e.Statement("1=1")
		if err != nil || len(statement.Args) != 9 || statement.Args[4] != nil || statement.Args[5] != nil || statement.Args[6] != text {
			t.Fatalf("statement=%+v err=%v", statement, err)
		}
		if e.ID != eventlog.EmailChange("operation-1", "different text", at.Add(time.Hour)).ID {
			t.Fatal("retry identity must ignore text and timestamp")
		}
		if e.ID == eventlog.EmailChange("operation-2", text, at).ID || e.ID == eventlog.PasswordReset("operation-1", text, "", at).ID {
			t.Fatal("event identity must distinguish operation and type")
		}
		encoded, err := json.Marshal(e)
		if err != nil || !strings.Contains(string(encoded), `"ip":null`) || !strings.Contains(string(encoded), `"data":null`) || !strings.Contains(string(encoded), `"text":"`+text+`"`) {
			t.Fatalf("json=%s err=%v", encoded, err)
		}
	}
}
