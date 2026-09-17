package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestJWKSRotatedContract(t *testing.T) {
	at := time.UnixMilli(1_800_004_000_123)
	e := eventlog.JWKSRotated("old/new", at)
	if e.Type != eventlog.JwksRotated || e.Level != eventlog.Notice || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data != nil || e.Text != nil {
		t.Fatalf("event=%#v", e)
	}
	if e.ID != eventlog.JWKSRotated("old/new", at.Add(time.Hour)).ID || e.ID == eventlog.JWKSRotated("new/next", at).ID {
		t.Fatal("event identity must depend on rotation, not caller time")
	}
	stmt, err := e.Statement("1=1")
	if err != nil || len(stmt.Args) != 9 || stmt.Args[4] != nil || stmt.Args[5] != nil || stmt.Args[6] != nil {
		t.Fatalf("statement=%#v err=%v", stmt, err)
	}
}
