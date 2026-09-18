package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestIssuedTokenPayload(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123)
	e := eventlog.IssuedToken("op-1", "authorization_code", "client-1", "user@example.com", eventlog.Info, at)
	if e.Type != eventlog.TokenIssued || e.Level != eventlog.Info || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data != nil {
		t.Fatalf("unexpected event fields: %+v", e)
	}
	if e.Text == nil || *e.Text != "client-1 (authorization_code) user@example.com" {
		t.Fatalf("text=%v", e.Text)
	}
}

func TestIssuedTokenEmptyEmail(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_456)
	e := eventlog.IssuedToken("op-2", "client_credentials", "svc-client", "", eventlog.Notice, at)
	if e.Text == nil || *e.Text != "svc-client (client_credentials) " {
		t.Fatalf("text=%v", e.Text)
	}
}

func TestIssuedTokenIDStability(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_789)
	a := eventlog.IssuedToken("op-stable", "code", "c1", "a@b.com", eventlog.Info, at)
	b := eventlog.IssuedToken("op-stable", "code", "c1", "a@b.com", eventlog.Info, at.Add(time.Hour))
	if a.ID != b.ID {
		t.Fatal("ID must be stable across time for same operation")
	}
	c := eventlog.IssuedToken("op-other", "code", "c1", "a@b.com", eventlog.Info, at)
	if a.ID == c.ID {
		t.Fatal("ID must differ for different operation")
	}
}

func TestIssuedTokenStatement(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_999)
	e := eventlog.IssuedToken("op-s", "code", "c1", "a@b.com", eventlog.Warning, at)
	s, err := e.Statement("1=1")
	if err != nil || len(s.Args) != 9 {
		t.Fatalf("statement=%+v err=%v", s, err)
	}
	if s.Args[0] != e.ID || s.Args[1] != at.UnixMilli() || s.Args[2] != 2 || s.Args[3] != "TokenIssued" || s.Args[4] != nil || s.Args[5] != nil || s.Args[6] != "c1 (code) a@b.com" {
		t.Fatalf("unexpected args: %v", s.Args)
	}
}

func TestIssuedTokenInvalidLevel(t *testing.T) {
	at := time.UnixMilli(1_800_000_001_000)
	e := eventlog.IssuedToken("op-bad", "code", "c1", "a@b.com", "bogus", at)
	_, err := e.Statement("1=1")
	if err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestIssuedTokenNoSecretFields(t *testing.T) {
	at := time.UnixMilli(1_800_000_001_234)
	e := eventlog.IssuedToken("op-nosec", "code", "c1", "a@b.com", eventlog.Info, at)
	if e.IP != nil {
		t.Fatal("IP must be nil")
	}
	if e.Data != nil {
		t.Fatal("Data must be nil")
	}
}
