package loginpolicy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/rhiza"
)

func TestAutomaticBlacklistFailureEventsUseThresholdsAndHostIP(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.Unix(1_800_000_000, 0).UTC()
	for attempt := 1; attempt <= 27; attempt++ {
		if _, err := store.Failure(context.Background(), "192.0.2.90", now); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if attempt == 7 || attempt == 9 {
			rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='IpBlacklisted' AND ip='192.0.2.90'`, Consistency: rhiza.ConsistencyLinearizable})
			want := int64(1)
			if err != nil || rows.Rows[0][0] != want {
				t.Fatalf("nonthreshold count at %d=%#v err=%v", attempt, rows.Rows, err)
			}
		}
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT e.timestamp,e.level,e.ip,e.data,e.text FROM event_log e JOIN event_log_order o ON o.event_id=e.id WHERE e.typ='IpBlacklisted' ORDER BY o.sequence`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 7 {
		t.Fatalf("blacklist events=%#v err=%v", rows.Rows, err)
	}
	for i, row := range rows.Rows {
		want := now.Unix() + []int64{60, 600, 900, 3600, 86400, 86400, 86400}[i]
		if row[0] != now.UnixMilli() || row[1] != int64(2) || row[2] != "192.0.2.90" || row[3] != want || row[4] != nil {
			t.Fatalf("event payload=%#v", row)
		}
	}
}

func TestAutomaticBlacklistConcurrentThresholdEmitsOneEventPerCommittedFailure(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	store := NewStoreWithBlacklist(db, blacklist)
	now := time.Unix(1_800_000_000, 0).UTC()
	for attempt := 0; attempt < 27; attempt++ {
		if _, err := store.Failure(context.Background(), "2001:db8::90", now); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log WHERE typ='IpBlacklisted' AND ip='2001:db8::90'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(7) {
		t.Fatalf("IPv6 events=%#v err=%v", rows.Rows, err)
	}
}

func TestAutomaticBlacklistConcurrentThresholdEmitsExactlyOneAtSeven(t *testing.T) {
	db := testDB(t)
	blacklist := ipblacklist.NewStore(db, 10000)
	first, second := NewStoreWithBlacklist(db, blacklist), NewStoreWithBlacklist(db, blacklist)
	now := time.Unix(1_800_000_000, 0).UTC()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 7; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.Failure(context.Background(), "192.0.2.91", now); err != nil {
				t.Errorf("failure: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*),COALESCE(MAX(data),0) FROM event_log WHERE typ='IpBlacklisted' AND ip='192.0.2.91'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != now.Unix()+60 {
		t.Fatalf("concurrent events=%#v err=%v", rows.Rows, err)
	}
}
