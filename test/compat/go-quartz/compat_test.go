package goquartzvet

import (
	"github.com/reugn/go-quartz/quartz"
	"testing"
	"time"
)

// These checks document known incompatibilities, not successful Rauthy parity.
func TestKnownRauthyDifferences(t *testing.T) {
	if _, err := quartz.NewCronTrigger("0 0 0 1 * 2 *"); err == nil {
		t.Fatal("DOM/DOW behavior changed; re-evaluate candidate")
	}
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	trigger, err := quartz.NewCronTriggerWithLoc("0 30 1 * * * *", loc)
	if err != nil {
		t.Fatal(err)
	}
	prev := time.Date(2027, 11, 7, 0, 59, 59, 0, loc).UnixNano()
	// Rauthy's iterator instead yields 2027-11-07T01:30:00-05:00 second.
	for _, expected := range []string{"2027-11-07T01:30:00-04:00", "2027-11-08T01:30:00-05:00"} {
		prev, err = trigger.NextFireTime(prev)
		if err != nil {
			t.Fatal(err)
		}
		if got := time.Unix(0, prev).In(loc).Format(time.RFC3339); got != expected {
			t.Fatalf("candidate behavior changed: got %s, expected %s; re-evaluate parity", got, expected)
		}
	}
}
