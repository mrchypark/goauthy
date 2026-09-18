package backupschedule

import (
	"context"
	"errors"
	"testing"
	"time"
	_ "time/tzdata"
)

func TestNextCalendarAndDST(t *testing.T) {
	for _, tc := range []struct {
		expression, zone, after string
		want                    []string
	}{
		{"0 30 2 * * * *", "UTC", "2027-01-01T02:29:59Z", []string{"2027-01-01T02:30:00Z"}},
		{"0 0 0 1 * 1 2027", "UTC", "2027-01-01T00:00:00Z", []string{"2027-08-01T00:00:00Z"}},
		{"0 0 0 1 1 * 2100", "UTC", "2099-12-31T00:00:00Z", []string{"2100-01-01T00:00:00Z"}},
		{"0 30 2 * * * *", "America/New_York", "2027-03-14T01:59:59-05:00", []string{"2027-03-15T02:30:00-04:00"}},
		{"0 30 1 * * * *", "America/New_York", "2027-11-07T00:59:59-04:00", []string{"2027-11-07T01:30:00-04:00", "2027-11-07T01:30:00-05:00", "2027-11-08T01:30:00-05:00"}},
		{"0 * 1 * * * *", "America/New_York", "2027-11-07T01:30:00-05:00", []string{"2027-11-07T01:31:00-05:00", "2027-11-07T01:32:00-05:00"}},
		{"0 45 1 * * * *", "Australia/Lord_Howe", "2027-04-04T01:44:59+11:00", []string{"2027-04-04T01:45:00+11:00", "2027-04-04T01:45:00+10:30"}},
		{"* * * * * * *", "UTC", "2027-01-01T00:00:00.5Z", []string{"2027-01-01T00:00:01Z", "2027-01-01T00:00:02Z"}},
	} {
		t.Run(tc.expression+tc.zone, func(t *testing.T) {
			s, err := Parse(tc.expression)
			if err != nil {
				t.Fatal(err)
			}
			loc, err := time.LoadLocation(tc.zone)
			if err != nil {
				t.Fatal(err)
			}
			prev, err := time.Parse(time.RFC3339Nano, tc.after)
			if err != nil {
				t.Fatal(err)
			}
			prev = prev.In(loc)
			for _, want := range tc.want {
				got, err := s.Next(context.Background(), prev)
				if err != nil {
					t.Fatal(err)
				}
				if got.Format(time.RFC3339) != want || !got.After(prev) {
					t.Fatalf("after %s got %s want %s", prev, got, want)
				}
				prev = got
			}
		})
	}
}

func TestNextExhaustionAndCancellation(t *testing.T) {
	s, err := Parse("0 0 0 29 2 * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := s.Next(context.Background(), after)
	if err != nil || !got.IsZero() {
		t.Fatalf("%s %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.Next(ctx, after); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// Independent second-by-second oracle around clock transitions. It does not
// share Next's calendar search or timezone interval logic.
func TestNextMatchesChronologicalSeconds(t *testing.T) {
	for _, tc := range []struct{ zone, start string }{
		{"America/New_York", "2027-03-14T00:55:00-05:00"},
		{"America/New_York", "2027-11-07T00:55:00-04:00"},
		{"Australia/Lord_Howe", "2027-04-04T00:55:00+11:00"},
		{"Pacific/Apia", "2011-12-29T23:55:00-10:00"},
	} {
		t.Run(tc.zone+tc.start, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.zone)
			if err != nil {
				t.Fatal(err)
			}
			prev, err := time.Parse(time.RFC3339, tc.start)
			if err != nil {
				t.Fatal(err)
			}
			prev = prev.In(loc)
			s, err := Parse("0 */15 * * * * *")
			if err != nil {
				t.Fatal(err)
			}
			for range 20 {
				want := prev.Add(time.Second)
				for want.Second() != 0 || want.Minute()%15 != 0 {
					want = want.Add(time.Second)
				}
				got, err := s.Next(context.Background(), prev)
				if err != nil {
					t.Fatal(err)
				}
				if !got.Equal(want) {
					t.Fatalf("after %s got %s want %s", prev, got, want)
				}
				prev = got
			}
		})
	}
}

func TestNextFutureZoneBounds(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ expression, after, want string }{
		{"0 0 0 1 1 * 2100", "2027-01-02T00:00:00-05:00", "2100-01-01T00:00:00-05:00"},
		{"0 0 19 30 12 * 2040", "2040-12-30T18:59:59-05:00", "2040-12-30T19:00:00-05:00"},
		{"0 0 20 30 12 * 2040", "2040-12-30T19:00:00-05:00", "2040-12-30T20:00:00-05:00"},
		{"0 0 0 30 2 * *", "2027-01-02T00:00:00-05:00", ""},
	} {
		s, err := Parse(tc.expression)
		if err != nil {
			t.Fatal(err)
		}
		after, err := time.Parse(time.RFC3339, tc.after)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Next(context.Background(), after.In(loc))
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "" {
			if !got.IsZero() {
				t.Fatal(got)
			}
		} else if got.Format(time.RFC3339) != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}
