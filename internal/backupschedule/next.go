package backupschedule

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// Next returns the first matching whole second strictly after after, in its
// location. A zero result means the schedule's supported years are exhausted.
// Walking constant-offset intervals preserves both sides of a DST fold without
// relying on time.Date's unspecified choice of an ambiguous local time.
func (s *Schedule) Next(ctx context.Context, after time.Time) (time.Time, error) {
	loc := after.Location()
	cursor := after.Truncate(time.Second).Add(time.Second)
	// IANA civil offsets are within one day. Reject unusual synthetic zones rather
	// than silently applying this search bound to them.
	limit := time.Date(2101, 1, 2, 0, 0, 0, 0, time.UTC)
	for cursor.Before(limit) {
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		_, offset := cursor.Zone()
		if offset < -86400 || offset > 86400 {
			return time.Time{}, fmt.Errorf("schedule timezone offset exceeds one day")
		}
		_, end := cursor.ZoneBounds()
		if !end.IsZero() && !end.After(cursor) {
			// Go's POSIX rule expansion can report a stale year-end boundary
			// during the last UTC day of a leap year. Do not infer a constant
			// offset beyond that boundary or skip a possible scheduled second.
			// ponytail: second-wise fallback only for stale native bounds;
			// remove when the standard library returns advancing bounds.
			if s.matches(cursor) {
				return cursor, nil
			}
			cursor = cursor.Add(time.Second)
			continue
		}
		wall := time.Date(cursor.Year(), cursor.Month(), cursor.Day(), cursor.Hour(), cursor.Minute(), cursor.Second(), 0, time.UTC)
		candidate, err := s.nextWall(ctx, wall)
		if err != nil {
			return time.Time{}, err
		}
		if !candidate.IsZero() {
			instant := candidate.Add(-time.Duration(offset) * time.Second).In(loc)
			if end.IsZero() || instant.Before(end) {
				return instant, nil
			}
		}
		if end.IsZero() {
			break
		}
		cursor = end.In(loc)
	}
	return time.Time{}, ctx.Err()
}

// nextWall treats UTC as a civil calendar, with inclusive lower bounds. Timezone
// gaps and duplicates are resolved by Next, outside this calendar search.
func (s *Schedule) nextWall(ctx context.Context, lower time.Time) (time.Time, error) {
	for _, year := range s.fields[6] {
		if year < lower.Year() {
			continue
		}
		for _, month := range s.fields[4] {
			if year == lower.Year() && month < int(lower.Month()) {
				continue
			}
			for _, day := range s.fields[3] {
				if err := ctx.Err(); err != nil {
					return time.Time{}, err
				}
				date := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
				if int(date.Month()) != month || !slices.Contains(s.fields[5], int(date.Weekday())+1) {
					continue
				}
				if date.AddDate(0, 0, 1).Compare(lower) <= 0 {
					continue
				}
				sameDay := year == lower.Year() && month == int(lower.Month()) && day == lower.Day()
				for _, hour := range s.fields[2] {
					if sameDay && hour < lower.Hour() {
						continue
					}
					sameHour := sameDay && hour == lower.Hour()
					for _, minute := range s.fields[1] {
						if sameHour && minute < lower.Minute() {
							continue
						}
						sameMinute := sameHour && minute == lower.Minute()
						for _, second := range s.fields[0] {
							if sameMinute && second < lower.Second() {
								continue
							}
							return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC), nil
						}
					}
				}
			}
		}
	}
	return time.Time{}, nil
}

func (s *Schedule) matches(t time.Time) bool {
	values := [7]int{t.Second(), t.Minute(), t.Hour(), t.Day(), int(t.Month()), int(t.Weekday()) + 1, t.Year()}
	for i, value := range values {
		if _, ok := slices.BinarySearch(s.fields[i], value); !ok {
			return false
		}
	}
	return true
}
