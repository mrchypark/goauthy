package backupschedule

import (
	"reflect"
	"testing"
)

func TestParseRustCronLonghand(t *testing.T) {
	schedule, err := Parse("  0,30  5/10  2  ?  January-March/2  Mon,Wed,Fri  2026/2  ")
	if err != nil {
		t.Fatal(err)
	}
	want := [parseFieldCount][]int{
		{0, 30}, {5, 15, 25, 35, 45, 55}, {2}, parseAll(parseBoundsByField[3]),
		{1, 3}, {2, 4, 6}, {2026, 2028, 2030, 2032, 2034, 2036, 2038, 2040, 2042, 2044, 2046, 2048, 2050, 2052, 2054, 2056, 2058, 2060, 2062, 2064, 2066, 2068, 2070, 2072, 2074, 2076, 2078, 2080, 2082, 2084, 2086, 2088, 2090, 2092, 2094, 2096, 2098, 2100},
	}
	if !reflect.DeepEqual(schedule.fields, want) {
		t.Fatalf("fields = %#v, want %#v", schedule.fields, want)
	}
}

func TestParseRustCronWhitespaceWithinFields(t *testing.T) {
	schedule, err := Parse("0 , 30  2 - 3 / 1  *  ?  Jan - Mar / 2  Mon , Wed")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := schedule.fields[0], []int{0, 30}; !reflect.DeepEqual(got, want) {
		t.Fatalf("seconds = %v, want %v", got, want)
	}
	if got, want := schedule.fields[1], []int{2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("minutes = %v, want %v", got, want)
	}
	if got, want := schedule.fields[4], []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("months = %v, want %v", got, want)
	}
}

func TestParseRustCronSequentialTokenRules(t *testing.T) {
	compact, err := Parse("******")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(compact.fields[6], parseAll(parseBoundsByField[6])) {
		t.Fatalf("compact fields = %#v", compact.fields)
	}
	stepped, err := Parse("*/ 2 * * * * *")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stepped.fields[0], []int{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stepped seconds = %v, want %v", got, want)
	}
	for _, expression := range []string{"* /2 * * * *", "*\u00a0* * * * *"} {
		if _, err := Parse(expression); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", expression)
		}
	}
}

func TestParseRustCronShortcutsAndOptionalYear(t *testing.T) {
	weekly, err := Parse("@weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got := weekly.fields[5]; !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("@weekly weekday = %v, want Sunday=1", got)
	}
	if got := weekly.fields[3]; !reflect.DeepEqual(got, parseAll(parseBoundsByField[3])) {
		t.Fatalf("@weekly day-of-month = %v", got)
	}
	six, err := Parse("0 30 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(six.fields[6], parseAll(parseBoundsByField[6])) {
		t.Fatalf("optional year = %v", six.fields[6])
	}
}

func TestParseRustCronRejectsUnsupportedOrInvalidGrammar(t *testing.T) {
	for _, expression := range []string{
		"0 30 2 * *", // Unix five-field syntax is not cron 0.17 longhand.
		"0 30 2 * * * * *",
		"? * * * * *",
		"0 30 2 * ? *",
		"0 30 2 * * 0",
		"60 * * * * *",
		"0 * * 0 * *",
		"0 * * * 13 *",
		"0 * * * * * 1969",
		"0 * * * * * 2101",
		"0/0 * * * * *",
		"0/60 * * * * *",
		"0 * * * January/2 *",
		"0 * * * March-January *",
		"0 * * * * Mon-3",
		"@annually",
	} {
		t.Run(expression, func(t *testing.T) {
			if _, err := Parse(expression); err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", expression)
			}
		})
	}
}

func TestParseRustCronQuestionMarkAndListSemantics(t *testing.T) {
	schedule, err := Parse("*/17 * * ?/2 * ?,Mon")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := schedule.fields[0], []int{0, 17, 34, 51}; !reflect.DeepEqual(got, want) {
		t.Fatalf("seconds = %v, want %v", got, want)
	}
	if got, want := schedule.fields[3], []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}; !reflect.DeepEqual(got, want) {
		t.Fatalf("day-of-month = %v, want %v", got, want)
	}
	if got := schedule.fields[5]; !reflect.DeepEqual(got, parseAll(parseBoundsByField[5])) {
		t.Fatalf("day-of-week = %v", got)
	}
}
