// Package backupschedule parses cron 0.17 backup schedule expressions.
// Execution is deliberately separate from parsing.
package backupschedule

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const parseFieldCount = 7

// Schedule stores allowed values in seconds, minutes, hours, day-of-month,
// month, day-of-week, and year order. Values are sorted and unique.
type Schedule struct {
	fields [parseFieldCount][]int
}

type parseBounds struct {
	min, max int
	allowAny bool
	names    map[string]int
}

var parseBoundsByField = [parseFieldCount]parseBounds{
	{min: 0, max: 59},
	{min: 0, max: 59},
	{min: 0, max: 23},
	{min: 1, max: 31, allowAny: true},
	{min: 1, max: 12, names: map[string]int{
		"jan": 1, "january": 1, "feb": 2, "february": 2,
		"mar": 3, "march": 3, "apr": 4, "april": 4, "may": 5,
		"jun": 6, "june": 6, "jul": 7, "july": 7, "aug": 8,
		"august": 8, "sep": 9, "september": 9, "oct": 10,
		"october": 10, "nov": 11, "november": 11, "dec": 12,
	}},
	{min: 1, max: 7, allowAny: true, names: map[string]int{
		"sun": 1, "sunday": 1, "mon": 2, "monday": 2,
		"tue": 3, "tues": 3, "tuesday": 3, "wed": 4,
		"wednesday": 4, "thu": 5, "thurs": 5, "thursday": 5,
		"fri": 6, "friday": 6, "sat": 7, "saturday": 7,
	}},
	{min: 1970, max: 2100},
}

// Parse accepts cron 0.17's six- or seven-field longhand syntax and its five
// keyword shorthands. It intentionally does not accept a Unix five-field form.
func Parse(expression string) (*Schedule, error) {
	if fields, ok := parseShorthand(expression); ok {
		return &Schedule{fields: fields}, nil
	}
	cursor := parseCursor{text: expression}
	var schedule Schedule
	for i := range 6 {
		values, err := parseField(&cursor, parseBoundsByField[i])
		if err != nil {
			return nil, fmt.Errorf("cron field %d: %w", i+1, err)
		}
		schedule.fields[i] = values
	}
	if !cursor.eof() {
		values, err := parseField(&cursor, parseBoundsByField[6])
		if err != nil {
			return nil, fmt.Errorf("cron field 7: %w", err)
		}
		schedule.fields[6] = values
		if !cursor.eof() {
			return nil, fmt.Errorf("cron expression has trailing input")
		}
	} else {
		schedule.fields[6] = parseAll(parseBoundsByField[6])
	}
	return &schedule, nil
}

func parseSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func parseShorthand(expression string) ([parseFieldCount][]int, bool) {
	var fields [parseFieldCount][]int
	cursor := parseCursor{text: expression}
	cursor.skipSpace()
	keywordStart := cursor.pos
	for !cursor.eof() && !parseSpace(cursor.text[cursor.pos]) {
		cursor.pos++
	}
	keyword := cursor.text[keywordStart:cursor.pos]
	cursor.skipSpace()
	if !cursor.eof() {
		return fields, false
	}
	for i, bounds := range parseBoundsByField {
		fields[i] = parseAll(bounds)
	}
	switch keyword {
	case "@yearly":
		fields[0], fields[1], fields[2], fields[3], fields[4] = []int{0}, []int{0}, []int{0}, []int{1}, []int{1}
	case "@monthly":
		fields[0], fields[1], fields[2], fields[3] = []int{0}, []int{0}, []int{0}, []int{1}
	case "@weekly":
		fields[0], fields[1], fields[2], fields[5] = []int{0}, []int{0}, []int{0}, []int{1}
	case "@daily":
		fields[0], fields[1], fields[2] = []int{0}, []int{0}, []int{0}
	case "@hourly":
		fields[0], fields[1] = []int{0}, []int{0}
	default:
		return fields, false
	}
	return fields, true
}

type parseCursor struct {
	text string
	pos  int
}

func (c *parseCursor) eof() bool { return c.pos == len(c.text) }

func (c *parseCursor) skipSpace() {
	for !c.eof() && parseSpace(c.text[c.pos]) {
		c.pos++
	}
}

func parseField(cursor *parseCursor, bounds parseBounds) ([]int, error) {
	cursor.skipSpace()
	if cursor.eof() {
		return nil, fmt.Errorf("empty field")
	}
	selected := make(map[int]struct{})
	for {
		values, err := parseRootSpecifier(cursor, bounds)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			selected[value] = struct{}{}
		}
		if cursor.eof() || cursor.text[cursor.pos] != ',' {
			break
		}
		cursor.pos++
	}
	cursor.skipSpace()
	values := make([]int, 0, len(selected))
	for value := range selected {
		values = append(values, value)
	}
	sort.Ints(values)
	return values, nil
}

func parseRootSpecifier(cursor *parseCursor, bounds parseBounds) ([]int, error) {
	kind, start, end, err := parseSpecifier(cursor, bounds)
	if err != nil {
		return nil, err
	}
	if cursor.eof() || cursor.text[cursor.pos] != '/' {
		return parseSpecifierValues(kind, start, end, bounds)
	}
	cursor.pos++
	if kind == parseNamedPoint {
		return nil, fmt.Errorf("named point cannot have a step")
	}
	stepText, ok := parseDigits(cursor)
	if !ok {
		return nil, fmt.Errorf("invalid step")
	}
	step, err := parseNumber(stepText)
	if err != nil || step < 1 || step > bounds.max {
		return nil, fmt.Errorf("invalid step")
	}
	values, err := parseSpecifierValues(kind, start, end, bounds)
	if err != nil {
		return nil, err
	}
	if kind == parsePoint {
		values = parseRange(start, bounds.max)
	}
	return parseEvery(values, step), nil
}

type parseSpecifierKind uint8

const (
	parseAllSpecifier parseSpecifierKind = iota
	parsePoint
	parseRangeSpecifier
	parseNamedPoint
)

func parseSpecifier(cursor *parseCursor, bounds parseBounds) (parseSpecifierKind, int, int, error) {
	if !cursor.eof() && cursor.text[cursor.pos] == '*' {
		cursor.pos++
		return parseAllSpecifier, 0, 0, nil
	}
	if !cursor.eof() && cursor.text[cursor.pos] == '?' && bounds.allowAny {
		cursor.pos++
		return parseAllSpecifier, 0, 0, nil
	}
	if !cursor.eof() && cursor.text[cursor.pos] == '?' {
		return 0, 0, 0, fmt.Errorf("question mark is only valid for day-of-month or day-of-week")
	}
	if kind, start, end, ok, err := parseNumericRange(cursor, bounds); ok {
		return kind, start, end, err
	}
	if text, ok := parseDigits(cursor); ok {
		value, _, err := parseValue(text, bounds)
		return parsePoint, value, value, err
	}
	if kind, start, end, ok, err := parseNamedRange(cursor, bounds); ok {
		return kind, start, end, err
	}
	if text, ok := parseName(cursor); ok {
		value, named, err := parseValue(text, bounds)
		if err != nil || !named {
			return 0, 0, 0, err
		}
		return parseNamedPoint, value, value, nil
	}
	return 0, 0, 0, fmt.Errorf("invalid specifier")
}

func parseNumericRange(cursor *parseCursor, bounds parseBounds) (parseSpecifierKind, int, int, bool, error) {
	saved := cursor.pos
	left, ok := parseDigits(cursor)
	if !ok || cursor.eof() || cursor.text[cursor.pos] != '-' {
		cursor.pos = saved
		return 0, 0, 0, false, nil
	}
	cursor.pos++
	right, ok := parseDigits(cursor)
	if !ok {
		return 0, 0, 0, true, fmt.Errorf("invalid range")
	}
	start, _, err := parseValue(left, bounds)
	if err != nil {
		return 0, 0, 0, true, err
	}
	end, _, err := parseValue(right, bounds)
	if err != nil || start > end {
		return 0, 0, 0, true, fmt.Errorf("invalid range")
	}
	return parseRangeSpecifier, start, end, true, nil
}

func parseNamedRange(cursor *parseCursor, bounds parseBounds) (parseSpecifierKind, int, int, bool, error) {
	saved := cursor.pos
	left, ok := parseName(cursor)
	if !ok || cursor.eof() || cursor.text[cursor.pos] != '-' {
		cursor.pos = saved
		return 0, 0, 0, false, nil
	}
	cursor.pos++
	right, ok := parseName(cursor)
	if !ok {
		return 0, 0, 0, true, fmt.Errorf("invalid range")
	}
	start, leftNamed, err := parseValue(left, bounds)
	if err != nil || !leftNamed {
		return 0, 0, 0, true, fmt.Errorf("invalid range")
	}
	end, rightNamed, err := parseValue(right, bounds)
	if err != nil || !rightNamed || start > end {
		return 0, 0, 0, true, fmt.Errorf("invalid range")
	}
	return parseRangeSpecifier, start, end, true, nil
}

func parseDigits(cursor *parseCursor) (string, bool) {
	cursor.skipSpace()
	start := cursor.pos
	for !cursor.eof() && cursor.text[cursor.pos] >= '0' && cursor.text[cursor.pos] <= '9' {
		cursor.pos++
	}
	if cursor.pos == start {
		return "", false
	}
	text := cursor.text[start:cursor.pos]
	cursor.skipSpace()
	return text, true
}

func parseName(cursor *parseCursor) (string, bool) {
	cursor.skipSpace()
	start := cursor.pos
	for !cursor.eof() && ((cursor.text[cursor.pos] >= 'a' && cursor.text[cursor.pos] <= 'z') || (cursor.text[cursor.pos] >= 'A' && cursor.text[cursor.pos] <= 'Z')) {
		cursor.pos++
	}
	if cursor.pos == start {
		return "", false
	}
	text := cursor.text[start:cursor.pos]
	cursor.skipSpace()
	return text, true
}

func parseValue(text string, bounds parseBounds) (int, bool, error) {
	if number, err := parseNumber(text); err == nil {
		if number < bounds.min || number > bounds.max {
			return 0, false, fmt.Errorf("value %d is outside %d..%d", number, bounds.min, bounds.max)
		}
		return number, false, nil
	}
	if !parseAlpha(text) || bounds.names == nil {
		return 0, false, fmt.Errorf("invalid value %q", text)
	}
	value, ok := bounds.names[strings.ToLower(text)]
	if !ok {
		return 0, false, fmt.Errorf("invalid value %q", text)
	}
	return value, true, nil
}

func parseNumber(text string) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("empty number")
	}
	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("not a decimal number")
		}
	}
	return strconv.Atoi(text)
}

func parseAlpha(text string) bool {
	if text == "" {
		return false
	}
	for i := range len(text) {
		if !(text[i] >= 'a' && text[i] <= 'z') && !(text[i] >= 'A' && text[i] <= 'Z') {
			return false
		}
	}
	return true
}

func parseSpecifierValues(kind parseSpecifierKind, start, end int, bounds parseBounds) ([]int, error) {
	switch kind {
	case parseAllSpecifier:
		return parseAll(bounds), nil
	case parsePoint, parseNamedPoint:
		return []int{start}, nil
	case parseRangeSpecifier:
		return parseRange(start, end), nil
	default:
		return nil, fmt.Errorf("invalid specifier")
	}
}

func parseAll(bounds parseBounds) []int { return parseRange(bounds.min, bounds.max) }

func parseRange(start, end int) []int {
	values := make([]int, 0, end-start+1)
	for value := start; value <= end; value++ {
		values = append(values, value)
	}
	return values
}

func parseEvery(values []int, step int) []int {
	selected := make([]int, 0, (len(values)+step-1)/step)
	for i := 0; i < len(values); i += step {
		selected = append(selected, values[i])
	}
	return selected
}
