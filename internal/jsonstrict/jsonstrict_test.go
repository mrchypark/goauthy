package jsonstrict

import "testing"

func TestRejectDuplicateKeys(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{
		`{}`,
		`{"a":1,"b":{"c":[1,{"d":2}]}}`,
		`[1,2,{"x":true}]`,
	} {
		if err := RejectDuplicateKeys([]byte(valid)); err != nil {
			t.Fatalf("unexpected error for %s: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		`{"a":1,"a":2}`,
		`{"outer":{"x":1,"x":2}}`,
		`[{"k":1,"k":2}]`,
		`{"a":1}{"b":2}`,
		`{"a":`,
		``,
	} {
		if err := RejectDuplicateKeys([]byte(invalid)); err == nil {
			t.Fatalf("expected error for %s", invalid)
		}
	}
}
