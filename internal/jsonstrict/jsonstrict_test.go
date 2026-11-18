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

func TestDecodeStrict(t *testing.T) {
	t.Parallel()
	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var ok payload
	if err := DecodeStrict([]byte(`{"name":"alice","count":2}`), &ok); err != nil {
		t.Fatalf("valid payload failed: %v", err)
	}
	if ok.Name != "alice" || ok.Count != 2 {
		t.Fatalf("decoded=%+v", ok)
	}
	for _, invalid := range []string{
		`{"name":"alice","unknown":1}`,
		`{"name":"alice","name":"bob"}`,
		`{"name":"alice"}{"count":1}`,
		`{"name":`,
	} {
		var dst payload
		if err := DecodeStrict([]byte(invalid), &dst); err == nil {
			t.Fatalf("expected error for %s", invalid)
		}
	}
}
