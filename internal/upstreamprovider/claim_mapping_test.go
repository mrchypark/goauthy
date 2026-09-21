package upstreamprovider

import (
	"testing"
)

func ptr(s string) *string { return &s }

func TestEvaluateClaimMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawJSON string
		path    *string
		value   *string
		want    *bool
		wantErr bool
	}{
		// --- nil-path -> nil decision ---
		{
			name:    "nil path returns nil",
			rawJSON: `{"foo":"bar"}`,
			path:    nil,
			value:   ptr("bar"),
			want:    nil,
		},

		// --- path present, value nil -> error ---
		{
			name:    "path present but value nil returns error",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$.foo"),
			value:   nil,
			wantErr: true,
		},

		// --- malformed path -> nil decision (no remap) ---
		{
			name:    "malformed path returns nil",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$[invalid"),
			value:   ptr("bar"),
			want:    nil,
		},

		// --- simple string match ---
		{
			name:    "simple string match",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$.foo"),
			value:   ptr("bar"),
			want:    boolPtr(true),
		},

		// --- simple string no match ---
		{
			name:    "simple string no match",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$.foo"),
			value:   ptr("baz"),
			want:    boolPtr(false),
		},

		// --- absent path (key missing) -> false ---
		{
			name:    "absent key returns false",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$.missing"),
			value:   ptr("bar"),
			want:    boolPtr(false),
		},

		// --- nested path match ---
		{
			name:    "nested path match",
			rawJSON: `{"foo":{"bar":"baz"}}`,
			path:    ptr("$.foo.bar"),
			value:   ptr("baz"),
			want:    boolPtr(true),
		},

		// --- $.foo.bar[*] array wildcard ---
		{
			name:    "array wildcard match",
			rawJSON: `{"foo":{"bar":["alpha","beta","gamma"]}}`,
			path:    ptr("$.foo.bar[*]"),
			value:   ptr("beta"),
			want:    boolPtr(true),
		},

		// --- $.foo.bar[*] no match ---
		{
			name:    "array wildcard no match",
			rawJSON: `{"foo":{"bar":["alpha","beta","gamma"]}}`,
			path:    ptr("$.foo.bar[*]"),
			value:   ptr("delta"),
			want:    boolPtr(false),
		},

		// --- $.foo.bar.* dot-wildcard ---
		{
			name:    "dot wildcard match",
			rawJSON: `{"foo":{"bar":{"x":"alpha","y":"beta"}}}`,
			path:    ptr("$.foo.bar.*"),
			value:   ptr("beta"),
			want:    boolPtr(true),
		},

		// --- $.*.bor recursive wildcard ---
		{
			name:    "recursive wildcard match",
			rawJSON: `{"a":{"bor":"hit"},"b":{"bor":"miss"}}`,
			path:    ptr("$.*.bor"),
			value:   ptr("hit"),
			want:    boolPtr(true),
		},

		// --- $.*.bor no match ---
		{
			name:    "recursive wildcard no match",
			rawJSON: `{"a":{"bor":"x"},"b":{"bor":"y"}}`,
			path:    ptr("$.*.bor"),
			value:   ptr("z"),
			want:    boolPtr(false),
		},

		// --- recursive descent $..foo ---
		{
			name:    "recursive descent match",
			rawJSON: `{"a":{"b":{"foo":"deep"}},"foo":"shallow"}`,
			path:    ptr("$..foo"),
			value:   ptr("deep"),
			want:    boolPtr(true),
		},

		// --- boolean match ---
		{
			name:    "boolean true match",
			rawJSON: `{"admin":true}`,
			path:    ptr("$.admin"),
			value:   ptr("true"),
			want:    boolPtr(true),
		},

		// --- boolean false no match against "true" ---
		{
			name:    "boolean false no match against true",
			rawJSON: `{"admin":false}`,
			path:    ptr("$.admin"),
			value:   ptr("true"),
			want:    boolPtr(false),
		},

		// --- number match ---
		{
			name:    "number match",
			rawJSON: `{"count":42}`,
			path:    ptr("$.count"),
			value:   ptr("42"),
			want:    boolPtr(true),
		},

		// --- number no match ---
		{
			name:    "number no match",
			rawJSON: `{"count":42}`,
			path:    ptr("$.count"),
			value:   ptr("43"),
			want:    boolPtr(false),
		},

		// --- quoted string in JSON ---
		{
			name:    "quoted string match",
			rawJSON: `{"name":"John \"Doe\""}`,
			path:    ptr("$.name"),
			value:   ptr(`John "Doe"`),
			want:    boolPtr(true),
		},

		// --- scalar wildcard nomatch (wildcard on scalar) ---
		{
			name:    "scalar wildcard no match",
			rawJSON: `{"foo":"bar"}`,
			path:    ptr("$.foo[*]"),
			value:   ptr("bar"),
			want:    boolPtr(false),
		},

		// --- array of objects, non-match quirk ---
		{
			name:    "array of objects no match",
			rawJSON: `{"users":[{"name":"alice"},{"name":"bob"}]}`,
			path:    ptr("$.users[*].name"),
			value:   ptr("charlie"),
			want:    boolPtr(false),
		},

		// --- array of objects, match ---
		{
			name:    "array of objects match",
			rawJSON: `{"users":[{"name":"alice"},{"name":"bob"}]}`,
			path:    ptr("$.users[*].name"),
			value:   ptr("bob"),
			want:    boolPtr(true),
		},

		// --- empty array -> false ---
		{
			name:    "empty array returns false",
			rawJSON: `{"items":[]}`,
			path:    ptr("$.items[*]"),
			value:   ptr("anything"),
			want:    boolPtr(false),
		},

		// --- object value comparison (non-string) ---
		{
			name:    "object value no match against string",
			rawJSON: `{"meta":{"key":"val"}}`,
			path:    ptr("$.meta"),
			value:   ptr(`{"key":"val"}`),
			want:    boolPtr(false),
		},

		// --- null value ---
		{
			name:    "null value no match",
			rawJSON: `{"val":null}`,
			path:    ptr("$.val"),
			value:   ptr("null"),
			want:    boolPtr(true),
		},

		// --- float match ---
		{
			name:    "float match",
			rawJSON: `{"score":3.14}`,
			path:    ptr("$.score"),
			value:   ptr("3.14"),
			want:    boolPtr(true),
		},

		// --- string "true" vs bool true ---
		{
			name:    "string true vs bool true",
			rawJSON: `{"flag":true}`,
			path:    ptr("$.flag"),
			value:   ptr("true"),
			want:    boolPtr(true),
		},

		// --- string "true" in JSON vs bool target ---
		{
			name:    "string true in JSON vs bool target",
			rawJSON: `{"flag":"true"}`,
			path:    ptr("$.flag"),
			value:   ptr("true"),
			want:    boolPtr(true),
		},

		// --- float 1.0 semantics (Rust serializes 1.0 as "1.0") ---
		{
			name:    "float 1.0 matches string 1.0",
			rawJSON: `{"v":1.0}`,
			path:    ptr("$.v"),
			value:   ptr("1.0"),
			want:    boolPtr(true),
		},

		// --- float 1.0 does not match string 1 ---
		{
			name:    "float 1.0 no match string 1",
			rawJSON: `{"v":1.0}`,
			path:    ptr("$.v"),
			value:   ptr("1"),
			want:    boolPtr(false),
		},

		// --- int 1 matches string 1 ---
		{
			name:    "int 1 matches string 1",
			rawJSON: `{"v":1}`,
			path:    ptr("$.v"),
			value:   ptr("1"),
			want:    boolPtr(true),
		},

		// --- exponent 1e2 normalizes to 100.0 (serde_json 1.0.151 probe) ---
		{
			name:    "exponent 1e2 matches 100.0",
			rawJSON: `{"v":1e2}`,
			path:    ptr("$.v"),
			value:   ptr("100.0"),
			want:    boolPtr(true),
		},

		// --- exponent 1e2 does not match 1e2 (normalized to 100.0) ---
		{
			name:    "exponent 1e2 no match 1e2",
			rawJSON: `{"v":1e2}`,
			path:    ptr("$.v"),
			value:   ptr("1e2"),
			want:    boolPtr(false),
		},

		// --- exponent 1.0e2 normalizes to 100.0 ---
		{
			name:    "exponent 1.0e2 matches 100.0",
			rawJSON: `{"v":1.0e2}`,
			path:    ptr("$.v"),
			value:   ptr("100.0"),
			want:    boolPtr(true),
		},

		// --- exponent 1e0 normalizes to 1.0 ---
		{
			name:    "exponent 1e0 matches 1.0",
			rawJSON: `{"v":1e0}`,
			path:    ptr("$.v"),
			value:   ptr("1.0"),
			want:    boolPtr(true),
		},

		// --- exponent 1.0e0 normalizes to 1.0 ---
		{
			name:    "exponent 1.0e0 matches 1.0",
			rawJSON: `{"v":1.0e0}`,
			path:    ptr("$.v"),
			value:   ptr("1.0"),
			want:    boolPtr(true),
		},

		// --- small exponent 1e-2 normalizes to 0.01 ---
		{
			name:    "small exponent 1e-2 matches 0.01",
			rawJSON: `{"v":1e-2}`,
			path:    ptr("$.v"),
			value:   ptr("0.01"),
			want:    boolPtr(true),
		},

		// --- -0 matches -0.0 (sign preserved by serde_json) ---
		{
			name:    "negative zero matches -0.0",
			rawJSON: `{"v":-0}`,
			path:    ptr("$.v"),
			value:   ptr("-0.0"),
			want:    boolPtr(true),
		},

		// --- -0.0 matches -0.0 ---
		{
			name:    "negative zero explicit matches -0.0",
			rawJSON: `{"v":-0.0}`,
			path:    ptr("$.v"),
			value:   ptr("-0.0"),
			want:    boolPtr(true),
		},

		// --- -0 does not match 0 (sign matters) ---
		{
			name:    "negative zero no match 0",
			rawJSON: `{"v":-0}`,
			path:    ptr("$.v"),
			value:   ptr("0"),
			want:    boolPtr(false),
		},

		// --- large exponent 1e20 normalizes to 1e+20 ---
		{
			name:    "large exponent 1e20 matches 1e+20",
			rawJSON: `{"v":1e20}`,
			path:    ptr("$.v"),
			value:   ptr("1e+20"),
			want:    boolPtr(true),
		},

		// --- large exponent 1e20 does not match 1e20 ---
		{
			name:    "large exponent 1e20 no match 1e20",
			rawJSON: `{"v":1e20}`,
			path:    ptr("$.v"),
			value:   ptr("1e20"),
			want:    boolPtr(false),
		},

		// --- boundary exponent 1e15 stays fixed (1000000000000000.0) ---
		{
			name:    "exponent 1e15 matches 1000000000000000.0",
			rawJSON: `{"v":1e15}`,
			path:    ptr("$.v"),
			value:   ptr("1000000000000000.0"),
			want:    boolPtr(true),
		},

		// --- boundary exponent 1e16 switches to scientific (1e+16) ---
		{
			name:    "exponent 1e16 matches 1e+16",
			rawJSON: `{"v":1e16}`,
			path:    ptr("$.v"),
			value:   ptr("1e+16"),
			want:    boolPtr(true),
		},

		// --- small boundary 1e-5 stays fixed (0.00001) ---
		{
			name:    "small exponent 1e-5 matches 0.00001",
			rawJSON: `{"v":1e-5}`,
			path:    ptr("$.v"),
			value:   ptr("0.00001"),
			want:    boolPtr(true),
		},

		// --- small boundary 1e-6 switches to scientific ---
		{
			name:    "small exponent 1e-6 matches 1e-6",
			rawJSON: `{"v":1e-6}`,
			path:    ptr("$.v"),
			value:   ptr("1e-6"),
			want:    boolPtr(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EvaluateClaimMapping() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("EvaluateClaimMapping() = %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("EvaluateClaimMapping() = nil, want %v", *tt.want)
			}
			if *got != *tt.want {
				t.Fatalf("EvaluateClaimMapping() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

// TestLargeIntegerPrecision verifies that large integers beyond float64
// precision (2^53+1) survive the JSON->yaml.Node path without rounding.
func TestLargeIntegerPrecision(t *testing.T) {
	t.Parallel()
	rawJSON := `{"big":9007199254740993}`
	want := boolPtr(true)
	got, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.big"), ptr("9007199254740993"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || *got != *want {
		t.Fatalf("large integer precision lost: got %v, want %v", got, want)
	}
}

// TestLargeIntegerNoFalseGrant verifies that a large integer that does NOT
// match the target is correctly reported as false.
func TestLargeIntegerNoFalseGrant(t *testing.T) {
	t.Parallel()
	rawJSON := `{"big":9007199254740993}`
	want := boolPtr(false)
	got, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.big"), ptr("9007199254740994"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || *got != *want {
		t.Fatalf("large integer wrong match: got %v, want %v", got, want)
	}
}

// TestDuplicateKeyRejects verifies that JSON with duplicate object keys
// is rejected by strict validation.
func TestDuplicateKeyRejects(t *testing.T) {
	t.Parallel()
	rawJSON := `{"a":1,"a":2}`
	_, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.a"), ptr("1"))
	if err == nil {
		t.Fatal("expected error for duplicate keys, got nil")
	}
}

// TestDuplicateKeyNested rejects duplicates in nested objects.
func TestDuplicateKeyNested(t *testing.T) {
	t.Parallel()
	rawJSON := `{"outer":{"x":1,"x":2}}`
	_, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.outer.x"), ptr("1"))
	if err == nil {
		t.Fatal("expected error for nested duplicate keys, got nil")
	}
}

// TestInvalidUTF8Rejects verifies that invalid UTF-8 is rejected.
func TestInvalidUTF8Rejects(t *testing.T) {
	t.Parallel()
	rawJSON := []byte{0x7b, 0x22, 0x6b, 0x65, 0x79, 0x22, 0x3a, 0xff, 0x22, 0x76, 0x61, 0x6c, 0x22, 0x7d}
	_, err := EvaluateClaimMapping(rawJSON, ptr("$.key"), ptr("val"))
	if err == nil {
		t.Fatal("expected error for invalid UTF-8, got nil")
	}
}

// TestMalformedJSONRejects verifies that syntactically invalid JSON
// is rejected by strict validation.
func TestMalformedJSONRejects(t *testing.T) {
	t.Parallel()
	rawJSON := `{not valid json}`
	_, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.foo"), ptr("bar"))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestTrailingCommaRejects verifies that trailing commas (invalid JSON)
// are rejected.
func TestTrailingCommaRejects(t *testing.T) {
	t.Parallel()
	rawJSON := `{"a":1,}`
	_, err := EvaluateClaimMapping([]byte(rawJSON), ptr("$.a"), ptr("1"))
	if err == nil {
		t.Fatal("expected error for trailing comma, got nil")
	}
}

// --- New tests for numeric mapping parity ---

// TestEvaluateNegativeThresholds verifies positive/negative float thresholds
// at the scientific/fixed boundary, matching serde_json 1.0.151 exactly.
func TestEvaluateNegativeThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawJSON string
		path    *string
		value   *string
		want    *bool
	}{
		// Negative small floats: fixed below -6 threshold
		{
			rawJSON: `{"v":-1e-5}`,
			path:    ptr("$.v"),
			value:   ptr("-0.00001"),
			want:    boolPtr(true),
		},
		{
			rawJSON: `{"v":-1e-5}`,
			path:    ptr("$.v"),
			value:   ptr("-1e-5"),
			want:    boolPtr(false),
		},
		// Negative small floats: scientific at -6 threshold
		{
			rawJSON: `{"v":-1e-6}`,
			path:    ptr("$.v"),
			value:   ptr("-1e-6"),
			want:    boolPtr(true),
		},
		{
			rawJSON: `{"v":-1e-6}`,
			path:    ptr("$.v"),
			value:   ptr("-0.000001"),
			want:    boolPtr(false),
		},
		// Positive boundary: 1e15 stays fixed, 1e16 goes scientific
		{
			rawJSON: `{"v":1e15}`,
			path:    ptr("$.v"),
			value:   ptr("1000000000000000.0"),
			want:    boolPtr(true),
		},
		{
			rawJSON: `{"v":1e16}`,
			path:    ptr("$.v"),
			value:   ptr("1e+16"),
			want:    boolPtr(true),
		},
		// Negative boundary: -1e15 stays fixed, -1e16 goes scientific
		{
			rawJSON: `{"v":-1e15}`,
			path:    ptr("$.v"),
			value:   ptr("-1000000000000000.0"),
			want:    boolPtr(true),
		},
		{
			rawJSON: `{"v":-1e16}`,
			path:    ptr("$.v"),
			value:   ptr("-1e+16"),
			want:    boolPtr(true),
		},
		// Negative non-integer floats: sign preserved
		{
			rawJSON: `{"v":-0.5}`,
			path:    ptr("$.v"),
			value:   ptr("-0.5"),
			want:    boolPtr(true),
		},
		{
			rawJSON: `{"v":-1.5}`,
			path:    ptr("$.v"),
			value:   ptr("-1.5"),
			want:    boolPtr(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil, want non-nil")
			}
			if *got != *tt.want {
				t.Fatalf("got %v, want %v", *got, *tt.want)
			}
		})
	}
}

// TestEvaluateNegativeZeroNormalization verifies that -0 (JSON number)
// normalizes to -0.0 in serde_json comparison, including sign preservation.
func TestEvaluateNegativeZeroNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawJSON string
		path    *string
		value   *string
		want    *bool
	}{
		{"-0 matches -0.0", `{"v":-0}`, ptr("$.v"), ptr("-0.0"), boolPtr(true)},
		{"-0 does not match 0", `{"v":-0}`, ptr("$.v"), ptr("0"), boolPtr(false)},
		{"-0.0 matches -0.0", `{"v":-0.0}`, ptr("$.v"), ptr("-0.0"), boolPtr(true)},
		{"0 matches 0 not 0.0", `{"v":0}`, ptr("$.v"), ptr("0"), boolPtr(true)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil, want non-nil")
			}
			if *got != *tt.want {
				t.Fatalf("got %v, want %v", *got, *tt.want)
			}
		})
	}
}

// TestEvaluateLargeUintPrecision verifies that large unsigned integers
// (uint64 max and beyond) survive the JSON->yaml.Node path correctly.
func TestEvaluateLargeUintPrecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rawJSON string
		path    *string
		value   *string
		want    *bool
	}{
		// uint64 max (18446744073709551615) is !!int in yaml.v4
		{`{"v":18446744073709551615}`, ptr("$.v"), ptr("18446744073709551615"), boolPtr(true)},
		// uint64 max does not match wrong value
		{`{"v":18446744073709551615}`, ptr("$.v"), ptr("18446744073709551614"), boolPtr(false)},
		// Beyond uint64: yaml.v4 tags as !!float; serde_json also float64
		{`{"v":18446744073709551616}`, ptr("$.v"), ptr("1.8446744073709552e+19"), boolPtr(true)},
	}

	for _, tt := range tests {
		got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("got nil, want non-nil")
		}
		if *got != *tt.want {
			t.Fatalf("JSON=%s value=%s: got %v, want %v", tt.rawJSON, *tt.value, *got, *tt.want)
		}
	}
}

// TestEvaluateNumericOverflow verifies that numbers exceeding float64
// range (e.g. 1e309) are rejected, matching serde_json behavior.
func TestEvaluateNumericOverflow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rawJSON string
		path    *string
		value   *string
		note    string
	}{
		{`{"v":1e309}`, ptr("$.v"), ptr("1e309"), "1e309 overflows float64"},
		{`{"v":-1e309}`, ptr("$.v"), ptr("-1e309"), "-1e309 overflows float64"},
		{`{"v":1e999}`, ptr("$.v"), ptr("1e999"), "1e999 overflows float64"},
	}

	for _, tt := range tests {
		got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
		if err == nil {
			t.Fatalf("%s: expected error, got result=%v", tt.note, got)
		}
	}
}

// TestEvaluatePositiveNegativeThresholds provides end-to-end observable
// tests for the scientific/fixed format boundary at both positive and
// negative thresholds.
func TestEvaluatePositiveNegativeThresholds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rawJSON string
		path    *string
		value   *string
		want    bool
		note    string
	}{
		// 1e-5 -> fixed "0.00001"
		{`{"v":1e-5}`, ptr("$.v"), ptr("0.00001"), true, "1e-5 fixed"},
		// 1e-6 -> scientific "1e-6"
		{`{"v":1e-6}`, ptr("$.v"), ptr("1e-6"), true, "1e-6 scientific"},
		// -1e-5 -> fixed "-0.00001"
		{`{"v":-1e-5}`, ptr("$.v"), ptr("-0.00001"), true, "-1e-5 fixed"},
		// -1e-6 -> scientific "-1e-6"
		{`{"v":-1e-6}`, ptr("$.v"), ptr("-1e-6"), true, "-1e-6 scientific"},
		// 1e15 -> fixed "1000000000000000.0"
		{`{"v":1e15}`, ptr("$.v"), ptr("1000000000000000.0"), true, "1e15 fixed"},
		// 1e16 -> scientific "1e+16"
		{`{"v":1e16}`, ptr("$.v"), ptr("1e+16"), true, "1e16 scientific"},
		// -1e15 -> fixed "-1000000000000000.0"
		{`{"v":-1e15}`, ptr("$.v"), ptr("-1000000000000000.0"), true, "-1e15 fixed"},
		// -1e16 -> scientific "-1e+16"
		{`{"v":-1e16}`, ptr("$.v"), ptr("-1e+16"), true, "-1e16 scientific"},
	}

	for _, tt := range tests {
		t.Run(tt.note, func(t *testing.T) {
			got, err := EvaluateClaimMapping([]byte(tt.rawJSON), tt.path, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil, want non-nil")
			}
			if *got != tt.want {
				t.Fatalf("got %v, want %v", *got, tt.want)
			}
		})
	}
}
