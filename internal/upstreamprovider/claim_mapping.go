package upstreamprovider

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"

	json "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/pb33f/jsonpath/pkg/jsonpath"
	"github.com/pb33f/jsonpath/pkg/jsonpath/config"
	"go.yaml.in/yaml/v4"
)

// EvaluateClaimMapping evaluates a single JSONPath claim mapping against raw
// JSON payload bytes, following Rauthy-compatible semantics:
//
//	path nil -> nil (no decision)
//	path present, value nil -> error (misconfigured)
//	malformed path -> nil decision (no remap)
//	valid path, no match -> false
//	valid path, any match -> true
//
// The value comparison follows Rauthy's serde_json::Value serialization:
// string nodes are compared as JSON-quoted strings; non-string scalar nodes
// (bool, int, float, null) are compared as literal-quoted JSON values.
// Arrays and objects are serialized to JSON then quoted for comparison.
//
// This is a pure helper -- no claims trust change, no MFA, no session
// integration. The rawJSON input is bounded by the caller (callback payload
// bound).
func EvaluateClaimMapping(rawJSON []byte, path, value *string) (*bool, error) {
	if path == nil {
		return nil, nil
	}
	if value == nil {
		return nil, fmt.Errorf("claim path configured without expected value")
	}

	// Strict validation via go-json-experiment/json: rejects duplicate keys,
	// invalid UTF-8, trailing data, and unpaired surrogates (RFC 7493).
	if err := json.Unmarshal(rawJSON, new(jsontext.Value)); err != nil {
		return nil, fmt.Errorf("invalid JSON payload: %w", err)
	}

	// Parse JSONPath expression -- strict RFC 9535.
	jp, err := jsonpath.NewPath(*path, config.WithStrictRFC9535())
	if err != nil {
		// Malformed path -> nil decision, no remap.
		return nil, nil
	}

	// Convert JSON to yaml.Node tree for the JSONPath library.
	// Uses yaml.Unmarshal directly on raw JSON to preserve number
	// precision (no float64 round-trip).
	node, err := jsonToYAMLNode(rawJSON)
	if err != nil {
		return nil, fmt.Errorf("parse JSON payload: %w", err)
	}

	// Reject numeric overflow: serde_json 1.0.151 rejects numbers like
	// 1e309 that overflow float64. yaml.v4 silently demotes these to
	// !!str (Style=0 plain scalar); detect before comparison.
	if err := checkYAMLOverflow(node); err != nil {
		return nil, err
	}

	// Query ALL results using the full JSONPath parser.
	results := jp.Query(node)

	// Build target: serde_json::Value::from(configuredString).to_string()
	target := jsonSerializeString(*value)

	for _, n := range results {
		if yamlNodeToSerializedString(n) == target {
			matched := true
			return &matched, nil
		}
	}

	matched := false
	return &matched, nil
}

// jsonToYAMLNode converts raw JSON bytes to a yaml.Node tree suitable for
// the pb33f/jsonpath library. Uses yaml.Unmarshal directly on the raw JSON
// bytes (YAML is a superset of JSON) to preserve number precision and type
// tags -- no float64 intermediate, no precision loss for large integers.
func jsonToYAMLNode(rawJSON []byte) (*yaml.Node, error) {
	node := new(yaml.Node)
	if err := yaml.Unmarshal(rawJSON, node); err != nil {
		return nil, err
	}
	// Unwrap document node.
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	return node, nil
}

// jsonSerializeString wraps s as a serde_json::Value::String and returns its
// JSON serialization with surrounding quotes, matching
// serde_json::Value::from(s).to_string().
func jsonSerializeString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// checkYAMLOverflow walks the yaml.Node tree and rejects numeric values that
// overflow float64 (e.g. 1e309). yaml.v4 silently demotes such values to
// !!str with Style=0 (plain scalar); serde_json rejects them with an error.
func checkYAMLOverflow(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.ShortTag() == "!!str" && node.Style == 0 {
			// Plain scalar that YAML could not parse as a native type.
			// If it looks like a number and overflows float64, reject it.
			if len(node.Value) > 0 && isDigitOrSign(node.Value[0]) {
				if _, err := strconv.ParseFloat(node.Value, 64); err != nil {
					// Successfully parsed -> overflow (serde_json rejects this)
					return fmt.Errorf("invalid JSON payload: number %s out of range", node.Value)
				}
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if err := checkYAMLOverflow(node.Content[i+1]); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := checkYAMLOverflow(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// isDigitOrSign returns true for ASCII digits, '+', '-', and '.' -- the
// characters that can start a JSON number.
func isDigitOrSign(b byte) bool {
	return unicode.IsDigit(rune(b)) || b == '+' || b == '-' || b == '.'
}

// yamlNodeToSerializedString converts a yaml.Node to the Rauthy-compatible
// serialized string for comparison. The encoding mirrors the Rust code:
//
//	if !value.is_string() {
//	    format!("\"{value}\"")
//	} else {
//	    value.to_string()
//	}
//
// where the value is a serde_json::Value node.
func yamlNodeToSerializedString(n *yaml.Node) string {
	if n == nil {
		return ""
	}

	switch n.Kind {
	case yaml.ScalarNode:
		tag := n.ShortTag()
		switch tag {
		case "!!str":
			// String -> JSON-quoted (serde_json Value::String.to_string())
			b, _ := json.Marshal(n.Value)
			return string(b)
		case "!!bool", "!!int":
			// Bool/int -> literal-quoted, preserving the original text.
			// serde_json preserves int lexemes and bool text exactly.
			// Defensive: normalize integer -0 to -0.0 (serde_json
			// always parses -0 as Value::Number(-0.0)).
			if n.Value == "-0" {
				return "\"-0.0\""
			}
			return "\"" + n.Value + "\""
		case "!!float":
			// Normalize float to serde_json canonical form.
			// Handles exponent normalization (1e2 -> 100.0), sign
			// normalization (-0 -> -0.0), and scientific notation
			// (1e+20 for large exponents, 1e-6 for small).
			if canonical := canonicalFloat(n.Value); canonical != "" {
				return "\"" + canonical + "\""
			}
			return "\"" + n.Value + "\""
		case "!!null":
			return "\"null\""
		default:
			// Unknown tag -> treat as string
			b, _ := json.Marshal(n.Value)
			return string(b)
		}
	default:
		// Non-scalar (array, object): convert to interface{}, marshal
		// to JSON, then wrap in quotes.
		var v any
		if err := n.Load(&v); err != nil {
			return ""
		}
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return "\"" + string(b) + "\""
	}
}

// canonicalFloat parses a YAML float lexeme to produce serde_json's (zmij
// 1.0.151) canonical string representation. Format thresholds determined
// by pinned serde_json 1.0.151 probe against serde_json::Value::to_string():
//
//	exponent >= 16  -> scientific  (1e16 -> 1e+16)
//	exponent <= -6  -> scientific  (1e-6 -> 1e-6)
//	-0              -> -0.0        (sign preserved)
//	Inf/NaN         -> rejected (empty string)
func canonicalFloat(s string) string {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return ""
	}
	// Reject non-finite values; serde_json would also reject these.
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return ""
	}

	// Use absolute value for exponent computation; sign is restored later.
	abs := f
	if abs < 0 {
		abs = -abs
	}

	// Derive format decision from the exponent of the stdlib scientific
	// representation.  This avoids log10 (NaN for negative floats) and
	// matches serde_json 1.0.151 exactly at every tested boundary.
	sci := strconv.FormatFloat(abs, 'e', -1, 64)
	exp := parseExponent(sci)
	useScientific := exp >= 16 || exp <= -6

	var out string
	if useScientific {
		out = stripLeadingZeroExponent(sci)
	} else {
		out = strconv.FormatFloat(abs, 'f', -1, 64)
		if !strings.Contains(out, ".") {
			out += ".0"
		}
	}

	// Restore sign for negative non-zero values.
	if f < 0 && f != 0 {
		out = "-" + out
	}

	// serde_json preserves -0 sign; strconv strips it.
	if (out == "0" || out == "0.0") && s[0] == '-' {
		out = "-" + out
	}
	return out
}

// parseExponent extracts the integer exponent from a scientific notation
// string produced by strconv.FormatFloat('e').  E.g. "1e+15" -> 15,
// "5e-1" -> -1.
func parseExponent(sci string) int {
	i := strings.IndexAny(sci, "eE")
	if i < 0 || i+2 > len(sci) {
		return 0
	}
	exp, _ := strconv.Atoi(sci[i+1:])
	return exp
}

// stripLeadingZeroExponent removes leading zeros from the exponent of
// scientific notation to match serde_json's output.
// E.g. "1e-06" -> "1e-6", "1e+020" -> "1e+20".
func stripLeadingZeroExponent(s string) string {
	i := strings.IndexAny(s, "eE")
	if i < 0 {
		return s
	}
	sign := s[i+1 : i+2]
	digits := s[i+2:]
	for len(digits) > 1 && digits[0] == '0' {
		digits = digits[1:]
	}
	return s[:i+1] + sign + digits
}
