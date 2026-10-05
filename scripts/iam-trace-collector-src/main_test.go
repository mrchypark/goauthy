package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func makeSpan(scope, name string, traceID, spanID, parentID []byte, start, end uint64) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Scope: &commonpb.InstrumentationScope{Name: scope},
				Spans: []*tracepb.Span{{
					TraceId:           traceID,
					SpanId:            spanID,
					ParentSpanId:      parentID,
					Name:              name,
					StartTimeUnixNano: start,
					EndTimeUnixNano:   end,
					Attributes: []*commonpb.KeyValue{{
						Key:   "secret",
						Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "leak-me"}},
					}},
					Events: []*tracepb.Span_Event{{Name: "boom"}},
					Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: "err"},
					Links:  []*tracepb.Span_Link{{TraceId: traceID, SpanId: spanID}},
				}},
			}},
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "goauthy"}},
			}}},
		}},
	}
}

func post(t *testing.T, s *sink, body []byte, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	newHandler(s).ServeHTTP(rec, req)
	return rec
}

func readRecords(t *testing.T, path string) []record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []record
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad ndjson line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// The three storage boundary stages must be allowlisted and must project onto
// exactly the existing record keys, with no new field of any kind.
func TestConvertKeepsNewStorageStageNamesWithOnlyTheExistingKeys(t *testing.T) {
	traceID := bytes.Repeat([]byte{0x0A}, 16)
	spanID := bytes.Repeat([]byte{0x0B}, 8)
	parentID := bytes.Repeat([]byte{0x0C}, 8)
	for _, name := range []string{"storage_submit", "storage_status", "storage_replay"} {
		recs, err := convert(makeSpan(scopeAuthStage, name, traceID, spanID, parentID, 100, 200))
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 1 {
			t.Fatalf("%s: want 1 record, got %d", name, len(recs))
		}
		if recs[0].Name != name {
			t.Fatalf("%s: name = %q", name, recs[0].Name)
		}
		encoded, err := json.Marshal(recs[0])
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 7 {
			t.Fatalf("%s: got %d fields, want 7: %v", name, len(fields), fields)
		}
		for _, key := range []string{"trace_id", "span_id", "parent_span_id", "start_ns", "end_ns", "duration_ms", "name"} {
			if _, ok := fields[key]; !ok {
				t.Fatalf("%s: missing key %q", name, key)
			}
		}
	}
}

// A near-miss name next to the new stages must still be discarded.
func TestConvertDiscardsNearMissStorageStageNames(t *testing.T) {
	traceID := bytes.Repeat([]byte{0x01}, 16)
	spanID := bytes.Repeat([]byte{0x02}, 8)
	for _, name := range []string{"storage", "storage_submit_v2", "storage_status_extra", "storage_replay_attempt", "Storage_Submit"} {
		recs, err := convert(makeSpan(scopeAuthStage, name, traceID, spanID, nil, 1, 2))
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 0 {
			t.Fatalf("%q: want 0 records, got %d", name, len(recs))
		}
	}
}

func TestConvertKeepsValidStageWithParentAndTiming(t *testing.T) {
	traceID := bytes.Repeat([]byte{0xAB}, 16)
	spanID := bytes.Repeat([]byte{0x01}, 8)
	parentID := bytes.Repeat([]byte{0x02}, 8)
	req := makeSpan(scopeAuthStage, "password_verify", traceID, spanID, parentID, 1000, 3000)
	recs, err := convert(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.TraceID != "abababababababababababababababab" || r.SpanID != "0101010101010101" || r.ParentSpanID != "0202020202020202" {
		t.Fatalf("bad ids: %+v", r)
	}
	if r.StartNS != 1000 || r.EndNS != 3000 || r.DurationMS != 0.002 {
		t.Fatalf("bad timing: %+v", r)
	}
	if r.Name != "password_verify" {
		t.Fatalf("bad name: %q", r.Name)
	}
}

func TestConvertDiscardsUnknownScopeStageAndBadIDs(t *testing.T) {
	good := bytes.Repeat([]byte{0x01}, 16)
	span8 := bytes.Repeat([]byte{0x02}, 8)
	cases := []*coltracepb.ExportTraceServiceRequest{
		makeSpan("other/scope", "password_verify", good, span8, nil, 1, 2),
		makeSpan(scopeAuthStage, "not_a_stage", good, span8, nil, 1, 2),
		makeSpan(scopeAuthStage, "password_verify", bytes.Repeat([]byte{0x01}, 8), span8, nil, 1, 2),
		makeSpan(scopeAuthStage, "password_verify", good, bytes.Repeat([]byte{0x01}, 4), nil, 1, 2),
		makeSpan(scopeAuthStage, "password_verify", good, span8, []byte{0x01}, 1, 2),
		makeSpan(scopeAuthStage, "password_verify", good, span8, nil, 5, 4),
	}
	for i, req := range cases {
		recs, err := convert(req)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 0 {
			t.Fatalf("case %d: want 0 records, got %d", i, len(recs))
		}
	}
}

func TestHTTPServerScopeDropsName(t *testing.T) {
	req := makeSpan(scopeHTTPSrv, "/some/route", bytes.Repeat([]byte{0x03}, 16), bytes.Repeat([]byte{0x04}, 8), nil, 10, 20)
	recs, _ := convert(req)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Name != "" {
		t.Fatalf("name should be omitted, got %q", recs[0].Name)
	}
}

func TestHandlerDiscardsArbitraryPayloadFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	s, err := newSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	req := makeSpan(scopeAuthStage, "oauth_issue", bytes.Repeat([]byte{0x05}, 16), bytes.Repeat([]byte{0x06}, 8), nil, 7, 9)
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := post(t, s, body, contentType)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out coltracepb.ExportTraceServiceResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.GetPartialSuccess() != nil {
		t.Fatal("expected empty ExportTraceServiceResponse")
	}
	if got := rec.Header().Get("Content-Type"); got != contentType {
		t.Fatalf("response content-type %q", got)
	}

	recs := readRecords(t, path)
	if len(recs) != 1 || recs[0].Name != "oauth_issue" {
		t.Fatalf("unexpected records: %+v", recs)
	}
	raw, _ := os.ReadFile(path)
	for _, forbidden := range []string{"leak-me", "boom", "attributes", "events", "links", "status"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("output leaked %q: %s", forbidden, raw)
		}
	}
}

func TestHandlerRejectsBadContentTypeAndOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	s, err := newSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if rec := post(t, s, []byte{}, "application/json"); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415, got %d", rec.Code)
	}
	if rec := post(t, s, []byte{0xff, 0x00, 0x01}, contentType); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for malformed protobuf, got %d", rec.Code)
	}
	big := bytes.Repeat([]byte{0x00}, maxRequestBytes+1)
	if rec := post(t, s, big, contentType); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", rec.Code)
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatalf("expected empty output, got %q", b)
	}
}

func TestNewSinkModeIs0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.ndjson")
	s, err := newSink(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", fi.Mode().Perm())
	}
}
