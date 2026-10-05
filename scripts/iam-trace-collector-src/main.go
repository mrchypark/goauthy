// Command iam-trace-collector is a tiny diagnostic OTLP/HTTP protobuf receiver.
//
// It accepts ExportTraceServiceRequest payloads on POST /v1/traces and emits a
// heavily reduced NDJSON projection of a fixed instrumentation scope. Nothing
// from the input beyond the identifiers, timing and (allowlisted) name is kept.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	maxRequestBytes = 4 << 20 // 4MiB
	contentType     = "application/x-protobuf"

	scopeAuthStage = "goauthy/auth-stage"
	scopeHTTPSrv   = "goauthy/http"
)

// authStages is the closed set of span names permitted for scopeAuthStage.
var authStages = map[string]bool{
	"credential_lookup":   true,
	"password_verify":     true,
	"subject_revalidate":  true,
	"interaction_consume": true,
	"session_rotate":      true,
	"oauth_issue":         true,
	"authorize_validate":  true,
	"authorize_session":   true,
	"policy_check":        true,
	"policy_allow":        true,
	"policy_account_lock": true,
	"policy_success":      true,
	"session_load":        true,
	"request_resolve":     true,
	"storage_execute":     true,
	"storage_submit":      true,
	"storage_status":      true,
	"storage_replay":      true,
}

// httpRoutes is the closed set of route names permitted for scopeHTTPSrv. It is
// empty by default: route identifiers cannot be confirmed safe without reading
// the repository, so http server spans are emitted without a name.
var httpRoutes = map[string]bool{}

type record struct {
	TraceID      string  `json:"trace_id"`
	SpanID       string  `json:"span_id"`
	ParentSpanID string  `json:"parent_span_id"`
	StartNS      uint64  `json:"start_ns"`
	EndNS        uint64  `json:"end_ns"`
	DurationMS   float64 `json:"duration_ms"`
	Name         string  `json:"name"`
}

type sink struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

func newSink(path string) (*sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	return &sink{f: f, enc: json.NewEncoder(f), path: path}, nil
}

func (s *sink) write(r record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(r)
}

func (s *sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}

func nameAllowed(scope, name string) (string, bool) {
	switch scope {
	case scopeAuthStage:
		if authStages[name] {
			return name, true
		}
		return "", false
	case scopeHTTPSrv:
		if len(httpRoutes) == 0 {
			return "", true // name intentionally dropped
		}
		if httpRoutes[name] {
			return name, true
		}
		return "", false
	}
	return "", false
}

// convert projects the request, returning only spans that pass every check.
func convert(req *coltracepb.ExportTraceServiceRequest) ([]record, error) {
	var out []record
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			scope := ss.GetScope().GetName()
			for _, sp := range ss.GetSpans() {
				tid, sid, pid := sp.GetTraceId(), sp.GetSpanId(), sp.GetParentSpanId()
				if len(tid) != 16 || len(sid) != 8 || (len(pid) != 0 && len(pid) != 8) {
					continue
				}
				start, end := sp.GetStartTimeUnixNano(), sp.GetEndTimeUnixNano()
				if start > end {
					continue
				}
				name, ok := nameAllowed(scope, sp.GetName())
				if !ok {
					continue
				}
				out = append(out, record{
					TraceID:      hexOrEmpty(tid),
					SpanID:       hexOrEmpty(sid),
					ParentSpanID: hexOrEmpty(pid),
					StartNS:      start,
					EndNS:        end,
					DurationMS:   float64(end-start) / 1e6,
					Name:         name,
				})
			}
		}
	}
	return out, nil
}

func newHandler(s *sink) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != contentType {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body) > maxRequestBytes {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var req coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		recs, _ := convert(&req)
		for _, rec := range recs {
			if err := s.write(rec); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		writeEmptyResponse(w)
	})
	return mux
}

func writeEmptyResponse(w http.ResponseWriter) {
	resp, err := proto.Marshal(&coltracepb.ExportTraceServiceResponse{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func run(args []string) error {
	fs := flag.NewFlagSet("iam-trace-collector", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:4318", "listen address")
	output := fs.String("output", "", "NDJSON output path (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("--output is required")
	}
	s, err := newSink(*output)
	if err != nil {
		return err
	}
	defer s.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(s),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	idle := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		srv.Close()
		close(idle)
	}()

	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-idle
		return nil
	}
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "iam-trace-collector:", err)
		os.Exit(1)
	}
}
