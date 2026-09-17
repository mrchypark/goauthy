// Command goauthy-backchannel-sink is a deliberately small, test-only RP
// back-channel logout endpoint. It keeps observations in memory and never logs
// request data, which can include signed logout tokens.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxRequestBody = 8 << 10
	maxControlBody = 1 << 10
	maxEvents      = 128
)

type event struct {
	Host        string `json:"host"`
	Attempt     int    `json:"attempt"`
	Token       string `json:"token"`
	ContentType string `json:"content_type"`
	RemoteIP    string `json:"remote_ip"`
	Status      int    `json:"status"`
}

type control struct {
	FailFirst     int
	DelayFirstMS  int
	SuccessStatus int
}

type controlInput struct {
	FailFirst     *int `json:"fail_first"`
	DelayFirstMS  *int `json:"delay_first_ms"`
	SuccessStatus *int `json:"success_status"`
}

type sink struct {
	mu           sync.Mutex
	config       control
	valid        int
	attempts     int
	observations []*event
}

func newSink(failFirst int) *sink {
	return &sink{config: control{FailFirst: failFirst, SuccessStatus: http.StatusNoContent}}
}

func (s *sink) record(token, contentType, remoteIP string, status int) *event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	e := &event{Attempt: s.attempts, Token: token, ContentType: contentType, RemoteIP: remoteIP, Status: status}
	s.observations = append(s.observations, e)
	if len(s.observations) > maxEvents {
		s.observations = s.observations[len(s.observations)-maxEvents:]
	}
	return e
}

func (s *sink) recordValid(token, contentType, remoteIP, host string) (*event, control, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.valid++
	c := s.config
	status := c.SuccessStatus
	if s.valid <= c.FailFirst {
		status = http.StatusServiceUnavailable
	}
	s.attempts++
	e := &event{Host: host, Attempt: s.attempts, Token: token, ContentType: contentType, RemoteIP: remoteIP, Status: status}
	s.observations = append(s.observations, e)
	if len(s.observations) > maxEvents {
		s.observations = s.observations[len(s.observations)-maxEvents:]
	}
	return e, c, status
}

func (s *sink) cancel(e *event) {
	s.mu.Lock()
	e.Status = 0
	s.mu.Unlock()
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return ""
}

func (s *sink) backchannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	contentType := r.Header.Get("Content-Type")
	remoteIP := remoteIP(r)
	if r.Method != http.MethodPost {
		s.record("", contentType, remoteIP, http.StatusMethodNotAllowed)
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		s.record("", contentType, remoteIP, http.StatusBadRequest)
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		s.record("", contentType, remoteIP, http.StatusUnsupportedMediaType)
		http.Error(w, "content type must be application/x-www-form-urlencoded", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		s.record("", contentType, remoteIP, status)
		http.Error(w, "invalid request body", status)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) != 1 || len(form["logout_token"]) != 1 || form.Get("logout_token") == "" {
		s.record("", contentType, remoteIP, http.StatusBadRequest)
		http.Error(w, "exactly one logout_token is required", http.StatusBadRequest)
		return
	}
	token := form.Get("logout_token")
	e, c, status := s.recordValid(token, contentType, remoteIP, r.Host)
	if c.DelayFirstMS > 0 && status == http.StatusServiceUnavailable {
		timer := time.NewTimer(time.Duration(c.DelayFirstMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			select {
			case <-r.Context().Done():
				s.cancel(e)
				return
			default:
			}
		case <-r.Context().Done():
			s.cancel(e)
			return
		}
	}
	w.WriteHeader(status)
}

func (s *sink) control(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBody))
	if err != nil {
		http.Error(w, "invalid control body", http.StatusBadRequest)
		return
	}
	var input controlInput
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.FailFirst == nil || input.DelayFirstMS == nil || input.SuccessStatus == nil || *input.FailFirst < 0 || *input.FailFirst > maxEvents || *input.DelayFirstMS < 0 || *input.DelayFirstMS > 30000 || (*input.SuccessStatus != http.StatusOK && *input.SuccessStatus != http.StatusNoContent) {
		http.Error(w, "invalid control input", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.config = control{FailFirst: *input.FailFirst, DelayFirstMS: *input.DelayFirstMS, SuccessStatus: *input.SuccessStatus}
	s.valid = 0
	s.attempts = 0
	s.observations = nil
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *sink) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	events := make([]event, len(s.observations))
	for i, event := range s.observations {
		events[i] = *event
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Events []event `json:"events"`
	}{Events: events})
}

func (s *sink) livez(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *sink) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/backchannel", s.backchannel)
	mux.HandleFunc("/control", s.control)
	mux.HandleFunc("/events", s.events)
	mux.HandleFunc("/livez", s.livez)
	return mux
}

func failFirstFromEnv() (int, error) {
	raw := os.Getenv("FAIL_FIRST")
	if raw == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("FAIL_FIRST must be a non-negative integer")
	}
	return n, nil
}

func tlsFilesFromEnv(getenv func(string) string) (string, string, error) {
	certificateFile, keyFile := getenv("TLS_CERT_FILE"), getenv("TLS_KEY_FILE")
	if certificateFile == "" && keyFile == "" {
		return "", "", nil
	}
	if certificateFile == "" || keyFile == "" {
		return "", "", errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	return certificateFile, keyFile, nil
}

func run() error {
	failFirst, err := failFirstFromEnv()
	if err != nil {
		return err
	}
	certificateFile, keyFile, err := tlsFilesFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           newSink(failFirst).handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	errCh := make(chan error, 1)
	go func() {
		if certificateFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
			errCh <- server.ListenAndServeTLS(certificateFile, keyFile)
			return
		}
		errCh <- server.ListenAndServe()
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
