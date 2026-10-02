// Command e2e-saas-isolation-fixture is a bounded local HTTPS SaaS provider
// used only by the opt-in #113 topology measurement.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxTokenFileBytes = 4096
	slowLimit         = 20 * time.Second
)

type options struct {
	addr, certFile, keyFile, tokenFile string
}

type routeCounts struct {
	started   atomic.Int64
	active    atomic.Int64
	completed atomic.Int64
}

type fixture struct {
	tokenHash [32]byte
	hasToken  bool
	counts    map[string]*routeCounts
}

func parseOptions(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("e2e-saas-isolation-fixture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.addr, "addr", ":443", "HTTPS listen address")
	fs.StringVar(&o.certFile, "cert", "", "TLS certificate file")
	fs.StringVar(&o.keyFile, "key", "", "TLS private key file")
	fs.StringVar(&o.tokenFile, "token-file", "", "optional private file containing the expected synthetic bearer token; without it only /metrics is accessible")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 || o.certFile == "" || o.keyFile == "" {
		return options{}, errors.New("-cert and -key are required; positional arguments are not accepted")
	}
	return o, nil
}

func readTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("token file must be a regular file with no group or other permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	if len(data) > maxTokenFileBytes {
		return "", errors.New("token file exceeds size limit")
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	token := string(data)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n\t ") {
		return "", errors.New("token file must contain one non-empty bearer token line")
	}
	return token, nil
}

func newFixture(token string) *fixture {
	counts := make(map[string]*routeCounts, 4)
	for _, route := range []string{"healthy", "slow-headers", "slow-body", "fail"} {
		counts[route] = &routeCounts{}
	}
	return &fixture{tokenHash: sha256.Sum256([]byte(token)), hasToken: token != "", counts: counts}
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/metrics" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.writeMetrics(w)
		return
	}
	route := strings.TrimPrefix(r.URL.Path, "/")
	counts, ok := f.counts[route]
	if !ok || strings.Contains(route, "/") || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	counts.started.Add(1)
	counts.active.Add(1)
	defer func() {
		counts.active.Add(-1)
		counts.completed.Add(1)
	}()
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !f.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		if err := writeJSON(w, http.StatusUnauthorized, `{"error":"unauthorized"}`); err != nil {
			return
		}
		return
	}

	switch route {
	case "healthy":
		if err := writeJSON(w, http.StatusOK, `{"ok":true,"provider":"e2e-saas-isolation"}`); err != nil {
			return
		}
	case "slow-headers":
		if waitForCancellationOrLimit(r.Context()) {
			return
		}
		if err := writeJSON(w, http.StatusGatewayTimeout, `{"error":"fixture delay limit reached"}`); err != nil {
			return
		}
	case "slow-body":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, `{"ok":true,"route":"slow-body","items":[1`); err != nil {
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		} else {
			return
		}
		if waitForCancellationOrLimit(r.Context()) {
			return
		}
		if _, err := io.WriteString(w, `,2]}`); err != nil {
			return
		}
	case "fail":
		if err := writeJSON(w, http.StatusServiceUnavailable, `{"error":"synthetic provider failure"}`); err != nil {
			return
		}
	}
}

func (f *fixture) authorized(r *http.Request) bool {
	if !f.hasToken {
		return false
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(f.tokenHash[:], got[:]) == 1
}

func (f *fixture) writeMetrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	metrics := make(map[string]map[string]int64, len(f.counts))
	for route, c := range f.counts {
		metrics[route] = map[string]int64{
			"started": c.started.Load(), "active": c.active.Load(), "completed": c.completed.Load(),
		}
	}
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		return
	}
}

func waitForCancellationOrLimit(ctx context.Context) bool {
	timer := time.NewTimer(slowLimit)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err := io.WriteString(w, body)
	return err
}

func run(args []string) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	token := ""
	if o.tokenFile != "" {
		token, err = readTokenFile(o.tokenFile)
		if err != nil {
			return err
		}
	}
	cert, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	listener, err := net.Listen("tcp", o.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := &http.Server{
		Handler:           newFixture(token),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      25 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{cert}},
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ServeTLS(listener, "", "") }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTPS: %w", err)
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutdown HTTPS: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
