// goauthy-checkpoint-fault is a test-only proxy used by the Kind DR test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultListen   = "127.0.0.1:9001"
	defaultControl  = "127.0.0.1:9002"
	defaultUpstream = "http://minio.goauthy.svc.cluster.local:9000"
	stallBytes      = 32 * 1024 // Rhiza's io.Copy buffer must fill before MinIO's Object.Read returns.
)

type config struct {
	listen, control string
	upstream        *url.URL
	dataDir, block  string
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	return err == nil && net.ParseIP(host).IsLoopback()
}

func loadConfig() (config, error) {
	upstream, err := url.Parse(getenv("UPSTREAM", defaultUpstream))
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || (upstream.Path != "" && upstream.Path != "/") || (upstream.RawPath != "" && upstream.RawPath != "/") || upstream.RawQuery != "" || upstream.Fragment != "" {
		return config{}, errors.New("invalid upstream")
	}
	listen := getenv("LISTEN", defaultListen)
	control := getenv("CONTROL_LISTEN", defaultControl)
	if !isLoopbackAddress(listen) {
		return config{}, errors.New("invalid listen address")
	}
	if !isLoopbackAddress(control) {
		return config{}, errors.New("control listener must be loopback")
	}
	dataDir := os.Getenv("DATA_DIR")
	block := os.Getenv("BLOCK_PATH")
	if !filepath.IsAbs(dataDir) || !strings.HasPrefix(block, "/") || strings.ContainsAny(block, "?#") {
		return config{}, errors.New("invalid fault target")
	}
	return config{listen: listen, control: control, upstream: upstream, dataDir: dataDir, block: block}, nil
}

type fault struct {
	dataDir string
	block   string

	mu          sync.Mutex
	claimed     bool
	blocked     bool
	cancelled   bool
	released    bool
	prefix      []byte
	release     chan struct{}
	releaseOnce sync.Once
}

func newFault(dataDir, block string) *fault {
	return &fault{dataDir: dataDir, block: block, release: make(chan struct{})}
}

func (f *fault) shouldFault(r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != f.block || !hasRestoreDir(f.dataDir) {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.claimed && !f.released
}

func hasRestoreDir(dataDir string) bool {
	paths, err := filepath.Glob(filepath.Join(dataDir, ".rhiza-checkpoint-restore-*"))
	if err != nil {
		return false
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func (f *fault) begin(prefix []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimed || f.released {
		return false
	}
	f.claimed = true
	f.prefix = append([]byte(nil), prefix...)
	f.blocked = true
	return true
}

func (f *fault) cancel() {
	f.mu.Lock()
	f.cancelled = true
	f.blocked = false
	f.mu.Unlock()
}

func (f *fault) unblock() {
	f.mu.Lock()
	f.released = true
	f.blocked = false
	f.mu.Unlock()
	f.releaseOnce.Do(func() { close(f.release) })
}

type faultStatus struct {
	Blocked        bool `json:"blocked"`
	PartialWritten bool `json:"partial_written"`
	Cancelled      bool `json:"cancelled"`
	Released       bool `json:"released"`
}

func (f *fault) status() faultStatus {
	f.mu.Lock()
	status := faultStatus{Blocked: f.blocked, Cancelled: f.cancelled, Released: f.released}
	prefix := append([]byte(nil), f.prefix...)
	f.mu.Unlock()
	status.PartialWritten = len(prefix) == stallBytes && restorePrefixMatches(f.dataDir, prefix)
	return status
}

func restorePrefixMatches(dataDir string, prefix []byte) bool {
	paths, err := filepath.Glob(filepath.Join(dataDir, ".rhiza-checkpoint-restore-*", "sqlite.db"))
	if err != nil {
		return false
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		got := make([]byte, len(prefix))
		n, readErr := io.ReadFull(file, got)
		file.Close()
		if readErr == nil && n == len(prefix) && bytes.Equal(got, prefix) {
			return true
		}
	}
	return false
}

type stalledBody struct {
	io.ReadCloser
	fault       *fault
	ctx         context.Context
	pending     []byte
	finalErr    error
	passthrough bool
	started     bool
	waited      bool
}

func (b *stalledBody) Read(p []byte) (int, error) {
	if !b.started {
		b.started = true
		prefix := make([]byte, stallBytes)
		n, err := io.ReadFull(b.ReadCloser, prefix)
		if n < len(prefix) {
			b.pending = prefix[:n]
			b.finalErr = err
			b.passthrough = true
		} else if b.fault.begin(prefix) {
			b.pending = prefix
		} else {
			b.pending = prefix
			b.passthrough = true
		}
	}
	if len(b.pending) > 0 {
		n := copy(p, b.pending)
		b.pending = b.pending[n:]
		if len(b.pending) == 0 && b.finalErr != nil {
			return n, b.finalErr
		}
		return n, nil
	}
	if b.passthrough {
		return b.ReadCloser.Read(p)
	}
	if !b.waited {
		b.waited = true
		select {
		case <-b.fault.release:
		case <-b.ctx.Done():
			b.fault.cancel()
			return 0, b.ctx.Err()
		}
	}
	return b.ReadCloser.Read(p)
}

func newProxy(target *url.URL, f *fault) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		host := r.Host
		originalDirector(r)
		r.Host = host // SigV4 signs this host; only URL routing changes.
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.StatusCode >= 200 && response.StatusCode < 300 && f.shouldFault(response.Request) {
			response.Body = &stalledBody{ReadCloser: response.Body, fault: f, ctx: response.Request.Context()}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "proxy request failed", http.StatusBadGateway)
	}
	return proxy
}

func controlHandler(f *fault) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.status())
	})
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.unblock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func controlCommand(command, control string) error {
	if !isLoopbackAddress(control) {
		return errors.New("invalid control address")
	}
	method, path := http.MethodGet, "/status"
	if command == "release" {
		method, path = http.MethodPost, "/release"
	} else if command != "status" {
		return errors.New("invalid command")
	}
	request, err := http.NewRequest(method, "http://"+control+path, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return errors.New("control request failed")
	}
	if command == "status" {
		_, err = io.Copy(os.Stdout, response.Body)
	}
	return err
}

func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "status" || os.Args[1] == "release") {
		return controlCommand(os.Args[1], getenv("CONTROL_LISTEN", defaultControl))
	}
	if len(os.Args) != 1 {
		return errors.New("invalid command")
	}
	config, err := loadConfig()
	if err != nil {
		return err
	}
	fault := newFault(config.dataDir, config.block)
	proxyListener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return errors.New("proxy listener failed")
	}
	defer proxyListener.Close()
	control, err := net.Listen("tcp", config.control)
	if err != nil {
		return errors.New("control listener failed")
	}
	defer control.Close()
	errs := make(chan error, 2)
	go func() { errs <- http.Serve(proxyListener, newProxy(config.upstream, fault)) }()
	go func() { errs <- http.Serve(control, controlHandler(fault)) }()
	return <-errs
}

func main() {
	if err := run(); err != nil {
		// Configuration and transport diagnostics must not disclose S3 credentials.
		os.Stderr.WriteString("checkpoint fault proxy failed\n")
		os.Exit(1)
	}
}
