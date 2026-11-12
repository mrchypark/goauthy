package backchannel

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mrchypark/goauthy/internal/securefile"
)

const maxRootCAFileSize = 256 << 10

// RootCAReloader atomically retains the most recently valid explicit trust
// bundle. It intentionally never includes system roots: an explicit bundle is
// an operator-selected replacement trust store.
type RootCAReloader struct {
	path string
	pool atomic.Pointer[x509.CertPool]
}

// NewRootCAReloader loads the initial explicit trust bundle. A caller must not
// construct one for an empty path; nil continues to mean system roots.
func NewRootCAReloader(path string) (*RootCAReloader, error) {
	if path == "" {
		return nil, errors.New("back-channel CA file path is empty")
	}
	r := &RootCAReloader{path: path}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload replaces the active trust bundle only after the file fully validates.
// On failure, Pool continues to return the last known-good bundle.
func (r *RootCAReloader) Reload() error {
	pool, err := LoadRootCAs(r.path)
	if err != nil {
		return err
	}
	r.pool.Store(pool)
	return nil
}

// Pool returns the current explicit trust bundle. The returned pool is never
// mutated by the reloader.
func (r *RootCAReloader) Pool() *x509.CertPool {
	return r.pool.Load()
}

// LoadRootCAs loads an explicit PEM trust bundle for HTTPS delivery. An empty
// path returns nil so callers retain the platform system roots. The bundle is
// deliberately validated as certificate-only and must be owner-only.
func LoadRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := securefile.Read(path, maxRootCAFileSize)
	if err != nil {
		return nil, fmt.Errorf("read back-channel CA file: %w", err)
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("back-channel CA file must contain only valid PEM certificates")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("back-channel CA file must contain only valid PEM certificates")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("back-channel CA file must contain only valid PEM certificates")
		}
		pool.AddCert(certificate)
		count++
		data = rest
	}
	if count == 0 {
		return nil, errors.New("back-channel CA file must contain at least one PEM certificate")
	}
	return pool, nil
}
