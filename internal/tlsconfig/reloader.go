// Package tlsconfig loads and atomically replaces the server certificate.
package tlsconfig

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync/atomic"
)

var ErrNoCertificate = errors.New("TLS certificate is not loaded")

type Reloader struct {
	certificateFile string
	keyFile         string
	certificate     atomic.Pointer[tls.Certificate]
}

func New(certificateFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certificateFile: certificateFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload replaces the active certificate only after the new PEM pair validates.
func (r *Reloader) Reload() error {
	certificate, err := tls.LoadX509KeyPair(r.certificateFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	r.certificate.Store(&certificate)
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := r.certificate.Load()
	if certificate == nil {
		return nil, ErrNoCertificate
	}
	return certificate, nil
}
