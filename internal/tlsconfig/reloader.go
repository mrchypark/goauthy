// Package tlsconfig loads and atomically replaces the server certificate.
package tlsconfig

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/mrchypark/goauthy/internal/securefile"
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
	certificatePEM, err := os.ReadFile(r.certificateFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	keyPEM, err := securefile.Read(r.keyFile, 1<<20)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
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
