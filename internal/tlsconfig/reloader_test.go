package tlsconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewLoadsCertificateAndReloadReplacesIt(t *testing.T) {
	directory := t.TempDir()
	certificateFile, keyFile := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "key.pem")
	firstCertificate, firstKey := testCertificate(t, 1)
	writePair(t, certificateFile, keyFile, firstCertificate, firstKey)

	reloader, err := New(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reloader.GetCertificate(nil)
	if err != nil || !bytes.Equal(loaded.Certificate[0], certificateDER(t, firstCertificate)) {
		t.Fatalf("initial certificate=%v err=%v", loaded, err)
	}

	secondCertificate, secondKey := testCertificate(t, 2)
	writePair(t, certificateFile, keyFile, secondCertificate, secondKey)
	if err := reloader.Reload(); err != nil {
		t.Fatal(err)
	}
	loaded, err = reloader.GetCertificate(nil)
	if err != nil || !bytes.Equal(loaded.Certificate[0], certificateDER(t, secondCertificate)) {
		t.Fatalf("reloaded certificate=%v err=%v", loaded, err)
	}
}

func TestNewFailsClosedForInvalidMismatchedAndEmptyFiles(t *testing.T) {
	directory := t.TempDir()
	certificate, key := testCertificate(t, 1)
	_, otherKey := testCertificate(t, 2)
	for _, test := range []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
	}{
		{name: "invalid", certPEM: []byte("not PEM"), keyPEM: key},
		{name: "mismatched", certPEM: certificate, keyPEM: otherKey},
		{name: "empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificateFile, keyFile := filepath.Join(directory, test.name+".crt"), filepath.Join(directory, test.name+".key")
			writePair(t, certificateFile, keyFile, test.certPEM, test.keyPEM)
			if _, err := New(certificateFile, keyFile); err == nil {
				t.Fatal("New accepted an invalid certificate pair")
			}
		})
	}
}

func TestReloadRetainsLastKnownGoodCertificate(t *testing.T) {
	directory := t.TempDir()
	certificateFile, keyFile := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "key.pem")
	certificate, key := testCertificate(t, 1)
	writePair(t, certificateFile, keyFile, certificate, key)
	reloader, err := New(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certificateFile, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.Reload(); err == nil {
		t.Fatal("Reload accepted invalid PEM")
	}
	loaded, err := reloader.GetCertificate(nil)
	if err != nil || !bytes.Equal(loaded.Certificate[0], certificateDER(t, certificate)) {
		t.Fatalf("certificate changed after failed reload: %v err=%v", loaded, err)
	}
}

func TestGetCertificateAndReloadAreConcurrentSafe(t *testing.T) {
	directory := t.TempDir()
	certificateFile, keyFile := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "key.pem")
	certificate, key := testCertificate(t, 1)
	writePair(t, certificateFile, keyFile, certificate, key)
	reloader, err := New(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	const workerCount = 16
	ready := make(chan struct{}, workerCount)
	start := make(chan struct{})
	errs := make(chan error, workerCount)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ready <- struct{}{}
			<-start
			for range 100 {
				loaded, err := reloader.GetCertificate(nil)
				if err != nil || len(loaded.Certificate) == 0 {
					errs <- fmt.Errorf("GetCertificate: certificate=%v err=%v", loaded, err)
					return
				}
			}
		}()
	}
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ready <- struct{}{}
			<-start
			for range 25 {
				if err := reloader.Reload(); err != nil {
					errs <- fmt.Errorf("Reload: %v", err)
					return
				}
			}
		}()
	}
	for range workerCount {
		<-ready
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func testCertificate(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "goauthy.test"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), DNSNames: []string{"goauthy.test"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{SerialNumber: big.NewInt(serial)}, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func writePair(t *testing.T, certificateFile, keyFile string, certificate, key []byte) {
	t.Helper()
	if err := os.WriteFile(certificateFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
}

func certificateDER(t *testing.T, certificate []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid test certificate")
	}
	return block.Bytes
}
