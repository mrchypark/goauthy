package e2e_tls

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTLSCertificate(t *testing.T) {
	url, caFile, serial := os.Getenv("GOAUTHY_TLS_E2E_URL"), os.Getenv("GOAUTHY_TLS_E2E_CA_FILE"), os.Getenv("GOAUTHY_TLS_E2E_SERIAL")
	if url == "" || caFile == "" || serial == "" {
		t.Skip("set GOAUTHY_TLS_E2E_URL, GOAUTHY_TLS_E2E_CA_FILE, and GOAUTHY_TLS_E2E_SERIAL")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid test CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	response, err := client.Get(url + "/livez")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("livez status=%d", response.StatusCode)
	}
	if got := strings.ToLower(response.TLS.PeerCertificates[0].SerialNumber.Text(16)); got != strings.ToLower(serial) {
		t.Fatalf("certificate serial=%s want=%s", got, serial)
	}
}
