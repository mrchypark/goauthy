package backupconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/backup"
)

func TestCatalogTrustBundle(t *testing.T) {
	var bundle []byte
	var first []byte
	for range backup.MaxCatalogTrustKeys + 1 {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if first == nil {
			first = encoded
		}
		bundle = append(bundle, encoded...)
	}
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKIXPublicKey(&wrong.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want int
	}{
		{"one", first, 1},
		{"bounded", bundle[:len(bundle)-len(first)], backup.MaxCatalogTrustKeys},
		{"whitespace", append([]byte(" \n"), first...), 1},
		{"empty", nil, 0},
		{"too many", bundle, 0},
		{"duplicate", bytes.Repeat(first, 2), 0},
		{"leading junk", append([]byte("junk\n"), first...), 0},
		{"trailing junk", append(append([]byte(nil), first...), 'x'), 0},
		{"skipped malformed block", append([]byte("-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----\n"), first...), 0},
		{"wrong algorithm", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrongDER}), 0},
		{"headers", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"X": "Y"}, Bytes: []byte{1}}), 0},
		{"oversize", bytes.Repeat([]byte(" "), 16385), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "trust.pem")
			if err := os.WriteFile(file, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			keys, err := ReadCatalogTrustKeys(file)
			if tc.want == 0 {
				if err == nil {
					t.Fatal("accepted invalid trust bundle")
				}
				return
			}
			if err != nil || len(keys) != tc.want {
				t.Fatalf("count=%d err=%v", len(keys), err)
			}
		})
	}
	if _, err := ReadCatalogTrustKeys(t.TempDir()); err == nil {
		t.Fatal("accepted directory")
	}
}
