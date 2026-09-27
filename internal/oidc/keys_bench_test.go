package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type signingKeyBenchFixture struct {
	db            *rhiza.DB
	keyring       *Keyring
	issuer        string
	kid           string
	publicJSON    string
	encoded       string
	envelope      []byte
	seed          []byte
	createdAtUnix int64
}

func newSigningKeyBenchFixture(b *testing.B) signingKeyBenchFixture {
	b.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "oidc-key-bench", DataDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		b.Fatal(err)
	}
	keyring := fixedKeyring("master-a")
	issuer := "https://id.example.com"
	createdAt := time.Unix(1_800_000_000, 0).UTC()
	key, err := EnsureSigningKey(ctx, db, keyring, issuer, createdAt)
	if err != nil {
		b.Fatal("ensure benchmark signing key:", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT kid, public_jwk, private_envelope, created_at_unix_ms FROM oidc_signing_keys WHERE state='active' LIMIT 1`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(row.Rows) != 1 || len(row.Rows[0]) != 4 {
		b.Fatalf("read benchmark signing-key row: rows=%d err=%v", len(row.Rows), err)
	}
	kid, ok := row.Rows[0][0].(string)
	if !ok {
		b.Fatal("invalid benchmark signing-key ID")
	}
	publicJSON, ok := row.Rows[0][1].(string)
	if !ok {
		b.Fatal("invalid benchmark public JWK")
	}
	encoded, ok := row.Rows[0][2].(string)
	if !ok {
		b.Fatal("invalid benchmark signing-key envelope")
	}
	createdAtUnix, ok := row.Rows[0][3].(int64)
	if !ok {
		b.Fatal("invalid benchmark signing-key creation time")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		b.Fatal("decode benchmark envelope:", err)
	}
	seed, err := openEnvelope(keyring, issuer, kid, envelope)
	if err != nil {
		b.Fatal("open benchmark envelope:", err)
	}
	b.Cleanup(func() {
		for i := range seed {
			seed[i] = 0
		}
		for i := range key.Private {
			key.Private[i] = 0
		}
	})
	return signingKeyBenchFixture{db: db, keyring: keyring, issuer: issuer, kid: kid, publicJSON: publicJSON, encoded: encoded, envelope: envelope, seed: seed, createdAtUnix: createdAtUnix}
}

func BenchmarkLoadActiveSigningKey(b *testing.B) {
	f := newSigningKeyBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadActiveSigningKey(context.Background(), f.db, f.keyring, f.issuer); err != nil {
			b.Fatal("load active signing key:", err)
		}
	}
}

func BenchmarkLoadActiveSigningKeyStages(b *testing.B) {
	f := newSigningKeyBenchFixture(b)
	ctx := context.Background()
	b.Run("active-row-query", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := f.db.Query(ctx, rhiza.QueryRequest{
				SQL:         `SELECT kid, public_jwk, private_envelope, created_at_unix_ms FROM oidc_signing_keys WHERE state='active' LIMIT 1`,
				Consistency: rhiza.ConsistencyLinearizable,
			}); err != nil {
				b.Fatal("query active signing key:", err)
			}
		}
	})
	b.Run("base64-decode-and-envelope-open", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			envelope, err := base64.RawURLEncoding.DecodeString(f.encoded)
			if err != nil {
				b.Fatal("decode signing-key envelope:", err)
			}
			seed, err := openEnvelope(f.keyring, f.issuer, f.kid, envelope)
			if err != nil {
				b.Fatal("open signing-key envelope:", err)
			}
			for j := range seed {
				seed[j] = 0
			}
		}
	})
	b.Run("seed-to-signing-key-reconstruction", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			key, _, _, err := signingKeyFromSeed(f.seed, time.UnixMilli(f.createdAtUnix))
			if err != nil {
				b.Fatal("reconstruct signing key:", err)
			}
			for j := range key.Private {
				key.Private[j] = 0
			}
		}
	})
	b.Run("stored-public-jwk-parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var stored any
			if err := json.Unmarshal([]byte(f.publicJSON), &stored); err != nil {
				b.Fatal("parse stored public JWK:", err)
			}
		}
	})
}
