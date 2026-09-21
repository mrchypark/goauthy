package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestOpenObjectStoreRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	secret := "do-not-disclose"
	for _, test := range []struct {
		name   string
		config rhiza.Config
	}{
		{"missing bucket", rhiza.Config{ObjStoreProvider: "s3", ObjStoreAccessKey: secret}},
		{"missing provider", rhiza.Config{ObjStoreBucket: "bucket", ObjStoreAccessKey: secret}},
		{"filesystem", rhiza.Config{ObjStoreProvider: "filesystem", ObjStoreBucket: "bucket", ObjStoreDir: "/tmp/store", ObjStoreAccessKey: secret}},
		{"unsupported provider", rhiza.Config{ObjStoreProvider: "azure", ObjStoreBucket: "bucket", ObjStoreAccessKey: secret}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := OpenObjectStore(context.Background(), test.config)
			if err == nil {
				t.Fatal("invalid object-store config was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error exposes credentials: %v", err)
			}
		})
	}
}
