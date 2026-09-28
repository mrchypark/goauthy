package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/thanos-io/objstore/providers/filesystem"
)

// This opt-in Darwin harness is invoked once per fresh process. Counter reads
// surround the operation; memory snapshots are outside the wall/CPU bracket.
// No GC, profiler, output, or correctness probes run inside an operation.
func TestSnapshot112IsolatedRestore(t *testing.T) {
	source := os.Getenv("GOAUTHY_SNAPSHOT112_RESTORE_BUNDLE")
	if source == "" {
		t.Skip("requires prebuilt synthetic bundle")
	}
	metadata, err := os.ReadFile(filepath.Join(source, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Key, Session, Other string
		Tokens              []string
		Shape               int
	}
	if err := json.Unmarshal(metadata, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := age.ParseX25519Identity(fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(filepath.Join(source, "bundle.age"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	root := t.TempDir()
	bucket, err := filesystem.NewBucket(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	limits := backup.Limits{MaxFiles: 4096, MaxFileBytes: 64 << 20, MaxTotalBytes: 128 << 20}
	type sample struct {
		Phase                    string
		WallNS, UserUS, SystemUS int64
		TotalAlloc, Mallocs      uint64
	}
	var samples []sample
	measure := func(phase string, operation func() error) {
		var before, after runtime.MemStats
		var first, last syscall.Rusage
		runtime.ReadMemStats(&before)
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &first); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		operationErr := operation()
		elapsed := time.Since(start)
		counterErr := syscall.Getrusage(syscall.RUSAGE_SELF, &last)
		runtime.ReadMemStats(&after)
		if operationErr != nil {
			t.Fatal(operationErr)
		}
		if counterErr != nil {
			t.Fatal(counterErr)
		}
		micros := func(v syscall.Timeval) int64 { return v.Sec*1000000 + int64(v.Usec) }
		samples = append(samples, sample{phase, elapsed.Nanoseconds(), micros(last.Utime) - micros(first.Utime), micros(last.Stime) - micros(first.Stime), after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs})
	}
	measure("empty", func() error { return nil })
	// Keep phase results for subsequent operations and untimed validation.
	var extracted backup.Extracted
	measure("extract", func() error {
		var err error
		extracted, err = backup.Extract(input, []age.Identity{key}, root, limits)
		return err
	})
	measure("restore", func() error {
		_, err := backup.Restore(ctx, bucket, "target/snapshot112", "snapshot112", extracted, root)
		return err
	})
	var db *rhiza.DB
	measure("open_ready", func() error {
		var err error
		db, err = rhiza.Open(ctx, rhiza.Config{ClusterID: "snapshot112", NodeID: "source", DataDir: filepath.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"), ObjStorePrefix: "target", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour})
		return err
	})
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	if !db.Ready() {
		t.Fatal("single-node Open returned before recovery readiness")
	}
	server := oauthTestServer(t, db, bytes.Repeat([]byte{7}, 32))
	bs, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1} {
		signature := fmt.Sprintf("synthetic-%03d", i)
		request, err := server.store.GetAuthorizeCodeSession(ctx, signature, nil)
		if i == 0 && !errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) || i == 1 && err != nil {
			t.Fatalf("code %d: %v", i, err)
		}
		if request == nil || request.GetID() != signature || request.GetClient().GetID() != testClientID || request.GetRequestForm().Get("redirect_uri") != testRedirectURI {
			t.Fatal("code error/request or binding changed")
		}
		pkce, err := server.store.GetPKCERequestSession(ctx, signature, nil)
		if i == 0 {
			if !errors.Is(err, fosite.ErrNotFound) {
				t.Fatalf("consumed PKCE: %v", err)
			}
		} else if err != nil || pkce.GetID() != signature || pkce.GetRequestForm().Get("code_challenge_method") != "S256" || pkce.GetRequestForm().Get("code_challenge") == "" {
			t.Fatalf("pending PKCE binding: %v", err)
		}
		loaded, err := bs.LoadAuthorizationInteractionReadOnly(ctx, fixture.Session, fixture.Tokens[i])
		if i == 0 {
			if !errors.Is(err, browser.ErrConsumed) {
				t.Fatalf("consumed interaction: %v", err)
			}
		} else if err != nil || loaded.RequestID != signature || !bytes.Equal(loaded.Payload, snapshotPayload(snapshotShapes[fixture.Shape].payload, i)) {
			t.Fatalf("pending interaction: %v", err)
		}
		if _, err := bs.LoadAuthorizationInteractionReadOnly(ctx, fixture.Other, fixture.Tokens[i]); !errors.Is(err, browser.ErrNotFound) {
			t.Fatalf("wrong session: %v", err)
		}
	}
	snapshotLog(t, "isolated_restore", map[string]any{"shape": snapshotShapes[fixture.Shape].name, "phases": samples, "bindings_checked": true})
}
