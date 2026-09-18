// Test-only observer of certified object-store state; never a voter or writer.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/mrchypark/rhiza"
)

func run() (resultErr error) {
	identityFile := flag.String("identity-file", "", "JSON storage identity used by the server scheduler")
	due := flag.Int64("due", 0, "exact expected completed Unix second")
	flag.Parse()
	raw, err := os.ReadFile(*identityFile)
	if err != nil {
		return errors.New("read scheduler identity")
	}
	var identity []string
	if json.Unmarshal(raw, &identity) != nil || len(identity) != 9 || *due <= 0 {
		return errors.New("invalid observer identity or due")
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	scope := fmt.Sprintf("scheduled-backup/%x", sha256.Sum256(canonical))
	key := fmt.Sprintf("goauthy/backup-completed/%x", sha256.Sum256([]byte(scope)))
	dir, err := os.MkdirTemp("", "goauthy-watermark-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(dir)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	replica, err := rhiza.OpenReadReplica(ctx, rhiza.ReplicaConfig{
		ClusterID: os.Getenv("GOAUTHY_CLUSTER_ID"), ReplicaID: "backup-watermark-observer", DataDir: dir,
		Members:          []rhiza.ReplicaMember{{ID: "goauthy-0"}, {ID: "goauthy-1"}, {ID: "goauthy-2"}},
		ObjStoreProvider: "s3", ObjStoreEndpoint: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT"),
		ObjStoreBucket: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_BUCKET"), ObjStorePrefix: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"),
		ObjStoreRegion: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_REGION"), ObjStoreInsecure: true,
		ObjStoreAccessKey: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY"), ObjStoreSecretKey: os.Getenv("GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY"),
	})
	if err != nil {
		return errors.New("open certified object-store observer")
	}
	defer func() { resultErr = errors.Join(resultErr, replica.Close()) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := replica.Sync(ctx); err != nil {
			return errors.New("sync certified object-store observer")
		}
		value, err := replica.KVGet(ctx, rhiza.KVGetRequest{Key: key})
		if err != nil {
			return errors.New("read certified completion marker")
		}
		if value.Found {
			got, err := strconv.ParseInt(string(value.Value), 10, 64)
			if err != nil || strconv.FormatInt(got, 10) != string(value.Value) || got <= 0 {
				return errors.New("invalid certified completion marker")
			}
			if got > *due {
				return errors.New("unexpected later completion marker")
			}
			if got == *due {
				if value.AppliedSlot == 0 || value.AppliedSlot > value.ConsensusTip {
					return errors.New("inconsistent certified read metadata")
				}
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"due": got, "applied_slot": value.AppliedSlot})
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("expected certified completion marker not observed")
		case <-ticker.C:
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
