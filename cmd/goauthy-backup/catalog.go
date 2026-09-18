package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/backupconfig"
	"github.com/mrchypark/goauthy/internal/storage"
)

func runCatalog(ctx context.Context, args []string, getenv func(string) string, out io.Writer) (err error) {
	flags := flag.NewFlagSet("goauthy-backup "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	prefix := flags.String("catalog-prefix", "", "independent immutable catalog namespace")
	keyPath := flags.String("key-file", "", "PKCS8 signing key (publish) or pinned PKIX public-key bundle (list/fetch/prune)")
	artifact := flags.String("file", "", "encrypted input (publish) or new output (fetch)")
	id := flags.String("id", "", "exact completed artifact ID (fetch)")
	work := flags.String("work-dir", "", "private scratch parent (fetch)")
	timeout := flags.Duration("timeout", 15*time.Minute, "operation timeout")
	maxBytes := flags.Int64("max-bytes", 16<<30, "maximum encrypted artifact bytes")
	keepDays := flags.Int("keep-days", 30, "UTC days to retain (0..65535)")
	policy := flags.String("retention-policy", string(backup.RetainLatest), "keep-latest or expire-all (prune only)")
	apply := flags.Bool("apply", false, "perform retention deletions (prune only)")
	maxEntries := flags.Int("max-entries", 4096, "maximum signed completion records")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *prefix == "" || *keyPath == "" || *timeout <= 0 || *maxBytes <= 0 || *maxBytes > 1<<50 || *maxEntries <= 0 || *keepDays < 0 || *keepDays > 65535 || (*policy != string(backup.RetainLatest) && *policy != string(backup.ExpireAll)) {
		return errors.New("invalid catalog arguments")
	}
	if args[0] == "publish" && (*artifact == "" || *id != "" || *work != "") || args[0] == "fetch" && (*artifact == "" || *id == "" || *work == "") || (args[0] == "list" || args[0] == "prune") && (*artifact != "" || *id != "" || *work != "") {
		return errors.New("invalid catalog command arguments")
	}
	if args[0] != "prune" && (*apply || *keepDays != 30 || *policy != string(backup.RetainLatest)) {
		return errors.New("retention flags require prune")
	}
	var private ed25519.PrivateKey
	var public []ed25519.PublicKey
	if args[0] == "publish" {
		private, _, err = readCatalogKey(*keyPath, true)
	} else {
		public, err = backupconfig.ReadCatalogTrustKeys(*keyPath)
	}
	if err != nil {
		return err
	}
	config, err := storage.RhizaConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	bucket, err := storage.OpenObjectStore(ctx, config)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bucket.Close()) }()
	switch args[0] {
	case "publish":
		file, openErr := os.Open(*artifact)
		if openErr != nil {
			return openErr
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		if info.Size() > *maxBytes {
			return errors.New("catalog artifact exceeds size limit")
		}
		entry, publishErr := backup.Publish(ctx, bucket, *prefix, path.Join(config.ObjStorePrefix, config.ClusterID), file, private, time.Now())
		if publishErr != nil {
			return publishErr
		}
		return json.NewEncoder(out).Encode(entry)
	case "list":
		entries, listErr := backup.ListCompleted(ctx, bucket, *prefix, public, *maxEntries)
		if listErr != nil {
			return listErr
		}
		return json.NewEncoder(out).Encode(entries)
	case "prune":
		entries, pruneErr := backup.PruneWithPolicy(ctx, bucket, *prefix, public, time.Now(), *keepDays, *maxEntries, *apply, backup.RetentionPolicy(*policy))
		if pruneErr != nil {
			return pruneErr
		}
		return json.NewEncoder(out).Encode(entries)
	case "fetch":
		name, entry, fetchErr := backup.FetchCompleted(ctx, bucket, *prefix, *id, public, *work, *maxBytes)
		if fetchErr != nil {
			return fetchErr
		}
		defer func() { err = errors.Join(err, os.Remove(name)) }()
		// Link publication requires scratch and destination on the same filesystem.
		if err := os.Link(name, *artifact); err != nil {
			return err
		}
		dir, openErr := os.Open(filepath.Dir(*artifact))
		if openErr != nil {
			return openErr
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(entry)
	}
	return errors.New("unknown catalog command")
}

func readCatalogKey(name string, private bool) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return backupconfig.ReadCatalogKey(name, private)
}
