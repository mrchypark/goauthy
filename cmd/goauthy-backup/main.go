// goauthy-backup exports encrypted Rhiza snapshots and restores them offline.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/storage"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout); err != nil {
		// Provider errors can contain credential-bearing URLs. Never log them.
		command := "command"
		if len(os.Args) > 1 {
			switch os.Args[1] {
			case "export", "restore", "create", "publish", "list", "fetch", "prune":
				command = os.Args[1]
			}
		}
		fmt.Fprintf(os.Stderr, "goauthy-backup %s: %s; no success is declared\n", command, backupFailureMessage(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) (err error) {
	if len(args) > 0 && args[0] == "create" {
		return runCreate(ctx, args[1:], getenv, out)
	}
	if len(args) > 0 && (args[0] == "publish" || args[0] == "list" || args[0] == "fetch" || args[0] == "prune") {
		return runCatalog(ctx, args, getenv, out)
	}
	if len(args) == 0 || (args[0] != "export" && args[0] != "restore") {
		return errors.New("require export or restore")
	}
	mode := args[0]
	flags := flag.NewFlagSet("goauthy-backup "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("file", "", "encrypted artifact path; export never overwrites")
	keys := flags.String("key-file", "", "age recipients (export) or private identities (restore)")
	expected := flags.String("sha256", "", "independently trusted artifact digest required for restore")
	work := flags.String("work-dir", "", "private staging parent")
	timeout := flags.Duration("timeout", 15*time.Minute, "operation timeout")
	maxFiles := flags.Int("max-files", 65536, "maximum bundle entries")
	maxFile := flags.Int64("max-file-bytes", 1<<30, "maximum plaintext object bytes")
	maxTotal := flags.Int64("max-total-bytes", 8<<30, "maximum total plaintext bytes")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *artifact == "" || *keys == "" || *work == "" || *timeout <= 0 || *maxFiles <= 0 || *maxFiles > 1<<20 || *maxFile <= 0 || *maxTotal <= 0 || *maxFile > *maxTotal || *maxTotal > (math.MaxInt64-(1<<33))/2 {
		return errors.New("invalid backup arguments")
	}
	if mode == "export" && *expected != "" {
		return errors.New("export does not accept a digest")
	}
	var wanted []byte
	if mode == "restore" {
		wanted, err = hex.DecodeString(*expected)
		if err != nil || len(wanted) != sha256.Size || strings.ToLower(*expected) != *expected {
			return errors.New("restore requires a trusted lowercase SHA-256")
		}
	}
	keyFile, err := os.Open(*keys)
	if err != nil {
		return err
	}
	info, statErr := keyFile.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || (mode == "restore" && info.Mode().Perm()&0077 != 0) {
		return errors.Join(errors.New("invalid key file or private-key permissions"), statErr, keyFile.Close())
	}
	var recipients []age.Recipient
	var identities []age.Identity
	if mode == "export" {
		recipients, err = age.ParseRecipients(io.LimitReader(keyFile, (1<<20)+1))
	} else {
		identities, err = age.ParseIdentities(io.LimitReader(keyFile, (1<<20)+1))
	}
	err = errors.Join(err, keyFile.Close())
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
	prefix := path.Join(config.ObjStorePrefix, config.ClusterID)
	limits := backup.Limits{MaxFiles: *maxFiles, MaxFileBytes: *maxFile, MaxTotalBytes: *maxTotal}
	if mode == "export" {
		// A same-directory temporary file plus link publishes without replacing any
		// existing artifact. The parent directory must remain exclusively controlled.
		var file *os.File
		file, err = os.CreateTemp(filepath.Dir(*artifact), ".goauthy-backup-")
		if err != nil {
			return err
		}
		name := file.Name()
		defer func() { err = errors.Join(err, file.Close(), os.Remove(name)) }()
		digest := sha256.New()
		if _, err := backup.Export(ctx, bucket, prefix, config.ClusterID, io.MultiWriter(file, digest), recipients, *work, limits); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := os.Link(name, *artifact); err != nil {
			return err
		}
		dir, err := os.Open(filepath.Dir(*artifact))
		if err != nil {
			return err
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%x\n", digest.Sum(nil))
		return err
	}
	file, err := os.Open(*artifact)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err = file.Stat()
	if err != nil {
		return err
	}
	// Conservative encrypted framing bound, with arithmetic bounded above.
	if !info.Mode().IsRegular() || info.Size() > 2**maxTotal+int64(*maxFiles)*4096+(1<<20) {
		return errors.New("invalid artifact size or type")
	}
	// Copy to owned staging while hashing: extraction consumes exactly the bytes
	// whose digest was checked, even if the supplied path is changed concurrently.
	copyFile, err := os.CreateTemp(*work, ".goauthy-backup-input-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, copyFile.Close(), os.Remove(copyFile.Name())) }()
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(copyFile, digest), io.LimitReader(file, info.Size()+1))
	if err != nil || n != info.Size() || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), hex.EncodeToString(wanted)) {
		return errors.Join(errors.New("artifact digest or size mismatch"), err)
	}
	if _, err := copyFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	staged, err := backup.Extract(copyFile, identities, *work, limits)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staged.Dir)) }()
	if _, err := backup.Restore(ctx, bucket, prefix, config.ClusterID, staged, *work); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "restored")
	return err
}

func backupFailureMessage(err error) string { return backup.FailureMessage(err) }
