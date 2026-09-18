package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math"
	"path"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/backupconfig"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func runCreate(ctx context.Context, args []string, getenv func(string) string, out io.Writer) (err error) {
	flags := flag.NewFlagSet("goauthy-backup create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recipientPath := flags.String("recipient-file", "", "age recipient file")
	signingPath := flags.String("signing-key-file", "", "PKCS8 Ed25519 catalog signing key")
	catalogPrefix := flags.String("catalog-prefix", "", "independent immutable catalog namespace")
	work := flags.String("work-dir", "", "private staging parent")
	timeout := flags.Duration("timeout", 15*time.Minute, "operation timeout")
	maxFiles := flags.Int("max-files", 65536, "maximum bundle entries")
	maxFile := flags.Int64("max-file-bytes", 1<<30, "maximum plaintext object bytes")
	maxTotal := flags.Int64("max-total-bytes", 8<<30, "maximum total plaintext bytes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *recipientPath == "" || *signingPath == "" || *catalogPrefix == "" || *work == "" || *timeout <= 0 || *maxFiles <= 0 || *maxFiles > 1<<20 || *maxFile <= 0 || *maxTotal <= 0 || *maxFile > *maxTotal || *maxTotal > (math.MaxInt64-(1<<33))/2 {
		return errors.New("invalid create arguments")
	}
	recipients, err := readRecipients(*recipientPath)
	if err != nil {
		return err
	}
	private, _, err := readCatalogKey(*signingPath, true)
	if err != nil {
		return err
	}
	sourceConfig, err := storage.RhizaConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	destinationConfig, separateDestination, err := backupDestinationConfig(getenv, sourceConfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	source, err := storage.OpenObjectStore(ctx, sourceConfig)
	if err != nil {
		return err
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			err = errors.Join(err, source.Close())
		}
	}()
	destination := source
	destinationClosed := true
	if separateDestination {
		destination, err = storage.OpenObjectStore(ctx, destinationConfig)
		if err != nil {
			return err
		}
		destinationClosed = false
		defer func() {
			if !destinationClosed {
				err = errors.Join(err, destination.Close())
			}
		}()
	}
	limits := backup.Limits{MaxFiles: *maxFiles, MaxFileBytes: *maxFile, MaxTotalBytes: *maxTotal}
	entry, err := backup.Create(ctx, source, destination, path.Join(sourceConfig.ObjStorePrefix, sourceConfig.ClusterID), sourceConfig.ClusterID, *catalogPrefix, recipients, private, *work, limits)
	if err != nil {
		return err
	}
	if separateDestination {
		destinationClosed = true
		if err := destination.Close(); err != nil {
			return err
		}
	}
	sourceClosed = true
	if err := source.Close(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(entry)
}

func readRecipients(name string) ([]age.Recipient, error) {
	return backupconfig.ReadRecipients(name)
}

func backupDestinationConfig(getenv func(string) string, source rhiza.Config) (rhiza.Config, bool, error) {
	return backupconfig.DestinationConfig(getenv, source)
}
