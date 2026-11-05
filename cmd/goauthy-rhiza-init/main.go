// goauthy-rhiza-init recovers Local storage before the application starts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	if os.Getenv("GOAUTHY_RHIZA_PROFILE") != storage.RhizaProfileStandaloneLocal {
		log.Fatal("Local init requires GOAUTHY_RHIZA_PROFILE=standalone-local")
	}
	config, err := storage.RhizaConfigFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := run(ctx, config); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, config rhiza.Config) error {
	if !config.Local || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck {
		return errors.New("Local init requires Local storage with before-ack durability")
	}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		return fmt.Errorf("open Local storage for recovery: %w", err)
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("close Local storage after recovery: %w", err)
	}
	return nil
}
