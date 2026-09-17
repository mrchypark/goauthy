// goauthy-bootstrap-secrets explicitly retrieves or purges a generated-secret
// artifact. Retrieval writes secrets to stdout; never use application logs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "goauthy-bootstrap-secrets:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, now time.Time) error {
	flags := flag.NewFlagSet("goauthy-bootstrap-secrets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "encrypted generated-secret artifact")
	keys := flags.String("key-dir", "", "master-key directory")
	purge := flags.Bool("purge-expired", false, "remove only an authenticated expired artifact")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || *keys == "" {
		return errors.New("require -file and -key-dir, with no positional arguments")
	}
	if *purge {
		removed, err := apikey.PurgeGeneratedBootstrapSecrets(*path, *keys, "", now)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Removed bool `json:"removed"`
		}{removed})
	}
	entries, err := apikey.ReadGeneratedBootstrapSecrets(*path, *keys, "", now)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(entries)
}
