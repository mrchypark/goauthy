//go:build integration

package oauth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const expiry65CheckpointHistory = "fresh open; Rhiza archive checkpoints excluded by 1h/512MiB policy with case <=60s and disk <=256MiB; default SQLite PASSIVE checkpoints remain uncontrolled (1s worker)"

// outcome.json is mutable finalization status, excluded from SHA256SUMS.
// Missing, pending, failed, or unreadable status must never certify completion.
func expiry65Finalize(root string, started time.Time, now func() time.Time, completed int, peak int64, failed bool) (err error) {
	outcome := map[string]any{"completed_cases": completed, "planned_cases": 45, "sampled_peak_file_bytes": peak, "complete": false, "failed": true, "finalization_status": "pending"}
	write := func() error {
		b, e := json.MarshalIndent(outcome, "", "  ")
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(root, "outcome.json"), b, 0600)
	}
	if err = write(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			outcome["complete"], outcome["failed"], outcome["finalization_status"] = false, true, "failed"
			err = errors.Join(err, write())
		}
	}()
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var hashes strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "outcome.json" || entry.Name() == "SHA256SUMS" {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(root, entry.Name()))
		if e != nil {
			return e
		}
		fmt.Fprintf(&hashes, "%x  %s\n", sha256.Sum256(raw), entry.Name())
	}
	if err = os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(hashes.String()), 0600); err != nil {
		return err
	}
	elapsed := now().Sub(started)
	if elapsed > 600*time.Second {
		return errors.New("aggregate evidence cap exceeded")
	}
	outcome["elapsed_ns"] = elapsed.Nanoseconds() // post-hash, before status publication
	if err = write(); err != nil {
		return err
	}
	// Keep status pending through the last deadline gate. The final status
	// write reports the gate result; it cannot certify its own elapsed time.
	if now().Sub(started) > 600*time.Second {
		return errors.New("aggregate status publication cap exceeded")
	}
	outcome["finalization_status"] = "complete"
	outcome["complete"], outcome["failed"] = completed == 45 && !failed, failed
	return write()
}

func TestExpiry65Finalization(t *testing.T) {
	for _, scenario := range []string{"success", "checksum_error", "hash_deadline", "publication_deadline", "prior_failure"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "evidence.log"), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			if scenario == "checksum_error" {
				if err := os.Mkdir(filepath.Join(root, "SHA256SUMS"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Unix(0, 0)
			calls := 0
			now := func() time.Time {
				calls++
				raw, err := os.ReadFile(filepath.Join(root, "outcome.json"))
				if err != nil || !strings.Contains(string(raw), `"finalization_status": "pending"`) || !strings.Contains(string(raw), `"complete": false`) {
					t.Fatalf("success before final gate: %s, error = %v", raw, err)
				}
				if scenario == "hash_deadline" || scenario == "publication_deadline" && calls == 2 {
					return started.Add(601 * time.Second)
				}
				return started.Add(time.Second)
			}
			err := expiry65Finalize(root, started, now, 45, 0, scenario == "prior_failure")
			wantError := scenario != "success" && scenario != "prior_failure"
			if (err != nil) != wantError {
				t.Fatalf("error = %v, want error %v", err, wantError)
			}
			raw, err := os.ReadFile(filepath.Join(root, "outcome.json"))
			if err != nil {
				t.Fatal(err)
			}
			var outcome struct {
				Complete bool
				Failed   bool
				Status   string `json:"finalization_status"`
			}
			if err := json.Unmarshal(raw, &outcome); err != nil {
				t.Fatal(err)
			}
			wantStatus := "complete"
			if wantError {
				wantStatus = "failed"
			}
			if outcome.Complete != (scenario == "success") || outcome.Failed != (scenario != "success") || outcome.Status != wantStatus {
				t.Fatalf("unsafe outcome: %s", raw)
			}
			if scenario != "checksum_error" {
				hashes, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
				if err != nil || !strings.Contains(string(hashes), "evidence.log") || strings.Contains(string(hashes), "outcome.json") {
					t.Fatalf("checksum inventory = %q, error = %v", hashes, err)
				}
			}
		})
	}
}

func TestExpiry65CheckpointMetadata(t *testing.T) {
	for _, required := range []string{"Rhiza archive checkpoints excluded", "SQLite PASSIVE checkpoints remain uncontrolled", "1s worker"} {
		if !strings.Contains(expiry65CheckpointHistory, required) {
			t.Fatalf("missing %q: %s", required, expiry65CheckpointHistory)
		}
	}
	if strings.Contains(expiry65CheckpointHistory, "no periodic checkpoint") {
		t.Fatal("unqualified checkpoint exclusion")
	}
}
