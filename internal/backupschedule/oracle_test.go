//go:build cronoracle

package backupschedule

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test compares actual accepted field sets with pinned Rust cron,
// independently of the Go implementation. Rust is only a development oracle.
func TestRustParserOracle(t *testing.T) {
	corpus := []string{"", "******", "*******", "********", "@daily", "@yearly", "@monthly", "@weekly", "@hourly", "@reboot", "@Daily", "0 30 2 * * *", "0 30 2 * * * * extra", "0\u00a030 2 * * *", "0 0 0 1 * 1 2027", "0\n30\t2 * * *", "\u00a0@daily", "@daily\u00a0", "0\v30 2 * * *", "0\xff30 2 * * *"}
	choices := []string{"*", "?", "0", "1", "7", "31", "59", "60", "1970", "2100", "2101", "*/2", "* /2", "*/ 2", "1 / 2", "1-3/2", "1 - 3 / 2", "1, 3", "1 ,3", "1,,3", "1,", "*/0", "*/60", "*/2101", "JAN", "January", "jan-mar", "mon", "tues", "thu", "thurs", "Monday-Friday", "mon-fri/2", "mon/2", "1-mon", "mon-1", "4294967296", "-1", "+1"}
	for field := range 7 {
		for _, choice := range choices {
			fields := []string{"*", "*", "*", "*", "*", "*", "*"}
			fields[field] = choice
			corpus = append(corpus, strings.Join(fields, " "))
		}
	}
	manifest, err := filepath.Abs("../../test/compat/rauthy-cron/Cargo.toml")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cargo", "run", "--quiet", "--locked", "--manifest-path", manifest)
	cmd.Env = os.Environ()
	if os.Getenv("CARGO_TARGET_DIR") == "" {
		cmd.Env = append(cmd.Env, "CARGO_TARGET_DIR="+t.TempDir())
	}
	encoded := make([]string, len(corpus))
	for i, expression := range corpus {
		encoded[i] = hex.EncodeToString([]byte(expression))
	}
	cmd.Stdin = strings.NewReader(strings.Join(encoded, "\n") + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v: %s", err, stderr.String())
	}
	expected := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(expected) != len(corpus) {
		t.Fatalf("oracle returned %d lines for %d expressions", len(expected), len(corpus))
	}
	for i, expression := range corpus {
		t.Run(fmt.Sprintf("%d:%s", i, expression), func(t *testing.T) {
			got := "err"
			s, err := Parse(expression)
			if err == nil {
				fields := make([]string, 7)
				for j, values := range s.fields {
					parts := make([]string, len(values))
					for k, v := range values {
						parts[k] = strconv.Itoa(v)
					}
					fields[j] = strings.Join(parts, ",")
				}
				got = strings.Join(fields, "|")
			}
			if got != expected[i] {
				t.Fatalf("Go=%s\nRust=%s", got, expected[i])
			}
		})
	}
}
