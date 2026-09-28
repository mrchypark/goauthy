//go:build integration

package oauth

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Untimed reduction of retained raw evidence. Called by the campaign parent,
// after all children have exited, within its aggregate evidence budget.
func expiry65Summarize(root string) error {
	files, err := filepath.Glob(filepath.Join(root, "*.log"))
	if err != nil {
		return err
	}
	out, err := os.Create(filepath.Join(root, "samples.csv"))
	if err != nil {
		return err
	}
	w := csv.NewWriter(out)
	if err = w.Write([]string{"case", "phase", "wall_ns", "user_us", "system_us", "allocated_bytes", "mallocs", "qlog_length_delta", "sqlite_length_delta", "sqlite_wal_length_delta", "object_inventory_length_delta", "upload_calls_delta", "upload_read_bytes_delta", "object_failures_delta"}); err != nil {
		return err
	}
	type observation struct {
		Files       map[string]int64 `json:"files"`
		ObjectStats struct {
			Uploads       uint64 `json:"uploads"`
			BytesUploaded uint64 `json:"bytes_uploaded"`
			Failures      uint64 `json:"failures"`
		} `json:"object_stats"`
	}
	groups := map[string][]expiry65Sample{}
	var brackets []expiry65Sample
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		var samples []expiry65Sample
		observations := map[string]observation{}
		for scanner.Scan() {
			_, text, ok := strings.Cut(scanner.Text(), "EXPIRY65 ")
			if !ok {
				continue
			}
			var record struct {
				Kind  string
				Value json.RawMessage
			}
			if err = json.Unmarshal([]byte(text), &record); err != nil {
				f.Close()
				return err
			}
			switch record.Kind {
			case "sample", "empty_bracket":
				var sample expiry65Sample
				if err = json.Unmarshal(record.Value, &sample); err != nil {
					f.Close()
					return err
				}
				if record.Kind == "sample" {
					samples = append(samples, sample)
				} else {
					brackets = append(brackets, sample)
				}
			case "before_operation_0", "before_operation_1", "after_operation_0", "after_operation_1":
				var o observation
				if err = json.Unmarshal(record.Value, &o); err != nil {
					f.Close()
					return err
				}
				observations[record.Kind] = o
			}
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return closeErr
		}
		name := strings.TrimSuffix(filepath.Base(path), ".log")
		_, group, _ := strings.Cut(name, "-")
		for i, s := range samples {
			before, bok := observations[fmt.Sprintf("before_operation_%d", i)]
			after, aok := observations[fmt.Sprintf("after_operation_%d", i)]
			if !bok || !aok {
				continue
			} // An incomplete failed case remains in its raw log.
			sum := func(files map[string]int64, prefix string) int64 {
				var n int64
				for path, v := range files {
					if strings.HasPrefix(path, prefix) {
						n += v
					}
				}
				return n
			}
			values := []int64{s.WallNS, s.UserUS, s.SystemUS, int64(s.TotalAlloc), int64(s.Mallocs), sum(after.Files, "data/qlog/") - sum(before.Files, "data/qlog/"), after.Files["data/sqlite.db"] - before.Files["data/sqlite.db"], after.Files["data/sqlite.db-wal"] - before.Files["data/sqlite.db-wal"], sum(after.Files, "objects/") - sum(before.Files, "objects/"), int64(after.ObjectStats.Uploads) - int64(before.ObjectStats.Uploads), int64(after.ObjectStats.BytesUploaded) - int64(before.ObjectStats.BytesUploaded), int64(after.ObjectStats.Failures) - int64(before.ObjectStats.Failures)}
			row := []string{name, s.Phase}
			for _, v := range values {
				row = append(row, strconv.FormatInt(v, 10))
			}
			if err = w.Write(row); err != nil {
				return err
			}
			groups[group+"/"+s.Phase] = append(groups[group+"/"+s.Phase], s)
		}
	}
	w.Flush()
	writeErr := w.Error()
	closeErr := out.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	var report strings.Builder
	report.WriteString("# Derived primary observations\n\nMedian [min, max], all in-process wall/CPU milliseconds; Go allocation KiB.\nOnly rows with three observations have three-repetition summaries. No tail percentiles.\n\n| Operation/state | Phase | n | Wall ms | Process CPU ms | Allocated KiB |\n| --- | --- | ---: | --- | --- | --- |\n")
	format := func(v []float64) string {
		slices.Sort(v)
		if len(v) == 0 {
			return "unavailable"
		}
		return fmt.Sprintf("%.3f [%.3f, %.3f]", v[len(v)/2], v[0], v[len(v)-1])
	}
	for _, op := range expiry65Operations {
		for _, state := range expiry65States {
			for _, phase := range []string{"first", "post_validation_followup"} {
				key := op + "-" + state
				group := groups[key+"/"+phase]
				var wall, cpu, alloc []float64
				for _, s := range group {
					wall = append(wall, float64(s.WallNS)/1e6)
					cpu = append(cpu, float64(s.UserUS+s.SystemUS)/1e3)
					alloc = append(alloc, float64(s.TotalAlloc)/1024)
				}
				fmt.Fprintf(&report, "| %s | %s | %d | %s | %s | %s |\n", key, phase, len(group), format(wall), format(cpu), format(alloc))
			}
		}
	}
	var empty []float64
	for _, s := range brackets {
		empty = append(empty, float64(s.WallNS)/1e6)
	}
	fmt.Fprintf(&report, "\nEmpty bracket wall ms, n=%d: %s. No subtraction.\n", len(empty), format(empty))
	return os.WriteFile(filepath.Join(root, "summary.md"), []byte(report.String()), 0600)
}
