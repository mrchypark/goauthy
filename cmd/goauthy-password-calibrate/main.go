// goauthy-password-calibrate measures bounded Argon2id candidates without changing configuration.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	minTarget      = 500 * time.Millisecond
	maxTarget      = 10 * time.Second
	minMemoryKiB   = 32 * 1024
	maxMemoryKiB   = 128 * 1024
	minParallelism = 2
	maxParallelism = 8
)

type recommendation struct {
	Iterations         uint32 `json:"iterations"`
	MemoryKiB          uint32 `json:"memory_kib"`
	Parallelism        uint8  `json:"parallelism"`
	MedianMilliseconds int64  `json:"median_ms"`
	WithinTarget       bool   `json:"within_target"`
}

type measureFunc func(iterations, memoryKiB uint32, parallelism uint8) (time.Duration, error)

func main() {
	if err := run(os.Args[1:], os.Stdout, measure); err != nil {
		fmt.Fprintln(os.Stderr, "goauthy-password-calibrate:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, measure measureFunc) error {
	fs := flag.NewFlagSet("goauthy-password-calibrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	target := fs.Duration("target", minTarget, "target Argon2id duration (500ms..10s)")
	memoryKiB := fs.Uint("memory-kib", minMemoryKiB, "Argon2id memory in KiB (32768..131072)")
	parallelism := fs.Uint("parallelism", uint(min(runtime.NumCPU(), maxParallelism)), "Argon2id parallelism (2..8)")
	samples := fs.Int("samples", 3, "odd measurement samples (1, 3, or 5)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("arguments are not supported")
	}
	if *target < minTarget || *target > maxTarget {
		return fmt.Errorf("target must be between %s and %s", minTarget, maxTarget)
	}
	if *memoryKiB < minMemoryKiB || *memoryKiB > maxMemoryKiB {
		return fmt.Errorf("memory-kib must be between %d and %d", minMemoryKiB, maxMemoryKiB)
	}
	if *parallelism < minParallelism || *parallelism > maxParallelism {
		return fmt.Errorf("parallelism must be between %d and %d", minParallelism, maxParallelism)
	}
	if *samples != 1 && *samples != 3 && *samples != 5 {
		return errors.New("samples must be 1, 3, or 5")
	}

	result, err := calibrate(uint32(*memoryKiB), uint8(*parallelism), *samples, *target, measure)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func calibrate(memoryKiB uint32, parallelism uint8, samples int, target time.Duration, measure measureFunc) ([]recommendation, error) {
	result := make([]recommendation, 0, 5)
	for iterations := uint32(5); iterations >= 1; iterations-- {
		values := make([]time.Duration, samples)
		for i := range values {
			value, err := measure(iterations, memoryKiB, parallelism)
			if err != nil {
				return nil, fmt.Errorf("measure iteration %d: %w", iterations, err)
			}
			values[i] = value
		}
		slices.Sort(values)
		median := values[len(values)/2]
		result = append(result, recommendation{
			Iterations:         iterations,
			MemoryKiB:          memoryKiB,
			Parallelism:        parallelism,
			MedianMilliseconds: median.Milliseconds(),
			WithinTarget:       median <= target,
		})
	}
	return result, nil
}

func measure(iterations, memoryKiB uint32, parallelism uint8) (time.Duration, error) {
	started := time.Now()
	_ = argon2.IDKey(
		[]byte("goauthy-password-calibration-input-v1"),
		[]byte("goauthy-password-calibration-salt-v1"),
		iterations,
		memoryKiB,
		parallelism,
		32,
	)
	return time.Since(started), nil
}
