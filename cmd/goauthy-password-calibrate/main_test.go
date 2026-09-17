package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestRunUsesInjectedMeasurementsAndReturnsDescendingMedians(t *testing.T) {
	var calls []uint32
	measure := func(iterations, memoryKiB uint32, parallelism uint8) (time.Duration, error) {
		if memoryKiB != 32768 || parallelism != 2 {
			t.Fatalf("parameters = %d KiB, %d", memoryKiB, parallelism)
		}
		calls = append(calls, iterations)
		return time.Duration(iterations*100+uint32(len(calls)%3)*100) * time.Millisecond, nil
	}
	var out bytes.Buffer
	if err := run([]string{"-target=500ms", "-memory-kib=32768", "-parallelism=2", "-samples=3"}, &out, measure); err != nil {
		t.Fatal(err)
	}
	var got []recommendation
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("recommendations = %d, want 5", len(got))
	}
	for i, value := range got {
		wantIterations := uint32(5 - i)
		if value.Iterations != wantIterations || value.MemoryKiB != 32768 || value.Parallelism != 2 {
			t.Fatalf("recommendation[%d] = %#v", i, value)
		}
		if value.MedianMilliseconds != int64(wantIterations*100+100) {
			t.Fatalf("median[%d] = %d", i, value.MedianMilliseconds)
		}
		if value.WithinTarget != (value.MedianMilliseconds <= 500) {
			t.Fatalf("within target[%d] = %t", i, value.WithinTarget)
		}
	}
	if want := []uint32{5, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 1, 1, 1}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestRunRejectsInvalidFlagsWithoutMeasuring(t *testing.T) {
	measure := func(uint32, uint32, uint8) (time.Duration, error) {
		t.Fatal("measurement must not run")
		return 0, nil
	}
	for _, args := range [][]string{
		{"-target=499ms"}, {"-target=10001ms"},
		{"-memory-kib=32767"}, {"-memory-kib=131073"},
		{"-parallelism=1"}, {"-parallelism=9"},
		{"-samples=2"}, {"unexpected"},
	} {
		var out bytes.Buffer
		if err := run(args, &out, measure); err == nil || out.Len() != 0 {
			t.Fatalf("run(%v) err=%v output=%q", args, err, out.String())
		}
	}
}

func TestCalibrateStopsOnMeasurementError(t *testing.T) {
	_, err := calibrate(32768, 2, 1, minTarget, func(uint32, uint32, uint8) (time.Duration, error) {
		return 0, errors.New("injected")
	})
	if err == nil || err.Error() != "measure iteration 5: injected" {
		t.Fatalf("error = %v", err)
	}
}

func TestRunDoesNotPersistSettings(t *testing.T) {
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	var out bytes.Buffer
	err = run([]string{"-parallelism=2", "-samples=1"}, &out, func(uint32, uint32, uint8) (time.Duration, error) {
		return minTarget, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected persisted files: %v", entries)
	}
}
