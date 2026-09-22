package storage_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// The adapter must reject incomplete objects even when an earlier complete
// read of that name exists. A populated baseline avoids missing-object false positives.
func TestNoPVCExportCaptureRejectsIncompleteObjects(t *testing.T) {
	t.Parallel()
	const name = "capture/archive/head.bin"
	for _, mode := range []string{"complete", "partial", "close failure", "conflicting bytes"} {
		t.Run(mode, func(t *testing.T) {
			bucket := &noPVCExportCaptureBucket{prefix: "capture", objects: map[string][]byte{
				name:                          []byte("original"),
				"capture/archive/blocks/a":    []byte("archive"),
				"capture/checkpoint/roots/a":  []byte("root"),
				"capture/checkpoint/blocks/a": []byte("checkpoint"),
			}, partial: make(map[string]struct{})}
			if err := bucket.complete(); err != nil {
				t.Fatal("invalid test baseline", err)
			}
			payload := "original"
			var closeErr error
			if mode == "conflicting bytes" {
				payload = "changed"
			}
			if mode == "close failure" {
				closeErr = errors.New("close failed")
			}
			reader := &noPVCExportCaptureReader{
				ReadCloser: exportCaptureTestReader{Reader: bytes.NewBufferString(payload), closeErr: closeErr},
				bucket:     bucket, name: name,
			}
			if mode == "partial" {
				if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := io.Copy(io.Discard, reader); err != nil {
					t.Fatal(err)
				}
			}
			if err := reader.Close(); !errors.Is(err, closeErr) {
				t.Fatal("close error was lost")
			}
			err := bucket.complete()
			if mode == "complete" && err != nil {
				t.Fatal(err)
			}
			if mode != "complete" && err == nil {
				t.Fatal("unsafe capture accepted")
			}
		})
	}
}

type exportCaptureTestReader struct {
	io.Reader
	closeErr error
}

func (r exportCaptureTestReader) Close() error { return r.closeErr }
