package main

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestFaviconFromEnv(t *testing.T) {
	t.Parallel()
	if asset, err := faviconFromEnv(func(string) string { return "" }); err != nil || asset != nil {
		t.Fatalf("empty path asset=%v err=%v", asset, err)
	}
	path := filepath.Join(t.TempDir(), "favicon.png")
	if err := os.WriteFile(path, faviconTestPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	asset, err := faviconFromEnv(func(string) string { return path })
	if err != nil || asset == nil {
		t.Fatalf("valid path asset=%v err=%v", asset, err)
	}
	if _, err := faviconFromEnv(func(string) string { return filepath.Join(t.TempDir(), "missing") }); err == nil {
		t.Fatal("missing favicon accepted")
	}
}

func faviconTestPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
