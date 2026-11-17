package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRequiresOwnerOnlyRegularNonSymlink(t *testing.T) {
	dir := t.TempDir()
	secure := filepath.Join(dir, "secure")
	if err := os.WriteFile(secure, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(secure, 64); err != nil || string(got) != "secret" {
		t.Fatalf("secure read=%q err=%v", got, err)
	}
	for _, mode := range []os.FileMode{0o440, 0o640} {
		path := filepath.Join(dir, mode.String())
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got, err := Read(path, 64); err != nil || string(got) != "secret" {
			t.Fatalf("mode=%#o read=%q err=%v", mode, got, err)
		}
	}
	for _, mode := range []os.FileMode{0o604, 0o660, 0o644, 0o000} {
		path := filepath.Join(dir, mode.String())
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path, 64); !errors.Is(err, ErrInsecure) {
			t.Fatalf("mode=%#o err=%v want ErrInsecure", mode, err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secure, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, 64); !errors.Is(err, ErrInsecure) {
		t.Fatalf("symlink err=%v want ErrInsecure", err)
	}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(oversized, 3); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := Read(dir, 64); !errors.Is(err, ErrInsecure) {
		t.Fatalf("directory err=%v want ErrInsecure", err)
	}
}
