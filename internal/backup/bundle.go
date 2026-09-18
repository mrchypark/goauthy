// Package backup writes and reads bounded encrypted object bundles.
//
// Recovery and catalog operations use public Rhiza APIs and native object-store primitives.
package backup

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

// Limits bounds both an archive's logical contents and its decrypted stream.
// All fields must be positive.
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// Entry is one object to include in a bundle. Reader must contain exactly Size
// bytes.
type Entry struct {
	Name   string
	Size   int64
	Reader io.Reader
}

// Inventory records a restored object without exposing its plaintext.
type Inventory struct {
	Name string
	Size int64
}

// Extracted is a private, caller-owned staging directory and its inventory.
// The directory is created beneath the parent passed to Extract.
type Extracted struct {
	Dir       string
	Inventory []Inventory
}

func (l Limits) valid() bool {
	return l.MaxFiles > 0 && l.MaxFileBytes > 0 && l.MaxTotalBytes > 0
}

func (l Limits) check(count int, size, total int64) error {
	if !l.valid() {
		return errors.New("backup limits must be positive")
	}
	if count > l.MaxFiles || size < 0 || size > l.MaxFileBytes || total < 0 || total > l.MaxTotalBytes {
		return errors.New("backup limits exceeded")
	}
	return nil
}

// streamLimit includes USTAR's 512-byte record per file, at most 511 bytes of
// padding per file, and the two terminating records. Write only emits USTAR,
// so no unbounded PAX metadata is accepted.
func (l Limits) streamLimit() (int64, error) {
	if !l.valid() {
		return 0, errors.New("backup limits must be positive")
	}
	const end = int64(1024)
	const perFile = int64(1023)
	const maxInt64 = int64(^uint64(0) >> 1)
	// Extract reserves one additional byte so it can distinguish a stream at
	// the limit from one that exceeds it.
	if l.MaxTotalBytes > maxInt64-1-end || int64(l.MaxFiles) > (maxInt64-1-end-l.MaxTotalBytes)/perFile {
		return 0, errors.New("backup limits exceeded")
	}
	return l.MaxTotalBytes + int64(l.MaxFiles)*perFile + end, nil
}

func validName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Write streams entries through a USTAR archive encrypted with age. It never
// closes dst. On an input error it deliberately does not finalize the tar or
// age stream; callers must discard the partial output.
func Write(dst io.Writer, recipients []age.Recipient, entries []Entry, limits Limits) error {
	if dst == nil || len(recipients) == 0 {
		return errors.New("backup recipients are required")
	}
	if !limits.valid() {
		return errors.New("backup limits must be positive")
	}
	if _, err := limits.streamLimit(); err != nil {
		return err
	}

	enc, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(enc)
	seen := make(map[string]struct{}, len(entries))
	var total int64
	for i, entry := range entries {
		if !validName(entry.Name) || entry.Reader == nil {
			return errors.New("invalid backup entry")
		}
		if _, ok := seen[entry.Name]; ok {
			return errors.New("duplicate backup entry")
		}
		if entry.Size > limits.MaxTotalBytes-total || limits.check(i+1, entry.Size, total+entry.Size) != nil {
			return errors.New("backup limits exceeded")
		}
		if err := tw.WriteHeader(&tar.Header{
			Format:   tar.FormatUSTAR,
			Name:     entry.Name,
			Mode:     0600,
			Size:     entry.Size,
			Typeflag: tar.TypeReg,
		}); err != nil {
			return fmt.Errorf("backup entry %q: %w", entry.Name, err)
		}
		if _, err := io.CopyN(tw, entry.Reader, entry.Size); err != nil {
			return fmt.Errorf("backup entry %q: %w", entry.Name, err)
		}
		var extra [1]byte
		n, readErr := io.ReadFull(entry.Reader, extra[:])
		if n != 0 {
			return errors.New("backup entry exceeds declared size")
		}
		if readErr != io.EOF {
			return fmt.Errorf("backup entry %q: %w", entry.Name, readErr)
		}
		seen[entry.Name] = struct{}{}
		total += entry.Size
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return enc.Close()
}

// Extract decrypts src into a new private directory beneath parent. It returns
// the directory and inventory only after the entire age stream is authenticated.
// On failure it removes only the directory it created.
func Extract(src io.Reader, identities []age.Identity, parent string, limits Limits) (_ Extracted, err error) {
	if src == nil || len(identities) == 0 {
		return Extracted{}, errors.New("backup identities are required")
	}
	maxStream, err := limits.streamLimit()
	if err != nil {
		return Extracted{}, err
	}
	stage, err := os.MkdirTemp(parent, ".goauthy-backup-")
	if err != nil {
		return Extracted{}, err
	}
	defer func() {
		if err != nil {
			if cleanupErr := os.RemoveAll(stage); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	if err := os.Chmod(stage, 0700); err != nil {
		return Extracted{}, err
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		return Extracted{}, err
	}
	defer root.Close()

	dec, err := age.Decrypt(src, identities...)
	if err != nil {
		return Extracted{}, err
	}
	limited := &io.LimitedReader{R: dec, N: maxStream + 1}
	tr := tar.NewReader(limited)
	seen := make(map[string]struct{})
	var inventory []Inventory
	var total int64
	for {
		h, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return Extracted{}, nextErr
		}
		if h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Linkname != "" || !validName(h.Name) {
			return Extracted{}, errors.New("invalid backup tar entry")
		}
		if _, ok := seen[h.Name]; ok {
			return Extracted{}, errors.New("duplicate backup tar entry")
		}
		if h.Size > limits.MaxTotalBytes-total || limits.check(len(inventory)+1, h.Size, total+h.Size) != nil {
			return Extracted{}, errors.New("backup limits exceeded")
		}
		if err := root.MkdirAll(path.Dir(h.Name), 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return Extracted{}, err
		}
		file, openErr := root.OpenFile(h.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return Extracted{}, openErr
		}
		_, copyErr := io.CopyN(file, tr, h.Size)
		closeErr := file.Close()
		if copyErr != nil {
			return Extracted{}, copyErr
		}
		if closeErr != nil {
			return Extracted{}, closeErr
		}
		seen[h.Name] = struct{}{}
		total += h.Size
		inventory = append(inventory, Inventory{Name: h.Name, Size: h.Size})
	}
	// Draining past tar EOF authenticates age's final chunk and detects both
	// encrypted trailing bytes and plaintext after the USTAR terminator.
	n, drainErr := io.Copy(io.Discard, limited)
	if drainErr != nil {
		return Extracted{}, drainErr
	}
	if limited.N == 0 || n != 0 {
		return Extracted{}, errors.New("invalid backup trailing data")
	}
	return Extracted{Dir: stage, Inventory: inventory}, nil
}
