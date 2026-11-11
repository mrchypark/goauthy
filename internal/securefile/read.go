// Package securefile reads local credential-bearing files with one fail-closed
// permission policy.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrInsecure is returned before reading a path that is not a regular,
// owner-only file or that changes between inspection and open.
var ErrInsecure = errors.New("sensitive file must be a regular, owner-only file and not a symlink")

// Read returns at most maxBytes from path. The pathname and opened descriptor
// must identify the same regular file; this rejects symlinks and replacement
// races without adding a platform-specific open flag.
func Read(path string, maxBytes int64) ([]byte, error) {
	if path == "" || maxBytes < 1 {
		return nil, ErrInsecure
	}
	inspected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !secureInfo(inspected) || inspected.Size() > maxBytes {
		return nil, ErrInsecure
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !secureInfo(opened) || !os.SameFile(inspected, opened) || opened.Size() > maxBytes {
		return nil, ErrInsecure
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("sensitive file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func secureInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}
