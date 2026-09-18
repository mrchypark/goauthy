// Package branding contains browser-facing branding assets that are independent
// from the login theme or a registered client's logo.
package branding

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
)

const maxFaviconBytes = 256 << 10
const maxFaviconDimension = 1024

var (
	ErrUnsupportedFormat = errors.New("unsupported favicon format")
	ErrInvalidFormat     = errors.New("invalid favicon format")
)

// Asset is a validated, immutable favicon. LoadFile is the normal constructor.
// The byte slice is copied before serving so callers cannot alter an installed
// asset through a buffer they supplied.
type Asset struct {
	bytes       []byte
	contentType string
	etag        string
}

// LoadFile loads an optional favicon from path. An empty path disables the
// favicon. A configured path must be a regular file and must fit the bound.
func LoadFile(path string) (*Asset, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open favicon: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat favicon: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("favicon must be a regular file")
	}
	if info.Size() > maxFaviconBytes {
		return nil, fmt.Errorf("favicon exceeds %d bytes", maxFaviconBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFaviconBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read favicon: %w", err)
	}
	if len(b) > maxFaviconBytes {
		return nil, fmt.Errorf("favicon exceeds %d bytes", maxFaviconBytes)
	}
	return NewAsset(b)
}

// NewAsset validates and copies favicon bytes. PNG and ICO are supported;
// SVG is deliberately rejected because serving user-controlled SVG as an
// image creates a CSP/XSS policy boundary that this package does not own.
func NewAsset(input []byte) (*Asset, error) {
	if len(input) == 0 || len(input) > maxFaviconBytes {
		return nil, ErrInvalidFormat
	}
	contentType, err := sniff(input)
	if err != nil {
		return nil, err
	}
	b := append([]byte(nil), input...)
	digest := sha256.Sum256(b)
	return &Asset{bytes: b, contentType: contentType, etag: `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`}, nil
}

func sniff(b []byte) (string, error) {
	if len(b) >= 8 && bytes.Equal(b[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		cfg, err := png.DecodeConfig(bytes.NewReader(b))
		if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxFaviconDimension || cfg.Height > maxFaviconDimension {
			return "", ErrInvalidFormat
		}
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			return "", ErrInvalidFormat
		}
		bounds := img.Bounds()
		if bounds.Dx() != cfg.Width || bounds.Dy() != cfg.Height {
			return "", ErrInvalidFormat
		}
		return "image/png", nil
	}
	if len(b) >= 6 && binary.LittleEndian.Uint16(b[0:2]) == 0 && binary.LittleEndian.Uint16(b[2:4]) == 1 {
		if err := validICO(b); err != nil {
			return "", err
		}
		return "image/x-icon", nil
	}
	return "", ErrUnsupportedFormat
}

func validICO(b []byte) error {
	count := int(binary.LittleEndian.Uint16(b[4:6]))
	if count < 1 || count > 64 || len(b) < 6+16*count {
		return ErrInvalidFormat
	}
	for i := 0; i < count; i++ {
		e := b[6+i*16 : 6+(i+1)*16]
		width, height := int(e[0]), int(e[1])
		if width == 0 {
			width = 256
		}
		if height == 0 {
			height = 256
		}
		if width > maxFaviconDimension || height > maxFaviconDimension {
			return ErrInvalidFormat
		}
		size, offset := uint64(binary.LittleEndian.Uint32(e[8:12])), uint64(binary.LittleEndian.Uint32(e[12:16]))
		if size == 0 || offset < uint64(6+16*count) || offset > uint64(len(b)) || size > uint64(len(b))-offset {
			return ErrInvalidFormat
		}
		payload := b[int(offset):int(offset+size)]
		if len(payload) >= 8 && bytes.Equal(payload[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
			cfg, err := png.DecodeConfig(bytes.NewReader(payload))
			if err != nil || cfg.Width != width || cfg.Height != height || cfg.Width > maxFaviconDimension || cfg.Height > maxFaviconDimension {
				return ErrInvalidFormat
			}
			img, err := png.Decode(bytes.NewReader(payload))
			if err != nil || img.Bounds().Dx() != cfg.Width || img.Bounds().Dy() != cfg.Height {
				return ErrInvalidFormat
			}
			continue
		}
		if err := validDIB(payload, width, height); err != nil {
			return err
		}
	}
	return nil
}

func validDIB(b []byte, width, height int) error {
	if len(b) < 40 {
		return ErrInvalidFormat
	}
	header := int64(binary.LittleEndian.Uint32(b[:4]))
	if header < 40 || header > int64(len(b)) {
		return ErrInvalidFormat
	}
	w := int64(int32(binary.LittleEndian.Uint32(b[4:8])))
	h := int64(int32(binary.LittleEndian.Uint32(b[8:12])))
	if w != int64(width) || h != int64(height*2) && h != -int64(height*2) || binary.LittleEndian.Uint16(b[12:14]) != 1 {
		return ErrInvalidFormat
	}
	bpp := binary.LittleEndian.Uint16(b[14:16])
	if bpp != 1 && bpp != 4 && bpp != 8 && bpp != 16 && bpp != 24 && bpp != 32 {
		return ErrInvalidFormat
	}
	compression := binary.LittleEndian.Uint32(b[16:20])
	if compression != 0 && compression != 3 {
		return ErrInvalidFormat
	}
	extra := uint64(0)
	if bpp <= 8 {
		colors := binary.LittleEndian.Uint32(b[32:36])
		if colors == 0 {
			colors = 1 << bpp
		}
		if colors > 1<<bpp {
			return ErrInvalidFormat
		}
		extra = uint64(colors) * 4
	} else if compression == 3 {
		extra = 12
	}
	row := (uint64(width)*uint64(bpp) + 31) / 32 * 4
	mask := (uint64(width) + 31) / 32 * 4
	need := uint64(header) + extra + row*uint64(height) + mask*uint64(height)
	if need > uint64(len(b)) {
		return ErrInvalidFormat
	}
	return nil
}

// Handler serves the optional favicon at the route where it is mounted.
func Handler(asset *Asset) http.Handler { return NewHandler(asset) }

// NewHandler returns a small immutable GET/HEAD handler. A nil asset returns
// 404, allowing callers to keep the file optional without route branching.
func NewHandler(asset *Asset) http.Handler {
	if asset == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	}
	b := append([]byte(nil), asset.bytes...)
	contentType, etag := asset.contentType, asset.etag
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
	})
}

func matchesETag(header, etag string) bool {
	for _, part := range bytes.Split([]byte(header), []byte{','}) {
		part = bytes.TrimSpace(part)
		if bytes.Equal(part, []byte("*")) {
			return true
		}
		part = bytes.TrimPrefix(part, []byte("W/"))
		if bytes.Equal(part, []byte(etag)) {
			return true
		}
	}
	return false
}
