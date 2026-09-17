package branding

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func testPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testPNGHeader(width, height uint32) []byte {
	b := []byte{137, 80, 78, 71, 13, 10, 26, 10}
	chunk := make([]byte, 25)
	binary.BigEndian.PutUint32(chunk[0:4], 13)
	copy(chunk[4:8], "IHDR")
	binary.BigEndian.PutUint32(chunk[8:12], width)
	binary.BigEndian.PutUint32(chunk[12:16], height)
	chunk[16] = 8
	chunk[17] = 6
	chunk[24] = 0
	binary.BigEndian.PutUint32(chunk[21:25], crc32.ChecksumIEEE(chunk[4:21]))
	b = append(b, chunk...)
	b = append(b, 0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82)
	return b
}

func testICO() []byte {
	// One 1x1 icon directory entry with a valid 32-bit DIB payload.
	b := make([]byte, 6+16+48)
	b[2] = 1
	b[4] = 1
	b[6] = 1
	b[7] = 1
	b[10] = 32
	binary.LittleEndian.PutUint32(b[14:18], 48)
	binary.LittleEndian.PutUint32(b[18:22], 22)
	binary.LittleEndian.PutUint32(b[22:26], 40)
	binary.LittleEndian.PutUint32(b[26:30], 1)
	binary.LittleEndian.PutUint32(b[30:34], 2)
	binary.LittleEndian.PutUint16(b[34:36], 1)
	binary.LittleEndian.PutUint16(b[36:38], 32)
	return b
}

func TestLoadFileAndHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "favicon.png")
	if err := os.WriteFile(path, testPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	asset, err := LoadFile(path)
	if err != nil || asset == nil {
		t.Fatalf("LoadFile() asset=%v err=%v", asset, err)
	}
	h := NewHandler(asset)
	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if first.Code != http.StatusOK || first.Header().Get("Content-Type") != "image/png" || first.Header().Get("Cache-Control") != "public, max-age=300, must-revalidate" || first.Header().Get("ETag") == "" || !bytes.Equal(first.Body.Bytes(), asset.bytes) {
		t.Fatalf("unexpected response: code=%d headers=%v body=%d", first.Code, first.Header(), first.Body.Len())
	}
	notModified := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	req.Header.Set("If-None-Match", first.Header().Get("ETag"))
	h.ServeHTTP(notModified, req)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("ETag response: code=%d body=%d", notModified.Code, notModified.Body.Len())
	}
}

func TestAssetFormatPolicy(t *testing.T) {
	if _, err := NewAsset(testICO()); err != nil {
		t.Fatalf("valid ICO rejected: %v", err)
	}
	if _, err := NewAsset([]byte("<svg xmlns='http://www.w3.org/2000/svg'/>")); err != ErrUnsupportedFormat {
		t.Fatalf("SVG err=%v, want ErrUnsupportedFormat", err)
	}
	if _, err := NewAsset([]byte("not an image")); err != ErrUnsupportedFormat {
		t.Fatalf("unknown err=%v, want ErrUnsupportedFormat", err)
	}
	if asset, err := LoadFile(""); err != nil || asset != nil {
		t.Fatalf("empty path asset=%v err=%v", asset, err)
	}
}

func TestRejectsHugePNGDimensionsBeforeDecode(t *testing.T) {
	if _, err := NewAsset(testPNGHeader(^uint32(0), ^uint32(0))); err != ErrInvalidFormat {
		t.Fatalf("huge PNG dimensions err=%v, want ErrInvalidFormat", err)
	}

	payload := testPNGHeader(^uint32(0), ^uint32(0))
	ico := make([]byte, 6+16+len(payload))
	ico[2] = 1
	ico[4], ico[6], ico[7] = 1, 1, 1
	binary.LittleEndian.PutUint32(ico[14:18], uint32(len(payload)))
	binary.LittleEndian.PutUint32(ico[18:22], 22)
	copy(ico[22:], payload)
	if _, err := NewAsset(ico); err != ErrInvalidFormat {
		t.Fatalf("huge ICO PNG dimensions err=%v, want ErrInvalidFormat", err)
	}
}

func TestRejectsICOUint32PayloadOverflowShape(t *testing.T) {
	ico := testICO()
	binary.LittleEndian.PutUint32(ico[14:18], ^uint32(0))
	if _, err := NewAsset(ico); err != ErrInvalidFormat {
		t.Fatalf("overflow-shaped ICO err=%v, want ErrInvalidFormat", err)
	}
}

func TestLoadFileRejectsNonRegularAndOversize(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(dir, "large")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxFaviconBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("oversized favicon accepted")
	}
}
