package backup

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

var testLimits = Limits{MaxFiles: 8, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20}

func TestWriteExtractRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{Name: "archive/head", Size: 128 << 10, Reader: &chunkReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), 128<<10)), n: 2}},
		{Name: "blocks/one", Size: 4, Reader: &chunkReader{r: bytes.NewReader([]byte("beta")), n: 1}},
	}
	wantContents := map[string]string{"archive/head": string(bytes.Repeat([]byte("a"), 128<<10)), "blocks/one": "beta"}
	bundle := writeBundle(t, identity.Recipient(), entries, testLimits)
	got, err := Extract(bytes.NewReader(bundle), []age.Identity{identity}, t.TempDir(), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(got.Dir)
	info, err := os.Stat(got.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("staging permissions = %o", info.Mode().Perm())
	}
	if len(got.Inventory) != len(entries) {
		t.Fatalf("inventory length = %d, want %d", len(got.Inventory), len(entries))
	}
	for _, item := range got.Inventory {
		data, err := os.ReadFile(filepath.Join(got.Dir, filepath.FromSlash(item.Name)))
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != item.Size {
			t.Fatalf("%s size = %d, want %d", item.Name, len(data), item.Size)
		}
		if string(data) != wantContents[item.Name] {
			t.Fatalf("%s contents = %q, want %q", item.Name, data, wantContents[item.Name])
		}
		fileInfo, err := os.Stat(filepath.Join(got.Dir, filepath.FromSlash(item.Name)))
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm()&0077 != 0 {
			t.Fatalf("%s permissions = %o", item.Name, fileInfo.Mode().Perm())
		}
	}
}

func TestWriteExtractHybridIdentity(t *testing.T) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeBundle(t, identity.Recipient(), []Entry{{Name: "object", Size: 2, Reader: bytes.NewReader([]byte("ok"))}}, testLimits)
	got, err := Extract(bytes.NewReader(bundle), []age.Identity{identity}, t.TempDir(), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(got.Dir)
	data, err := os.ReadFile(filepath.Join(got.Dir, "object"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("contents = %q, want ok", data)
	}
}

func TestExtractRejectsUnauthenticatedBundlesAndCleansStage(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeBundle(t, identity.Recipient(), []Entry{{Name: "object", Size: 4, Reader: bytes.NewReader([]byte("data"))}}, testLimits)
	cases := map[string][]byte{
		"wrong identity": bundle,
		"tamper":         append([]byte(nil), bundle...),
		"truncate":       bundle[:len(bundle)-1],
		"trailing":       append(append([]byte(nil), bundle...), 0),
	}
	// Altering the final authenticated byte is distinct from truncation.
	cases["tamper"][len(cases["tamper"])-1] ^= 1
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			identities := []age.Identity{identity}
			if name == "wrong identity" {
				identities = []age.Identity{other}
			}
			if _, err := Extract(bytes.NewReader(data), identities, parent, testLimits); err == nil {
				t.Fatal("Extract succeeded")
			}
			contents, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if len(contents) != 0 {
				t.Fatal("failed extraction left plaintext staging")
			}
		})
	}
}

func TestWriteRejectsUnsafeDuplicateAndOverlongEntries(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, entries := range map[string][]Entry{
		"unsafe":    {{Name: "../object", Size: 1, Reader: bytes.NewReader([]byte("x"))}},
		"nul":       {{Name: "object\x00", Size: 1, Reader: bytes.NewReader([]byte("x"))}},
		"duplicate": {{Name: "object", Size: 1, Reader: bytes.NewReader([]byte("x"))}, {Name: "object", Size: 1, Reader: bytes.NewReader([]byte("x"))}},
		"overlong":  {{Name: "object", Size: 1, Reader: bytes.NewReader([]byte("xx"))}},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Write(&out, []age.Recipient{identity.Recipient()}, entries, testLimits); err == nil {
				t.Fatal("Write succeeded")
			}
		})
	}
}

func TestExtractRejectsUnsafeDuplicateAndLimitedArchive(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, headers := range map[string][]*tar.Header{
		"unsafe": {{Format: tar.FormatUSTAR, Name: "../object", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
		"duplicate": {
			{Format: tar.FormatUSTAR, Name: "object", Mode: 0600, Size: 1, Typeflag: tar.TypeReg},
			{Format: tar.FormatUSTAR, Name: "object", Mode: 0600, Size: 1, Typeflag: tar.TypeReg},
		},
		"symlink": {{Format: tar.FormatUSTAR, Name: "object", Mode: 0600, Typeflag: tar.TypeSymlink, Linkname: "elsewhere"}},
	} {
		t.Run(name, func(t *testing.T) {
			bundle := malformedBundle(t, identity.Recipient(), headers)
			assertExtractFailsClean(t, bundle, identity, testLimits)
		})
	}
	bundle := writeBundle(t, identity.Recipient(), []Entry{{Name: "object", Size: 2, Reader: bytes.NewReader([]byte("xx"))}}, testLimits)
	assertExtractFailsClean(t, bundle, identity, Limits{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: 1})
}

func TestExtractRejectsDecryptedStreamOverLimit(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// The valid USTAR archive is followed by authenticated plaintext. This
	// exercises the bounded drain after tar EOF, rather than a file-count check.
	bundle := bundleWithPlaintextTrailer(t, identity.Recipient())
	assertExtractFailsClean(t, bundle, identity, Limits{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: 1})
}

func TestExtractPreservesParentContentsOnFailure(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	sentinel := filepath.Join(parent, "keep")
	if err := os.WriteFile(sentinel, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader([]byte("not an age file")), []age.Identity{identity}, parent, testLimits); err == nil {
		t.Fatal("Extract succeeded")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sentinel" {
		t.Fatalf("sentinel = %q", data)
	}
}

func TestWriteErrorDoesNotProduceAnAuthenticatedBundle(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writer := &failWriter{remaining: 100000} // Fail after at least one complete payload chunk.
	err = Write(writer, []age.Recipient{identity.Recipient()}, []Entry{{Name: "object", Size: 128 << 10, Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 128<<10))}}, testLimits)
	if err == nil {
		t.Fatal("Write succeeded")
	}
	if _, err := Extract(bytes.NewReader(writer.bytes.Bytes()), []age.Identity{identity}, t.TempDir(), testLimits); err == nil {
		t.Fatal("partial output authenticated")
	}
}

func TestWriteInputFailureDoesNotFinalizePriorEntries(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []io.Reader{bytes.NewReader(nil), failingReader{}} {
		var out bytes.Buffer
		err := Write(&out, []age.Recipient{identity.Recipient()}, []Entry{
			{Name: "complete", Size: 128 << 10, Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 128<<10))},
			{Name: "incomplete", Size: 1, Reader: reader},
		}, testLimits)
		if err == nil {
			t.Fatal("Write accepted failed input")
		}
		assertExtractFailsClean(t, out.Bytes(), identity, testLimits)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("forced input failure") }

func TestWriteRejectsUnrepresentableStreamLimit(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	limits := Limits{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: int64(^uint64(0) >> 1)}
	if err := Write(&out, []age.Recipient{identity.Recipient()}, nil, limits); err == nil {
		t.Fatal("Write accepted an unrepresentable stream limit")
	}
}

func writeBundle(t *testing.T, recipient age.Recipient, entries []Entry, limits Limits) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Write(&out, []age.Recipient{recipient}, entries, limits); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func malformedBundle(t *testing.T, recipient age.Recipient, headers []*tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, recipient)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	for _, header := range headers {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(tw, bytes.NewReader(make([]byte, header.Size)), header.Size); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func bundleWithPlaintextTrailer(t *testing.T, recipient age.Recipient) []byte {
	t.Helper()
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, recipient)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	if err := tw.WriteHeader(&tar.Header{Format: tar.FormatUSTAR, Name: "object", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func assertExtractFailsClean(t *testing.T, bundle []byte, identity age.Identity, limits Limits) {
	t.Helper()
	parent := t.TempDir()
	if _, err := Extract(bytes.NewReader(bundle), []age.Identity{identity}, parent, limits); err == nil {
		t.Fatal("Extract succeeded")
	}
	contents, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatal("failed extraction left plaintext staging")
	}
}

type chunkReader struct {
	r io.Reader
	n int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.r.Read(p)
}

type failWriter struct {
	bytes     bytes.Buffer
	remaining int
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, errors.New("forced output failure")
	}
	n := len(p)
	if n > w.remaining {
		n = w.remaining
	}
	_, _ = w.bytes.Write(p[:n])
	w.remaining -= n
	if n != len(p) {
		return n, errors.New("forced output failure")
	}
	return n, nil
}

func TestNamesRejectInvalidUTF8BeforeJSONEncoding(t *testing.T) {
	invalid := "source/" + string([]byte{0xff}) + "/cluster-a"
	if validName(invalid) {
		t.Fatal("invalid UTF-8 name would change identity during JSON encoding")
	}
	manifest := testManifest(completeObjects(map[string][]byte{"archive/head.bin": []byte("head")}))
	manifest.SourcePrefix = invalid
	if _, err := MarshalManifest(manifest); err == nil {
		t.Fatal("manifest accepted a lossy source prefix")
	}
}
