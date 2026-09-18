package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	nativewebp "github.com/HugoSmits86/nativewebp"
)

func TestNoPVCThemeRecovery(t *testing.T) {
	const s3OptIn = "GOAUTHY_THEME_RECOVERY_S3"
	root := os.Getenv("GOAUTHY_THEME_RECOVERY_ROOT")
	if root == "" {
		root = t.TempDir()
		useS3 := os.Getenv(s3OptIn) == "1"
		if useS3 {
			for _, name := range []string{"GOAUTHY_RECOVERY_S3_ENDPOINT", "GOAUTHY_RECOVERY_S3_BUCKET", "GOAUTHY_RECOVERY_S3_ACCESS_KEY", "GOAUTHY_RECOVERY_S3_SECRET_KEY"} {
				if os.Getenv(name) == "" {
					t.Fatalf("S3 opt-in requires %s", name)
				}
			}
		}
		run := func(dataDir, phase string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCThemeRecovery$")
			cmd.Env = append(os.Environ(),
				"GOAUTHY_THEME_RECOVERY_ROOT="+root,
				"GOAUTHY_THEME_RECOVERY_DATA_DIR="+dataDir,
				"GOAUTHY_THEME_RECOVERY_PHASE="+phase,
			)
			if !useS3 {
				cmd.Env = append(cmd.Env, "GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_S3_BUCKET=", "GOAUTHY_RECOVERY_S3_ACCESS_KEY=", "GOAUTHY_RECOVERY_S3_SECRET_KEY=")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s failed: %v\n%s", phase, err, out)
			}
		}
		run(filepath.Join(root, "writer"), "write")
		run(filepath.Join(root, "fresh"), "recover")
		return
	}

	phase := os.Getenv("GOAUTHY_THEME_RECOVERY_PHASE")
	if phase != "write" && phase != "recover" {
		t.Fatalf("invalid recovery phase %q", phase)
	}
	if os.Getenv(s3OptIn) != "1" {
		for _, name := range []string{"GOAUTHY_RECOVERY_S3_ENDPOINT", "GOAUTHY_RECOVERY_S3_BUCKET", "GOAUTHY_RECOVERY_S3_ACCESS_KEY", "GOAUTHY_RECOVERY_S3_SECRET_KEY"} {
			t.Setenv(name, "")
		}
	}
	dataDir := os.Getenv("GOAUTHY_THEME_RECOVERY_DATA_DIR")
	config := noPVCExportConfig(t, root, dataDir, filepath.Join(root, "objects"))
	ctx := t.Context()
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "recover" {
		defer db.Close()
	}
	if phase == "write" {
		if err := storage.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if phase == "recover" {
		if err := storage.Ready(ctx, db); err != nil {
			t.Fatal(err)
		}
	}

	themeStore, err := branding.NewThemeStore(db)
	if err != nil {
		t.Fatal(err)
	}
	want := noPVCThemeFixture()
	if phase == "write" {
		if err := themeStore.Put(ctx, want); err != nil {
			t.Fatal(err)
		}
		real32WebP := make32WebPFavicon(t)
		for _, table := range []string{"client_logos", "auth_provider_logos"} {
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "recover-" + table, SQL: "INSERT INTO " + table + " VALUES(?, 'svg', 'image/svg+xml', ?, ?)", Args: []any{want.ClientID, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h84v84z"/></svg>`), int64(123456789)}}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "recover-favicon", SQL: "INSERT INTO client_logos VALUES(?, 'favicon', 'image/webp', ?, ?)", Args: []any{want.ClientID, real32WebP, int64(123456790)}}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Exercise fresh-directory recovery after an abrupt writer exit.
	}

	// Both logo tables must survive loss of all local files, byte for byte.
	for _, table := range []string{"client_logos", "auth_provider_logos"} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT res,content_type,data,updated FROM " + table + " WHERE res='svg'", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
			t.Fatalf("recovered %s svg rows=%v err=%v", table, result.Rows, err)
		}
		row := result.Rows[0]
		data, ok := row[2].([]byte)
		if !ok || !bytes.Equal(data, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h84v84z"/></svg>`)) || row[0] != "svg" || row[1] != "image/svg+xml" || row[3] != int64(123456789) {
			t.Fatalf("recovered %s asset changed: %v", table, row)
		}
	}

	// Unified client favicon 32px lossless WebP survives recovery.
	want32WebP := make32WebPFavicon(t)
	favResult, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT res,content_type,data,updated FROM client_logos WHERE client_id=? AND res='favicon'", Args: []any{want.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(favResult.Rows) != 1 || len(favResult.Rows[0]) != 4 {
		t.Fatalf("recovered client_logos favicon rows=%v err=%v", favResult.Rows, err)
	}
	favRow := favResult.Rows[0]
	if favRow[0] != "favicon" || favRow[1] != "image/webp" || favRow[3] != int64(123456790) {
		t.Fatalf("favicon metadata changed: res=%v content_type=%v updated=%v", favRow[0], favRow[1], favRow[3])
	}
	favData, ok := favRow[2].([]byte)
	if !ok || !bytes.Equal(favData, want32WebP) {
		t.Fatalf("favicon bytes changed: len=%d want=%d", len(favData), len(want32WebP))
	}
	decodedFavicon, err := nativewebp.Decode(bytes.NewReader(favData))
	if err != nil {
		t.Fatal(err)
	}
	if decodedFavicon.Bounds().Dx() != 32 || decodedFavicon.Bounds().Dy() != 32 {
		t.Fatalf("favicon decode bounds=%v want 32x32", decodedFavicon.Bounds())
	}

	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	themeRow, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT version,document_json FROM client_themes WHERE client_id=?`, Args: []any{want.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(themeRow.Rows) != 1 || len(themeRow.Rows[0]) != 2 || themeRow.Rows[0][0] != int64(1) || themeRow.Rows[0][1] != string(wantJSON) {
		t.Fatalf("recovered theme row=%v err=%v", themeRow.Rows, err)
	}
	got, err := themeStore.GetDefault(ctx, want.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("recovered typed theme changed")
	}
}

func noPVCThemeFixture() branding.Theme {
	theme := branding.DefaultTheme("no-pvc-theme-client")
	theme.Light.Text = []uint16{123, 45, 67}
	theme.Light.ThemeSun = "hsla(var(--action) / .91)"
	theme.Dark.BgHigh = []uint16{211, 22, 18}
	theme.Dark.BtnText = "hsl(var(--bg-high))"
	theme.BorderRadius = "9px"
	return theme
}

// make32WebPFavicon produces a deterministic 32x32 WebP favicon via the
// shared ProcessRasterLogo fixture pipeline. The returned bytes are stable
// across runs because the seed image and the WebP encoder are deterministic.
func make32WebPFavicon(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 8), G: uint8(y * 8), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	assets, err := branding.ProcessRasterLogo(buf.Bytes(), 84, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Resolution != "favicon" || assets[0].ContentType != "image/webp" {
		t.Fatalf("unexpected favicon assets: %#v", assets)
	}
	// Verify WebP magic header.
	if !bytes.HasPrefix(assets[0].Data, []byte("RIFF")) || string(assets[0].Data[8:12]) != "WEBP" {
		t.Fatal("favicon data is not valid WebP")
	}
	return assets[0].Data
}