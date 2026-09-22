package branding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	"testing"

	nativewebp "github.com/HugoSmits86/nativewebp"
	xdraw "golang.org/x/image/draw"
)

func TestProcessRasterLogoClientPNGDimensionsCropAndWebP(t *testing.T) {
	t.Parallel()
	input := logoFixture(200, 100)
	assets, err := ProcessRasterLogo(encodePNG(t, input), logoClientSmallSize, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[0].Resolution != "medium" || assets[1].Resolution != "small" {
		t.Fatalf("assets=%#v", assets)
	}
	for _, asset := range assets {
		if asset.ContentType != "image/webp" || !bytes.HasPrefix(asset.Data, []byte("RIFF")) || string(asset.Data[8:12]) != "WEBP" {
			t.Fatalf("asset=%#v", asset)
		}
	}
	assertDecodedSize(t, assets[0].Data, 128, 128)
	assertDecodedSize(t, assets[1].Data, 84, 84)
	assertCenterColor(t, assets[0].Data)
	assertCenterColor(t, assets[1].Data)
}

func TestProcessRasterLogoCustomJPEGAndFavicon(t *testing.T) {
	t.Parallel()
	input := logoFixture(100, 90)
	assets, err := ProcessRasterLogo(encodeJPEG(t, input), logoProviderSmallSize, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[0].Resolution != "custom" || assets[1].Resolution != "small" {
		t.Fatalf("custom assets=%#v", assets)
	}
	assertDecodedSize(t, assets[0].Data, 100, 90)
	assertDecodedSize(t, assets[1].Data, 20, 20)

	assets, err = ProcessRasterLogo(encodePNG(t, input), logoClientSmallSize, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Resolution != "favicon" || assets[0].ContentType != "image/webp" {
		t.Fatalf("favicon assets=%#v", assets)
	}
	assertDecodedSize(t, assets[0].Data, 32, 32)
}

func TestResizeToFillMatchesPinnedScaleThenCropRounding(t *testing.T) {
	t.Parallel()
	source := asymmetricLogoFixture(301, 101)
	got, err := resizeToFill(source, 128, 84)
	if err != nil {
		t.Fatal(err)
	}
	want := pinnedResizeToFill(source, 128, 84)
	for y := 0; y < 84; y++ {
		for x := 0; x < 128; x++ {
			gotR, gotG, gotB, gotA := got.At(x, y).RGBA()
			wantR, wantG, wantB, wantA := want.At(x, y).RGBA()
			if gotR != wantR || gotG != wantG || gotB != wantB || gotA != wantA {
				t.Fatalf("pixel (%d,%d) got=(%d,%d,%d,%d) want=(%d,%d,%d,%d)", x, y, gotR, gotG, gotB, gotA, wantR, wantG, wantB, wantA)
			}
		}
	}
}

func TestResizeToFillBoundsExtremeIntermediate(t *testing.T) {
	t.Parallel()
	if _, err := resizeToFill(boundedImage{bounds: image.Rect(0, 0, 8192, 20)}, 128, 128); !errors.Is(err, ErrRasterLogoTooLarge) {
		t.Fatalf("extreme intermediate error=%v", err)
	}
}

func TestProcessRasterLogoRejectsMalformedAndBoundedResources(t *testing.T) {
	t.Parallel()
	if _, err := ProcessRasterLogo([]byte("not an image"), logoClientSmallSize, false); !errors.Is(err, ErrInvalidRasterLogo) {
		t.Fatalf("malformed error=%v", err)
	}
	if _, err := ProcessRasterLogo(pngHeader(9000, 9000), logoClientSmallSize, false); !errors.Is(err, ErrRasterLogoTooLarge) {
		t.Fatalf("pixel bomb error=%v", err)
	}
	if _, err := ProcessRasterLogo(bytes.Repeat([]byte{'x'}, maxRasterLogoBytes+1), logoClientSmallSize, false); !errors.Is(err, ErrRasterLogoTooLarge) {
		t.Fatalf("input bomb error=%v", err)
	}
	if _, err := ProcessRasterLogo(encodePNG(t, logoFixture(1, 83)), logoClientSmallSize, false); !errors.Is(err, ErrInvalidRasterLogo) {
		t.Fatalf("small client logo error=%v", err)
	}
}

func logoFixture(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			var pixel color.RGBA
			switch {
			case x < width/4:
				pixel = color.RGBA{R: 255, A: 255}
			case x >= width*3/4:
				pixel = color.RGBA{B: 255, A: 255}
			default:
				pixel = color.RGBA{G: 255, A: 255}
			}
			img.SetRGBA(x, y, pixel)
		}
	}
	return img
}

func asymmetricLogoFixture(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8((x * 3) % 251), G: uint8((y * 5) % 251), B: uint8((x + y*7) % 251), A: 255})
		}
	}
	return img
}

func pinnedResizeToFill(src image.Image, width, height int) image.Image {
	source := src.Bounds()
	ratio := math.Max(float64(width)/float64(source.Dx()), float64(height)/float64(source.Dy()))
	intermediateWidth := maxInt(int(math.Round(float64(source.Dx())*ratio)), 1)
	intermediateHeight := maxInt(int(math.Round(float64(source.Dy())*ratio)), 1)
	intermediate := image.NewNRGBA(image.Rect(0, 0, intermediateWidth, intermediateHeight))
	lanczos3.Scale(intermediate, intermediate.Bounds(), src, source, xdraw.Src, nil)
	cropX, cropY := 0, 0
	if uint64(width)*uint64(intermediateHeight) > uint64(intermediateWidth)*uint64(height) {
		cropY = (intermediateHeight - height) / 2
	} else {
		cropX = (intermediateWidth - width) / 2
	}
	result := image.NewNRGBA(image.Rect(0, 0, width, height))
	xdraw.Draw(result, result.Bounds(), intermediate, image.Pt(cropX, cropY), xdraw.Src)
	return result
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}

type boundedImage struct{ bounds image.Rectangle }

func (i boundedImage) ColorModel() color.Model { return color.RGBAModel }
func (i boundedImage) Bounds() image.Rectangle { return i.bounds }
func (i boundedImage) At(int, int) color.Color { return color.White }

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := png.Encode(&output, img); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func encodeJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := jpeg.Encode(&output, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func assertDecodedSize(t *testing.T, data []byte, width, height int) {
	t.Helper()
	decoded, err := nativewebp.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Bounds(); got.Dx() != width || got.Dy() != height {
		t.Fatalf("decoded bounds=%v want %dx%d", got, width, height)
	}
}

func assertCenterColor(t *testing.T, data []byte) {
	t.Helper()
	decoded, err := nativewebp.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	bounds := decoded.Bounds()
	red, green, blue, alpha := decoded.At(bounds.Min.X+bounds.Dx()/2, bounds.Min.Y+bounds.Dy()/2).RGBA()
	if alpha < 0xffff/2 || green <= red*2 || green <= blue*2 {
		t.Fatalf("center color=(%d,%d,%d,%d) is not cropped center", red, green, blue, alpha)
	}
}

func pngHeader(width, height uint32) []byte {
	const pngSignature = "\x89PNG\r\n\x1a\n"
	chunk := make([]byte, 17)
	binary.BigEndian.PutUint32(chunk[0:4], 13)
	copy(chunk[4:8], "IHDR")
	binary.BigEndian.PutUint32(chunk[8:12], width)
	binary.BigEndian.PutUint32(chunk[12:16], height)
	chunk[16] = 8
	chunk = append(chunk, 2, 0, 0, 0)
	crc := crc32.ChecksumIEEE(chunk[4:21])
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc)
	chunk = append(chunk, checksum[:]...)
	return append([]byte(pngSignature), chunk...)
}
