package branding

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"

	nativewebp "github.com/HugoSmits86/nativewebp"
	"golang.org/x/image/draw"
)

const (
	logoMediumSize        = 128
	logoClientSmallSize   = 84
	logoProviderSmallSize = 20
	logoFaviconSize       = 32

	// These bounds are checked from the image header before image.Decode can
	// allocate a pixel buffer. They cap both compressed input and expansion.
	maxRasterLogoBytes  = 16 << 20
	maxRasterLogoPixels = 16 << 20
	maxRasterLogoDim    = 8192

	// resize_to_fill may briefly widen a very short image before cropping it.
	// Bound that intermediate independently so an accepted input cannot turn
	// into an unbounded allocation during the scale-before-crop step.
	maxRasterIntermediateDim    = 32768
	maxRasterIntermediatePixels = 16 << 20
)

var (
	ErrInvalidRasterLogo  = errors.New("invalid raster logo")
	ErrRasterLogoTooLarge = errors.New("raster logo exceeds resource limit")
)

// LogoAsset is one processed WebP resolution. Resolution is one of
// "medium", "custom", "small", or "favicon".
type LogoAsset struct {
	Resolution  string
	ContentType string
	Data        []byte
}

// ProcessRasterLogo ports the pinned Rauthy raster logo pipeline for PNG and
// JPEG input. Normal logos produce a medium/custom asset and a square small
// asset; favicon processing produces only the fixed 32px square asset.
func ProcessRasterLogo(data []byte, smallSize int, favicon bool) ([]LogoAsset, error) {
	if len(data) == 0 {
		return nil, ErrInvalidRasterLogo
	}
	if len(data) > maxRasterLogoBytes {
		return nil, ErrRasterLogoTooLarge
	}

	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: decode config: %v", ErrInvalidRasterLogo, err)
	}
	if format != "png" && format != "jpeg" {
		return nil, fmt.Errorf("%w: format %q", ErrInvalidRasterLogo, format)
	}
	if config.Width <= 0 || config.Height <= 0 {
		return nil, ErrInvalidRasterLogo
	}
	if config.Width > maxRasterLogoDim || config.Height > maxRasterLogoDim {
		return nil, ErrRasterLogoTooLarge
	}
	if uint64(config.Width) > maxRasterLogoPixels/uint64(config.Height) {
		return nil, ErrRasterLogoTooLarge
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidRasterLogo, err)
	}
	if img.Bounds().Dx() != config.Width || img.Bounds().Dy() != config.Height {
		return nil, ErrInvalidRasterLogo
	}

	if favicon {
		if config.Height < logoFaviconSize {
			return nil, fmt.Errorf("%w: favicon height must be at least %d", ErrInvalidRasterLogo, logoFaviconSize)
		}
		resized, err := resizeToFill(img, logoFaviconSize, logoFaviconSize)
		if err != nil {
			return nil, err
		}
		data, err := encodeWebP(resized)
		if err != nil {
			return nil, err
		}
		return []LogoAsset{{Resolution: "favicon", ContentType: "image/webp", Data: data}}, nil
	}
	if smallSize <= 0 {
		return nil, fmt.Errorf("%w: invalid small size", ErrInvalidRasterLogo)
	}
	if config.Height < smallSize {
		return nil, fmt.Errorf("%w: height must be at least %d", ErrInvalidRasterLogo, smallSize)
	}

	medium := img
	resolution := "custom"
	if config.Width >= logoMediumSize || config.Height >= logoMediumSize {
		medium, err = resizeToFill(img, logoMediumSize, logoMediumSize)
		if err != nil {
			return nil, err
		}
		resolution = "medium"
	}
	mediumData, err := encodeWebP(medium)
	if err != nil {
		return nil, err
	}
	small, err := resizeToFill(medium, smallSize, smallSize)
	if err != nil {
		return nil, err
	}
	smallData, err := encodeWebP(small)
	if err != nil {
		return nil, err
	}
	return []LogoAsset{
		{Resolution: resolution, ContentType: "image/webp", Data: mediumData},
		{Resolution: "small", ContentType: "image/webp", Data: smallData},
	}, nil
}

var lanczos3 = &draw.Kernel{
	Support: 3,
	At: func(t float64) float64 {
		if t == 0 {
			return 1
		}
		if t < 0 {
			t = -t
		}
		if t >= 3 {
			return 0
		}
		return sinc(t) * sinc(t/3)
	},
}

func sinc(x float64) float64 {
	x *= math.Pi
	return math.Sin(x) / x
}

func resizeToFill(src image.Image, width, height int) (image.Image, error) {
	if src == nil || width <= 0 || height <= 0 || width > maxRasterIntermediateDim || height > maxRasterIntermediateDim {
		return nil, ErrRasterLogoTooLarge
	}
	source := src.Bounds()
	sourceWidth, sourceHeight := source.Dx(), source.Dy()
	if sourceWidth <= 0 || sourceHeight <= 0 {
		return nil, ErrInvalidRasterLogo
	}
	ratio := math.Max(float64(width)/float64(sourceWidth), float64(height)/float64(sourceHeight))
	intermediateWidthFloat := math.Max(math.Round(float64(sourceWidth)*ratio), 1)
	intermediateHeightFloat := math.Max(math.Round(float64(sourceHeight)*ratio), 1)
	if intermediateWidthFloat > maxRasterIntermediateDim || intermediateHeightFloat > maxRasterIntermediateDim {
		return nil, ErrRasterLogoTooLarge
	}
	intermediateWidth, intermediateHeight := int(intermediateWidthFloat), int(intermediateHeightFloat)
	if uint64(intermediateWidth) > maxRasterIntermediatePixels/uint64(intermediateHeight) {
		return nil, ErrRasterLogoTooLarge
	}
	if intermediateWidth < width || intermediateHeight < height {
		return nil, ErrRasterLogoTooLarge
	}

	intermediate := image.NewNRGBA(image.Rect(0, 0, intermediateWidth, intermediateHeight))
	lanczos3.Scale(intermediate, intermediate.Bounds(), src, source, draw.Src, nil)
	cropX, cropY := 0, 0
	if uint64(width)*uint64(intermediateHeight) > uint64(intermediateWidth)*uint64(height) {
		cropY = (intermediateHeight - height) / 2
	} else {
		cropX = (intermediateWidth - width) / 2
	}
	result := image.NewNRGBA(image.Rect(0, 0, width, height))
	draw.Draw(result, result.Bounds(), intermediate, image.Pt(cropX, cropY), draw.Src)
	return result, nil
}

func encodeWebP(img image.Image) ([]byte, error) {
	var output bytes.Buffer
	if err := nativewebp.Encode(&output, img, nil); err != nil {
		return nil, fmt.Errorf("encode WebP: %w", err)
	}
	return output.Bytes(), nil
}
