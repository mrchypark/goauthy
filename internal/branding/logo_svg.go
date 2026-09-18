// Package branding contains validated branding assets and their safe renderers.
package branding

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const (
	svgNamespace     = "http://www.w3.org/2000/svg"
	xlinkNamespace   = "http://www.w3.org/1999/xlink"
	maxSVGDataLength = 1 << 28
	maxSVGAttributes = 200
	maxSVGNameLength = 1000
)

var ErrInvalidLogoSVG = errors.New("invalid logo SVG")

type svgAttrType uint8

const (
	svgAttrAnyAscii svgAttrType = iota
	svgAttrKeyword
	svgAttrNumber
	svgAttrText
	svgAttrAttributeName
	svgAttrUrl
	svgAttrUrlFunc
	svgAttrStyleSheet
)

var allowedSVGElements = map[string]struct{}{
	"a":                   {},
	"altGlyph":            {},
	"altGlyphDef":         {},
	"altGlyphItem":        {},
	"animate":             {},
	"animateColor":        {},
	"animateMotion":       {},
	"animateTransform":    {},
	"circle":              {},
	"clipPath":            {},
	"color-profile":       {},
	"defs":                {},
	"desc":                {},
	"ellipse":             {},
	"feBlend":             {},
	"feColorMatrix":       {},
	"feComponentTransfer": {},
	"feComposite":         {},
	"feConvolveMatrix":    {},
	"feDiffuseLighting":   {},
	"feDisplacementMap":   {},
	"feDistantLight":      {},
	"feDropShadow":        {},
	"feFlood":             {},
	"feFuncA":             {},
	"feFuncB":             {},
	"feFuncG":             {},
	"feFuncR":             {},
	"feGaussianBlur":      {},
	"feImage":             {},
	"feMerge":             {},
	"feMergeNode":         {},
	"feMorphology":        {},
	"feOffset":            {},
	"fePointLight":        {},
	"feSpecularLighting":  {},
	"feSpotLight":         {},
	"feTile":              {},
	"feTurbulence":        {},
	"filter":              {},
	"flowDiv":             {},
	"flowLine":            {},
	"flowPara":            {},
	"flowRegion":          {},
	"flowRoot":            {},
	"flowSpan":            {},
	"flowTref":            {},
	"font":                {},
	"g":                   {},
	"glyph":               {},
	"glyphRef":            {},
	"hkern":               {},
	"image":               {},
	"line":                {},
	"linearGradient":      {},
	"marker":              {},
	"mask":                {},
	"meshgradient":        {},
	"meshpatch":           {},
	"meshrow":             {},
	"mpath":               {},
	"mPath":               {},
	"path":                {},
	"pattern":             {},
	"polygon":             {},
	"polyline":            {},
	"radialGradient":      {},
	"rect":                {},
	"set":                 {},
	"solidColor":          {},
	"stop":                {},
	"svg":                 {},
	"switch":              {},
	"symbol":              {},
	"text":                {},
	"textPath":            {},
	"title":               {},
	"tref":                {},
	"tspan":               {},
	"use":                 {},
	"view":                {},
	"vkern":               {},
}

var svgAttributeTypes = map[string]svgAttrType{
	"attributeName":                svgAttrAttributeName,
	"fr":                           svgAttrAnyAscii,
	"vector-effect":                svgAttrKeyword,
	"solid-color":                  svgAttrAnyAscii,
	"mask-type":                    svgAttrKeyword,
	"filterPrimitiveUnits":         svgAttrKeyword,
	"attributeType":                svgAttrKeyword,
	"blend":                        svgAttrAnyAscii,
	"animateColor":                 svgAttrAnyAscii,
	"animateMotion":                svgAttrAnyAscii,
	"animateTransform":             svgAttrAnyAscii,
	"arabic-form":                  svgAttrAnyAscii,
	"bbox":                         svgAttrAnyAscii,
	"begin":                        svgAttrAnyAscii,
	"by":                           svgAttrAnyAscii,
	"color-profile":                svgAttrUrl,
	"unicode":                      svgAttrAnyAscii,
	"description":                  svgAttrText,
	"dur":                          svgAttrAnyAscii,
	"end":                          svgAttrAnyAscii,
	"format":                       svgAttrAnyAscii,
	"from":                         svgAttrAnyAscii,
	"g1":                           svgAttrAnyAscii,
	"g2":                           svgAttrAnyAscii,
	"glyph-name":                   svgAttrAnyAscii,
	"glyphRef":                     svgAttrAnyAscii,
	"hidden":                       svgAttrKeyword,
	"id":                           svgAttrKeyword,
	"in":                           svgAttrAnyAscii,
	"in2":                          svgAttrAnyAscii,
	"kernelMatrix":                 svgAttrAnyAscii,
	"keyPoints":                    svgAttrAnyAscii,
	"keySplines":                   svgAttrAnyAscii,
	"keyTimes":                     svgAttrAnyAscii,
	"line-height":                  svgAttrAnyAscii,
	"local":                        svgAttrAnyAscii,
	"max":                          svgAttrAnyAscii,
	"min":                          svgAttrAnyAscii,
	"name":                         svgAttrAnyAscii,
	"orient":                       svgAttrAnyAscii,
	"orientation":                  svgAttrAnyAscii,
	"origin":                       svgAttrAnyAscii,
	"panose-1":                     svgAttrAnyAscii,
	"path":                         svgAttrAnyAscii,
	"repeatCount":                  svgAttrAnyAscii,
	"repeatDur":                    svgAttrAnyAscii,
	"result":                       svgAttrAnyAscii,
	"side":                         svgAttrKeyword,
	"string":                       svgAttrAnyAscii,
	"tabindex":                     svgAttrNumber,
	"tableValues":                  svgAttrAnyAscii,
	"to":                           svgAttrUrlFunc,
	"transform-origin":             svgAttrAnyAscii,
	"u1":                           svgAttrAnyAscii,
	"u2":                           svgAttrAnyAscii,
	"unicode-range":                svgAttrAnyAscii,
	"values":                       svgAttrAnyAscii,
	"widths":                       svgAttrAnyAscii,
	"accent-height":                svgAttrNumber,
	"accumulate":                   svgAttrKeyword,
	"additive":                     svgAttrKeyword,
	"alignment-baseline":           svgAttrKeyword,
	"alphabetic":                   svgAttrNumber,
	"amplitude":                    svgAttrNumber,
	"arcrole":                      svgAttrUrl,
	"ascent":                       svgAttrNumber,
	"azimuth":                      svgAttrNumber,
	"base":                         svgAttrUrl,
	"baseFrequency":                svgAttrAnyAscii,
	"baseline-shift":               svgAttrAnyAscii,
	"baseProfile":                  svgAttrText,
	"bias":                         svgAttrNumber,
	"calcMode":                     svgAttrKeyword,
	"cap-height":                   svgAttrNumber,
	"class":                        svgAttrAnyAscii,
	"clip":                         svgAttrUrlFunc,
	"clip-path":                    svgAttrUrlFunc,
	"clip-rule":                    svgAttrAnyAscii,
	"clipPathUnits":                svgAttrKeyword,
	"color":                        svgAttrAnyAscii,
	"color-interpolation":          svgAttrKeyword,
	"color-interpolation-filters":  svgAttrKeyword,
	"color-rendering":              svgAttrKeyword,
	"cursor":                       svgAttrUrlFunc,
	"cx":                           svgAttrAnyAscii,
	"cy":                           svgAttrAnyAscii,
	"d":                            svgAttrAnyAscii,
	"descent":                      svgAttrNumber,
	"diffuseConstant":              svgAttrNumber,
	"direction":                    svgAttrKeyword,
	"display":                      svgAttrKeyword,
	"divisor":                      svgAttrNumber,
	"dominant-baseline":            svgAttrKeyword,
	"dx":                           svgAttrAnyAscii,
	"dy":                           svgAttrAnyAscii,
	"edgeMode":                     svgAttrKeyword,
	"elevation":                    svgAttrNumber,
	"enable-background":            svgAttrAnyAscii,
	"exponent":                     svgAttrNumber,
	"externalResourcesRequired":    svgAttrKeyword,
	"fill":                         svgAttrUrlFunc,
	"fill-opacity":                 svgAttrAnyAscii,
	"fill-rule":                    svgAttrAnyAscii,
	"filter":                       svgAttrUrlFunc,
	"filterRes":                    svgAttrAnyAscii,
	"filterUnits":                  svgAttrKeyword,
	"flood-color":                  svgAttrAnyAscii,
	"flood-opacity":                svgAttrAnyAscii,
	"font-family":                  svgAttrAnyAscii,
	"font-size":                    svgAttrAnyAscii,
	"font-size-adjust":             svgAttrAnyAscii,
	"font-stretch":                 svgAttrKeyword,
	"font-style":                   svgAttrKeyword,
	"font-variant":                 svgAttrKeyword,
	"font-weight":                  svgAttrKeyword,
	"fx":                           svgAttrAnyAscii,
	"fy":                           svgAttrAnyAscii,
	"glyph-orientation-horizontal": svgAttrAnyAscii,
	"glyph-orientation-vertical":   svgAttrAnyAscii,
	"gradientTransform":            svgAttrAnyAscii,
	"gradientUnits":                svgAttrKeyword,
	"hanging":                      svgAttrNumber,
	"height":                       svgAttrAnyAscii,
	"horiz-adv-x":                  svgAttrNumber,
	"horiz-origin-x":               svgAttrNumber,
	"horiz-origin-y":               svgAttrNumber,
	"href":                         svgAttrUrl,
	"ideographic":                  svgAttrNumber,
	"image-rendering":              svgAttrKeyword,
	"intercept":                    svgAttrNumber,
	"k":                            svgAttrNumber,
	"k1":                           svgAttrNumber,
	"k2":                           svgAttrNumber,
	"k3":                           svgAttrNumber,
	"k4":                           svgAttrNumber,
	"kernelUnitLength":             svgAttrAnyAscii,
	"kerning":                      svgAttrAnyAscii,
	"lang":                         svgAttrAnyAscii,
	"lengthAdjust":                 svgAttrKeyword,
	"letter-spacing":               svgAttrAnyAscii,
	"lighting-color":               svgAttrAnyAscii,
	"limitingConeAngle":            svgAttrNumber,
	"marker-end":                   svgAttrUrlFunc,
	"marker-mid":                   svgAttrUrlFunc,
	"marker-start":                 svgAttrUrlFunc,
	"markerHeight":                 svgAttrAnyAscii,
	"markerUnits":                  svgAttrKeyword,
	"markerWidth":                  svgAttrAnyAscii,
	"mask":                         svgAttrUrlFunc,
	"maskContentUnits":             svgAttrKeyword,
	"maskUnits":                    svgAttrKeyword,
	"mathematical":                 svgAttrNumber,
	"media":                        svgAttrAnyAscii,
	"method":                       svgAttrKeyword,
	"mode":                         svgAttrKeyword,
	"numOctaves":                   svgAttrNumber,
	"offset":                       svgAttrAnyAscii,
	"opacity":                      svgAttrAnyAscii,
	"operator":                     svgAttrKeyword,
	"order":                        svgAttrAnyAscii,
	"overflow":                     svgAttrKeyword,
	"overline-position":            svgAttrNumber,
	"overline-thickness":           svgAttrNumber,
	"pathLength":                   svgAttrNumber,
	"patternContentUnits":          svgAttrKeyword,
	"patternTransform":             svgAttrAnyAscii,
	"patternUnits":                 svgAttrKeyword,
	"pointer-events":               svgAttrKeyword,
	"points":                       svgAttrAnyAscii,
	"pointsAtX":                    svgAttrNumber,
	"pointsAtY":                    svgAttrNumber,
	"pointsAtZ":                    svgAttrNumber,
	"preserveAlpha":                svgAttrKeyword,
	"preserveAspectRatio":          svgAttrAnyAscii,
	"primitiveUnits":               svgAttrKeyword,
	"r":                            svgAttrAnyAscii,
	"radius":                       svgAttrAnyAscii,
	"refX":                         svgAttrAnyAscii,
	"refY":                         svgAttrAnyAscii,
	"rendering-intent":             svgAttrKeyword,
	"requiredExtensions":           svgAttrAnyAscii,
	"requiredFeatures":             svgAttrAnyAscii,
	"restart":                      svgAttrKeyword,
	"role":                         svgAttrUrl,
	"rotate":                       svgAttrAnyAscii,
	"rx":                           svgAttrAnyAscii,
	"ry":                           svgAttrAnyAscii,
	"scale":                        svgAttrNumber,
	"seed":                         svgAttrNumber,
	"shape-rendering":              svgAttrKeyword,
	"show":                         svgAttrKeyword,
	"slope":                        svgAttrNumber,
	"space":                        svgAttrKeyword,
	"spacing":                      svgAttrKeyword,
	"specularConstant":             svgAttrNumber,
	"specularExponent":             svgAttrNumber,
	"spreadMethod":                 svgAttrKeyword,
	"startOffset":                  svgAttrAnyAscii,
	"stdDeviation":                 svgAttrAnyAscii,
	"stemh":                        svgAttrNumber,
	"stemv":                        svgAttrNumber,
	"stitchTiles":                  svgAttrKeyword,
	"stop-color":                   svgAttrAnyAscii,
	"stop-opacity":                 svgAttrAnyAscii,
	"strikethrough-position":       svgAttrNumber,
	"strikethrough-thickness":      svgAttrNumber,
	"stroke":                       svgAttrUrlFunc,
	"stroke-dasharray":             svgAttrAnyAscii,
	"stroke-dashoffset":            svgAttrAnyAscii,
	"stroke-linecap":               svgAttrKeyword,
	"stroke-linejoin":              svgAttrKeyword,
	"stroke-miterlimit":            svgAttrAnyAscii,
	"stroke-opacity":               svgAttrAnyAscii,
	"stroke-width":                 svgAttrAnyAscii,
	"style":                        svgAttrStyleSheet,
	"surfaceScale":                 svgAttrNumber,
	"systemLanguage":               svgAttrAnyAscii,
	"targetX":                      svgAttrNumber,
	"targetY":                      svgAttrNumber,
	"text-anchor":                  svgAttrKeyword,
	"text-decoration":              svgAttrAnyAscii,
	"text-rendering":               svgAttrKeyword,
	"textLength":                   svgAttrAnyAscii,
	"title":                        svgAttrText,
	"transform":                    svgAttrAnyAscii,
	"type":                         svgAttrKeyword,
	"underline-position":           svgAttrNumber,
	"underline-thickness":          svgAttrNumber,
	"unicode-bidi":                 svgAttrKeyword,
	"units-per-em":                 svgAttrNumber,
	"v-alphabetic":                 svgAttrNumber,
	"v-hanging":                    svgAttrNumber,
	"v-ideographic":                svgAttrNumber,
	"v-mathematical":               svgAttrNumber,
	"version":                      svgAttrNumber,
	"vert-adv-y":                   svgAttrNumber,
	"vert-origin-x":                svgAttrNumber,
	"vert-origin-y":                svgAttrNumber,
	"viewBox":                      svgAttrAnyAscii,
	"visibility":                   svgAttrKeyword,
	"width":                        svgAttrAnyAscii,
	"word-spacing":                 svgAttrAnyAscii,
	"writing-mode":                 svgAttrKeyword,
	"x":                            svgAttrAnyAscii,
	"x-height":                     svgAttrNumber,
	"x1":                           svgAttrAnyAscii,
	"x2":                           svgAttrAnyAscii,
	"xChannelSelector":             svgAttrKeyword,
	"xmlns":                        svgAttrUrl,
	"y":                            svgAttrAnyAscii,
	"y1":                           svgAttrAnyAscii,
	"y2":                           svgAttrAnyAscii,
	"yChannelSelector":             svgAttrKeyword,
	"z":                            svgAttrNumber,
	"zoomAndPan":                   svgAttrKeyword,
}

// SanitizedLogoSVG applies the svg-hush v0.9.6 policy pinned by rauthy v0.36.2.
// Its allowlists and filtering algorithm are ported from
// ../rauthy/src/data/src/entity/logos.rs and svg-hush 0.9.6; see
// licenses/SVG-HUSH-LICENSE for the required MIT attribution.
// It removes unsupported elements and attributes, strips XML namespaces except
// for SVG, rewrites URL references to same-origin relative paths, and permits
// only standard raster image data URLs.
func SanitizedLogoSVG(source []byte) ([]byte, error) {
	if len(source) > maxSVGDataLength {
		return nil, fmt.Errorf("%w: input exceeds parser limit", ErrInvalidLogoSVG)
	}
	decoder := xml.NewDecoder(bytes.NewReader(source))
	decoder.Strict = true
	var out bytes.Buffer
	out.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	depth, skipped, roots := 0, 0, 0
	emitted := false
	styleDepth := 0
	var styleText strings.Builder

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: parse SVG: %v", ErrInvalidLogoSVG, err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(value.Name.Local) > maxSVGNameLength || len(value.Attr) > maxSVGAttributes {
				return nil, fmt.Errorf("%w: parser limit exceeded", ErrInvalidLogoSVG)
			}
			if depth == 0 {
				roots++
				if roots > 1 {
					return nil, fmt.Errorf("%w: multiple root elements", ErrInvalidLogoSVG)
				}
			}
			depth++
			if skipped > 0 {
				skipped++
				continue
			}
			if value.Name.Space != svgNamespace {
				skipped = 1
				continue
			}
			if value.Name.Local != "style" {
				if _, ok := allowedSVGElements[value.Name.Local]; !ok {
					skipped = 1
					continue
				}
			}
			attrs := filterSVGAttributes(value.Name.Local, value.Attr)
			out.WriteByte('<')
			out.WriteString(value.Name.Local)
			if depth == 1 {
				out.WriteString(` xmlns="`)
				out.WriteString(svgNamespace)
				out.WriteByte('"')
			}
			for _, attr := range attrs {
				out.WriteByte(' ')
				out.WriteString(attr.Name.Local)
				out.WriteString(`="`)
				out.WriteString(escapeXMLAttribute(attr.Value))
				out.WriteByte('"')
			}
			out.WriteByte('>')
			emitted = true
			if value.Name.Local == "style" {
				styleDepth = depth
				styleText.Reset()
			}

		case xml.EndElement:
			if depth == 0 {
				return nil, fmt.Errorf("%w: unexpected end element", ErrInvalidLogoSVG)
			}
			if skipped > 0 {
				skipped--
				depth--
				continue
			}
			if styleDepth == depth {
				filteredStyle := filteredSVGURLFunc(styleText.String())
				if err := xml.EscapeText(&out, []byte(filteredStyle)); err != nil {
					return nil, fmt.Errorf("%w: escape style text: %v", ErrInvalidLogoSVG, err)
				}
				styleDepth = 0
				styleText.Reset()
			}
			out.WriteString(`</`)
			out.WriteString(value.Name.Local)
			out.WriteByte('>')
			depth--

		case xml.CharData:
			if skipped > 0 {
				continue
			}
			if styleDepth == depth {
				styleText.Write([]byte(value))
				continue
			}
			if err := xml.EscapeText(&out, value); err != nil {
				return nil, fmt.Errorf("%w: escape text: %v", ErrInvalidLogoSVG, err)
			}
		case xml.Comment, xml.Directive, xml.ProcInst:
			// svg-hush drops comments, doctypes, and processing instructions.
		}
	}
	if depth != 0 || !emitted {
		return nil, fmt.Errorf("%w: no acceptable SVG elements found", ErrInvalidLogoSVG)
	}
	return out.Bytes(), nil
}

func filterSVGAttributes(element string, input []xml.Attr) []xml.Attr {
	filtered := make([]xml.Attr, 0, len(input))
	seenHref := false
	for _, attr := range input {
		if attr.Name.Local == "href" {
			if seenHref {
				continue
			}
			seenHref = true
		}
		if attr.Name.Local == "xmlns" || attr.Name.Space == "xmlns" {
			continue
		}
		if attr.Name.Space != "" {
			if attr.Name.Space != xlinkNamespace || attr.Name.Local != "href" {
				continue
			}
			attr.Name = xml.Name{Local: "href"}
		}
		if attr.Name.Local == "href" && !mayUseSVGHref(element) {
			continue
		}
		kind, ok := svgAttributeTypes[attr.Name.Local]
		if !ok {
			switch {
			case strings.HasPrefix(attr.Name.Local, "aria-"):
				kind = svgAttrAnyAscii
			case strings.HasPrefix(attr.Name.Local, "data-"):
				filtered = append(filtered, attr)
				continue
			default:
				continue
			}
		}
		if kind == svgAttrText {
			filtered = append(filtered, attr)
			continue
		}
		trimmed := strings.TrimSpace(attr.Value)
		value := normalizeSVGASCII(attr.Value, trimmed)
		switch kind {
		case svgAttrAnyAscii, svgAttrKeyword, svgAttrNumber:
			attr.Value = value
		case svgAttrAttributeName:
			nameKind, validName := svgAttributeTypes[strings.TrimSpace(attr.Value)]
			if !validName || (nameKind != svgAttrAnyAscii && nameKind != svgAttrKeyword && nameKind != svgAttrNumber && nameKind != svgAttrText) {
				continue
			}
			attr.Value = value
		case svgAttrUrl:
			value, ok := filterSVGURL(value)
			if !ok {
				continue
			}
			attr.Value = value
		case svgAttrUrlFunc, svgAttrStyleSheet:
			attr.Value = filteredSVGURLFunc(value)
		default:
			continue
		}
		filtered = append(filtered, attr)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].Name.Local < filtered[j].Name.Local
	})
	return filtered
}

func normalizeSVGASCII(original, trimmed string) string {
	if trimmed == "" {
		return trimmed
	}
	ascii := true
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == 0 || trimmed[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return trimmed
	}
	var out strings.Builder
	for _, r := range original {
		if r == 0 {
			continue
		}
		if unicode.IsSpace(r) {
			out.WriteByte(' ')
			continue
		}
		if r >= 0x80 {
			continue
		}
		out.WriteRune(r)
	}
	return strings.TrimSpace(out.String())
}

func mayUseSVGHref(element string) bool {
	switch element {
	case "radialGradient", "linearGradient", "image", "use", "pattern", "feImage":
		return true
	default:
		return false
	}
}

func allowStandardImageDataURL(value string) bool {
	if len(value) < len("data:") || !strings.EqualFold(value[:len("data:")], "data:") {
		return false
	}
	rest := value[len("data:"):]
	comma := strings.IndexByte(rest, ',')
	fragment := strings.IndexByte(rest, '#')
	if comma < 0 || fragment >= 0 && fragment < comma {
		return false
	}
	metadata := strings.Trim(rest[:comma], " \t\r\n")
	if withoutBase64, ok := removeDataURLBase64Suffix(metadata); ok {
		metadata = withoutBase64
	}
	mediaType, _, err := mime.ParseMediaType(metadata)
	if err != nil {
		return false
	}
	parts := strings.SplitN(strings.ToLower(mediaType), "/", 2)
	if len(parts) != 2 || parts[0] != "image" {
		return false
	}
	switch parts[1] {
	case "jpeg", "png", "gif":
		return true
	default:
		return false
	}
}

func removeDataURLBase64Suffix(value string) (string, bool) {
	if len(value) < len(";base64") {
		return "", false
	}
	position := len(value)
	for _, expected := range []byte{'4', '6', 'e', 's', 'a', 'b'} {
		for position > 0 && strings.ContainsRune("\t\n\r", rune(value[position-1])) {
			position--
		}
		if position == 0 || !strings.EqualFold(value[position-1:position], string(expected)) {
			return "", false
		}
		position--
	}
	for position > 0 && value[position-1] == ' ' {
		position--
	}
	if position == 0 || value[position-1] != ';' {
		return "", false
	}
	return value[:position-1], true
}

func filterSVGURL(value string) (string, bool) {
	if allowStandardImageDataURL(value) {
		return value, true
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.EqualFold(parsed.Scheme, "data") || parsed.Opaque != "" {
		return "", false
	}
	base, _ := url.Parse("https://127.0.0.1/__relpath_prefix__/")
	resolved := base.ResolveReference(parsed)
	path := resolved.EscapedPath()
	if path == "" {
		path = "/"
	}
	relative := strings.TrimPrefix(path, "/__relpath_prefix__/")
	if strings.HasPrefix(strings.TrimLeft(relative, " \t\r\n"), "//") {
		return "", false
	}
	if strings.Contains(relative, ":") {
		relative = strings.ReplaceAll(relative, ":", "%3a")
	}
	if relative == "/" {
		return "", false
	}
	if resolved.RawQuery != "" {
		relative += "?" + strings.ReplaceAll(resolved.RawQuery, " ", "%20")
	}
	if fragment := resolved.EscapedFragment(); fragment != "" || strings.Contains(value, "#") {
		relative += "#" + fragment
	}
	if strings.Contains(relative, "(") {
		relative = strings.ReplaceAll(relative, "(", "%28")
	}
	return relative, true
}

func filteredSVGURLFunc(value string) string {
	var out strings.Builder
	insideURL := false
	for _, chunk := range strings.SplitAfter(value, "(") {
		if insideURL {
			close := strings.IndexByte(chunk, ')')
			if close < 0 {
				continue
			}
			urlValue := strings.Trim(strings.TrimSpace(chunk[:close]), "\"'")
			urlValue = strings.TrimSpace(urlValue)
			rest := chunk[close+1:]
			filtered, ok := filterSVGURL(urlValue)
			if !ok || strings.ContainsAny(filtered, "()'\"\\ ") {
				filtered = "#"
			}
			out.WriteString(filtered)
			out.WriteByte(')')
			insideURL = false
			chunk = rest
		}
		for _, part := range splitSVGDelimiters(chunk) {
			lower := strings.ToLower(part)
			if strings.Contains(part, "\\") || (strings.Contains(part, "@") && strings.Contains(lower, "@import")) {
				if len(part) > 0 {
					last := part[len(part)-1]
					if last == '{' || last == '}' {
						out.WriteByte(last)
					}
				}
				continue
			}
			out.WriteString(part)
			insideURL = len(part) >= 4 && strings.EqualFold(part[len(part)-4:], "url(")
		}
	}
	if insideURL {
		out.WriteByte(')')
	}
	return out.String()
}

func splitSVGDelimiters(value string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(value); i++ {
		if strings.ContainsRune(";{},", rune(value[i])) {
			parts = append(parts, value[start:i+1])
			start = i + 1
		}
	}
	if start < len(value) {
		parts = append(parts, value[start:])
	}
	return parts
}

func escapeXMLAttribute(value string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	return strings.ReplaceAll(escaped.String(), `"`, "&#34;")
}
