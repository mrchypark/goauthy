package branding

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	clientIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,256}$`)
	cssNumberPattern = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$`)
	cssValuePattern  = regexp.MustCompile(`^[a-z0-9-,.#()%/\s]+$`)
)

var (
	ErrInvalidTheme     = errors.New("invalid theme")
	ErrThemeLowContrast = errors.New("theme colors lack sufficient contrast")
)

// ThemeCSS contains the HSL values and CSS values used by a theme variant.
// HSL slices are validated at the JSON boundary so missing values are not
// silently accepted as zero-filled fixed arrays.
type ThemeCSS struct {
	Text      []uint16 `json:"text"`
	TextHigh  []uint16 `json:"text_high"`
	Bg        []uint16 `json:"bg"`
	BgHigh    []uint16 `json:"bg_high"`
	Action    []uint16 `json:"action"`
	Accent    []uint16 `json:"accent"`
	Error     []uint16 `json:"error"`
	Approved  []uint16 `json:"approved,omitempty"`
	Warning   []uint16 `json:"warning,omitempty"`
	BtnText   string   `json:"btn_text"`
	ThemeSun  string   `json:"theme_sun"`
	ThemeMoon string   `json:"theme_moon"`
}

type Theme struct {
	ClientID     string           `json:"client_id"`
	BrandName    string           `json:"brand_name,omitempty"`
	FontFamily   string           `json:"font_family,omitempty"`
	Light        ThemeCSS         `json:"light"`
	Dark         ThemeCSS         `json:"dark"`
	BorderRadius string           `json:"border_radius"`
	Login        *LoginAppearance `json:"login,omitempty"`
}

type LoginAppearance struct {
	Copy          map[string]LoginCopy `json:"copy,omitempty"`
	LogoAlignment string               `json:"logo_alignment,omitempty"`
	CardWidth     int                  `json:"card_width,omitempty"`
}

type LoginCopy struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Button      string `json:"button,omitempty"`
}

func (a LoginAppearance) CopyFor(language string) LoginCopy {
	copy, fallback := a.Copy[language], a.Copy["en"]
	if copy.Title == "" {
		copy.Title = fallback.Title
	}
	if copy.Description == "" {
		copy.Description = fallback.Description
	}
	if copy.Button == "" {
		copy.Button = fallback.Button
	}
	return copy
}

func DefaultTheme(clientID string) Theme {
	return Theme{
		ClientID: clientID,
		Light: ThemeCSS{
			Text:      []uint16{200, 5, 37},
			TextHigh:  []uint16{200, 15, 25},
			Bg:        []uint16{34, 25, 97},
			BgHigh:    []uint16{34, 20, 95},
			Action:    []uint16{34, 100, 40},
			Accent:    []uint16{265, 100, 53},
			Error:     []uint16{15, 100, 37},
			BtnText:   "#10231b",
			ThemeSun:  "hsla(var(--action) / .7)",
			ThemeMoon: "hsla(var(--accent) / .85)",
		},
		Dark: ThemeCSS{
			Text:      []uint16{34, 5, 75},
			TextHigh:  []uint16{34, 7, 90},
			Bg:        []uint16{200, 40, 6},
			BgHigh:    []uint16{200, 20, 17},
			Action:    []uint16{34, 100, 59},
			Accent:    []uint16{265, 100, 53},
			Error:     []uint16{15, 100, 70},
			BtnText:   "hsl(var(--bg))",
			ThemeSun:  "hsla(var(--action) / .7)",
			ThemeMoon: "hsla(var(--accent) / .85)",
		},
		BorderRadius: "5px",
	}
}

func (t Theme) Validate() error {
	if !clientIDPattern.MatchString(t.ClientID) {
		return ErrInvalidTheme
	}
	if utf8.RuneCountInString(t.BrandName) > 120 || (t.BrandName != "" && strings.TrimSpace(t.BrandName) == "") || strings.ContainsFunc(t.BrandName, unicode.IsControl) {
		return ErrInvalidTheme
	}
	if _, ok := fontStackFor(t.FontFamily); !ok {
		return ErrInvalidTheme
	}
	if err := t.Light.Validate(); err != nil {
		return err
	}
	if err := t.Dark.Validate(); err != nil {
		return err
	}
	if !validCSSValue(t.BorderRadius) {
		return ErrInvalidTheme
	}
	if t.Login != nil {
		if (t.Login.LogoAlignment != "" && t.Login.LogoAlignment != "start" && t.Login.LogoAlignment != "center") || (t.Login.CardWidth != 0 && (t.Login.CardWidth < 320 || t.Login.CardWidth > 640)) {
			return ErrInvalidTheme
		}
		for language, copy := range t.Login.Copy {
			if (language != "en" && language != "ko") || utf8.RuneCountInString(copy.Title) > 120 || utf8.RuneCountInString(copy.Description) > 500 || utf8.RuneCountInString(copy.Button) > 60 {
				return ErrInvalidTheme
			}
		}
	}
	return nil
}

// ValidateWriteContrast rejects new themes whose core text or focus colors
// would be unreadable. Stored themes intentionally skip this check so that
// they remain loadable and CSS can render them with accessible fallbacks.
func (t Theme) ValidateWriteContrast() error {
	for _, theme := range []ThemeCSS{t.Light, t.Dark} {
		if !hasContrast(theme.Text, theme.Bg, 4.5) || !hasContrast(theme.TextHigh, theme.Bg, 4.5) || !hasContrast(theme.Error, theme.Bg, 4.5) || !hasContrast(theme.Action, theme.Bg, 3) {
			return ErrThemeLowContrast
		}
		if !hasContrast(theme.Text, theme.BgHigh, 4.5) || !hasContrast(theme.TextHigh, theme.BgHigh, 4.5) || !hasContrast(theme.Error, theme.BgHigh, 4.5) || !hasContrast(theme.Action, theme.BgHigh, 3) {
			return ErrThemeLowContrast
		}
		if buttonText, known := cssColorRGB(theme.BtnText, theme); known && contrast(buttonText, hslRGB(theme.Action)) < 4.5 {
			return ErrThemeLowContrast
		}
		if len(theme.Approved) == 3 && (!hasContrast(theme.Approved, theme.Bg, 4.5) || !hasContrast(theme.Approved, theme.BgHigh, 4.5)) {
			return ErrThemeLowContrast
		}
		if len(theme.Warning) == 3 && (!hasContrast(theme.Warning, theme.Bg, 4.5) || !hasContrast(theme.Warning, theme.BgHigh, 4.5)) {
			return ErrThemeLowContrast
		}
	}
	return nil
}

func (t ThemeCSS) Validate() error {
	// The pinned v0.36.2 source validates accent twice and omits action. Keep
	// the three-element shape check for every field, but preserve that range
	// validation quirk for action.
	allValues := [][]uint16{t.Text, t.TextHigh, t.Bg, t.BgHigh, t.Action, t.Accent, t.Error}
	for _, values := range allValues {
		if len(values) != 3 {
			return ErrInvalidTheme
		}
	}
	for _, values := range [][]uint16{t.Text, t.TextHigh, t.Bg, t.BgHigh, t.Accent, t.Error} {
		if values[0] > 360 || values[1] > 100 || values[2] > 100 {
			return ErrInvalidTheme
		}
	}
	for _, optional := range [][]uint16{t.Approved, t.Warning} {
		if len(optional) == 0 {
			continue
		}
		if len(optional) != 3 || optional[0] > 360 || optional[1] > 100 || optional[2] > 100 {
			return ErrInvalidTheme
		}
	}
	if !validCSSValue(t.BtnText) || !validCSSValue(t.ThemeSun) || !validCSSValue(t.ThemeMoon) {
		return ErrInvalidTheme
	}
	return nil
}

func fontStackFor(name string) (string, bool) {
	switch name {
	case "", "default":
		return "", true
	case "system":
		return "system-ui, -apple-system, sans-serif", true
	case "geist":
		return "Geist, system-ui, sans-serif", true
	case "pretendard":
		return "Pretendard, system-ui, sans-serif", true
	case "inter":
		return "Inter, system-ui, sans-serif", true
	case "mono":
		return "'Geist Mono', 'JetBrains Mono', ui-monospace, monospace", true
	default:
		return "", false
	}
}

func validCSSValue(value string) bool {
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, value)
	return cssValuePattern.MatchString(value)
}

// CSS returns the pinned full light/dark stylesheet. Invalid values are not
// rendered, which keeps callers from emitting unvalidated CSS.
func (t Theme) CSS() string {
	if t.Validate() != nil {
		return ""
	}
	var css strings.Builder
	css.WriteString("body{")
	appendThemeCSS(&css, t.Light)
	css.WriteString("--border-radius:")
	css.WriteString(t.BorderRadius)
	if stack, ok := fontStackFor(t.FontFamily); ok && stack != "" {
		css.WriteString(";--brand-font:")
		css.WriteString(stack)
	}
	css.WriteString(";}")

	css.WriteString(".theme-dark{")
	appendThemeCSS(&css, t.Dark)
	css.WriteString("}")

	css.WriteString("@media (prefers-color-scheme: dark){")
	css.WriteString("body{")
	appendThemeCSS(&css, t.Dark)
	css.WriteString("}")
	css.WriteString(".theme-light{")
	appendThemeCSS(&css, t.Light)
	css.WriteString("}")
	css.WriteString("}")
	if t.Login != nil {
		if t.Login.CardWidth != 0 {
			width := strconv.Itoa(t.Login.CardWidth)
			css.WriteString("body.auth-page .auth-panel{width:min(100%,640px);max-width:")
			css.WriteString(width)
			css.WriteString("px}")
		}
		if t.Login.LogoAlignment == "center" {
			css.WriteString("body.auth-page .auth-topbar .auth-brand{margin-inline:auto}")
		}
	}
	return css.String()
}

// EmailCSS returns the light theme variable declarations used inside an
// email body rule.
func (t Theme) EmailCSS() string {
	if t.Validate() != nil {
		return ""
	}
	var css strings.Builder
	appendThemeCSS(&css, t.Light)
	css.WriteString("--border-radius:")
	css.WriteString(t.BorderRadius)
	css.WriteString(";")
	return css.String()
}

func appendThemeCSS(css *strings.Builder, theme ThemeCSS) {
	theme = theme.accessible()
	for _, value := range []struct {
		name string
		data []uint16
	}{
		{"--text:", theme.Text},
		{"--text-high:", theme.TextHigh},
		{"--bg:", theme.Bg},
		{"--bg-high:", theme.BgHigh},
		{"--action:", theme.Action},
		{"--accent:", theme.Accent},
		{"--error:", theme.Error},
	} {
		css.WriteString(value.name)
		css.WriteString(strconv.Itoa(int(value.data[0])))
		css.WriteByte(' ')
		css.WriteString(strconv.Itoa(int(value.data[1])))
		css.WriteByte(' ')
		css.WriteString(strconv.Itoa(int(value.data[2])))
		css.WriteByte(';')
	}
	css.WriteString("--btn-text:")
	css.WriteString(theme.BtnText)
	css.WriteString(";--theme-sun:")
	css.WriteString(theme.ThemeSun)
	css.WriteString(";--theme-moon:")
	css.WriteString(theme.ThemeMoon)
	css.WriteByte(';')
	for _, opt := range []struct {
		name string
		data []uint16
	}{
		{"approved", theme.Approved},
		{"warning", theme.Warning},
	} {
		if len(opt.data) == 3 {
			hsl := strconv.Itoa(int(opt.data[0])) + " " + strconv.Itoa(int(opt.data[1])) + "% " + strconv.Itoa(int(opt.data[2])) + "%"
			css.WriteString("--" + opt.name + ":hsl(" + hsl + ");--" + opt.name + "-tint:hsl(" + hsl + " / .12);")
		}
	}
}

func (t ThemeCSS) accessible() ThemeCSS {
	t.Text = accessibleHSL(t.Text, t.Bg, 4.5)
	t.TextHigh = accessibleHSL(t.TextHigh, t.Bg, 4.5)
	t.Action = accessibleHSL(t.Action, t.Bg, 3)
	t.Error = accessibleHSL(t.Error, t.Bg, 4.5)
	if !hasContrast(t.Text, t.BgHigh, 4.5) || !hasContrast(t.TextHigh, t.BgHigh, 4.5) || !hasContrast(t.Error, t.BgHigh, 4.5) || !hasContrast(t.Action, t.BgHigh, 3) {
		t.BgHigh = t.Bg
	}
	t.BtnText = accessibleButtonText(t.BtnText, t)
	return t
}

func accessibleHSL(foreground, background []uint16, minimum float64) []uint16 {
	if hasContrast(foreground, background, minimum) {
		return foreground
	}
	if contrast(rgb{0, 0, 0}, hslRGB(background)) >= contrast(rgb{1, 1, 1}, hslRGB(background)) {
		return []uint16{0, 0, 0}
	}
	return []uint16{0, 0, 100}
}

func accessibleButtonText(value string, theme ThemeCSS) string {
	foreground, ok := cssColorRGB(value, theme)
	if !ok || contrast(foreground, hslRGB(theme.Action)) >= 4.5 {
		return value
	}
	if contrast(rgb{0, 0, 0}, hslRGB(theme.Action)) >= contrast(rgb{1, 1, 1}, hslRGB(theme.Action)) {
		return "#000"
	}
	return "#fff"
}

func cssColorRGB(value string, theme ThemeCSS) (rgb, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "black":
		return rgb{0, 0, 0}, true
	case "white":
		return rgb{1, 1, 1}, true
	case "hsl(var(--bg))":
		return hslRGB(theme.Bg), true
	case "hsl(var(--text))":
		return hslRGB(theme.Text), true
	case "hsl(var(--text-high))":
		return hslRGB(theme.TextHigh), true
	}
	if strings.HasPrefix(value, "rgb(") && strings.HasSuffix(value, ")") {
		body := strings.TrimSpace(value[4 : len(value)-1])
		var parts []string
		if strings.Contains(body, ",") {
			parts = strings.Split(body, ",")
		} else {
			parts = strings.Fields(body)
		}
		if len(parts) == 3 {
			var channels [3]float64
			firstPercent := strings.HasSuffix(strings.TrimSpace(parts[0]), "%")
			for i, part := range parts {
				part = strings.TrimSpace(part)
				if strings.Contains(body, ",") && strings.HasSuffix(part, "%") != firstPercent {
					return rgb{}, false
				}
				scale := 255.0
				if strings.HasSuffix(part, "%") {
					part, scale = strings.TrimSuffix(part, "%"), 100
				}
				n, err := strconv.ParseFloat(part, 64)
				if !cssNumberPattern.MatchString(part) {
					return rgb{}, false
				}
				if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
					return rgb{}, false
				}
				channels[i] = math.Max(0, math.Min(scale, n)) / scale
			}
			return rgb{channels[0], channels[1], channels[2]}, true
		}
	}
	if (len(value) != 4 && len(value) != 7) || !strings.HasPrefix(value, "#") {
		return rgb{}, false
	}
	if len(value) == 4 {
		value = "#" + strings.Repeat(string(value[1]), 2) + strings.Repeat(string(value[2]), 2) + strings.Repeat(string(value[3]), 2)
	}
	parsed, err := strconv.ParseUint(value[1:], 16, 32)
	if err != nil {
		return rgb{}, false
	}
	return rgb{float64(parsed>>16) / 255, float64((parsed>>8)&0xff) / 255, float64(parsed&0xff) / 255}, true
}

type rgb struct{ red, green, blue float64 }

func hasContrast(foreground, background []uint16, minimum float64) bool {
	return contrast(hslRGB(foreground), hslRGB(background)) >= minimum
}

func contrast(first, second rgb) float64 {
	firstLum, secondLum := luminance(first), luminance(second)
	if firstLum < secondLum {
		firstLum, secondLum = secondLum, firstLum
	}
	return (firstLum + 0.05) / (secondLum + 0.05)
}

func luminance(value rgb) float64 {
	linear := func(component float64) float64 {
		if component <= 0.04045 {
			return component / 12.92
		}
		return math.Pow((component+0.055)/1.055, 2.4)
	}
	return 0.2126*linear(value.red) + 0.7152*linear(value.green) + 0.0722*linear(value.blue)
}

func hslRGB(value []uint16) rgb {
	if len(value) != 3 {
		return rgb{}
	}
	hue := float64(value[0]%360) / 60
	saturation := float64(min(value[1], 100)) / 100
	lightness := float64(min(value[2], 100)) / 100
	chroma := (1 - math.Abs(2*lightness-1)) * saturation
	x := chroma * (1 - math.Abs(math.Mod(hue, 2)-1))
	match := rgb{}
	switch {
	case hue < 1:
		match = rgb{chroma, x, 0}
	case hue < 2:
		match = rgb{x, chroma, 0}
	case hue < 3:
		match = rgb{0, chroma, x}
	case hue < 4:
		match = rgb{0, x, chroma}
	case hue < 5:
		match = rgb{x, 0, chroma}
	default:
		match = rgb{chroma, 0, x}
	}
	minimum := lightness - chroma/2
	return rgb{match.red + minimum, match.green + minimum, match.blue + minimum}
}
