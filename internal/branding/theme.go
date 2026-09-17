package branding

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	clientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,256}$`)
	cssValuePattern = regexp.MustCompile(`^[a-z0-9-,.#()%/\s]+$`)
)

var ErrInvalidTheme = errors.New("invalid theme")

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
	BtnText   string   `json:"btn_text"`
	ThemeSun  string   `json:"theme_sun"`
	ThemeMoon string   `json:"theme_moon"`
}

type Theme struct {
	ClientID     string   `json:"client_id"`
	Light        ThemeCSS `json:"light"`
	Dark         ThemeCSS `json:"dark"`
	BorderRadius string   `json:"border_radius"`
}

func DefaultTheme(clientID string) Theme {
	return Theme{
		ClientID: clientID,
		Light: ThemeCSS{
			Text:      []uint16{200, 5, 37},
			TextHigh:  []uint16{200, 15, 25},
			Bg:        []uint16{34, 25, 97},
			BgHigh:    []uint16{34, 20, 90},
			Action:    []uint16{34, 100, 40},
			Accent:    []uint16{265, 100, 53},
			Error:     []uint16{15, 100, 37},
			BtnText:   "white",
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
			Error:     []uint16{15, 100, 37},
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
	if err := t.Light.Validate(); err != nil {
		return err
	}
	if err := t.Dark.Validate(); err != nil {
		return err
	}
	if !validCSSValue(t.BorderRadius) {
		return ErrInvalidTheme
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
	if !validCSSValue(t.BtnText) || !validCSSValue(t.ThemeSun) || !validCSSValue(t.ThemeMoon) {
		return ErrInvalidTheme
	}
	return nil
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
}
