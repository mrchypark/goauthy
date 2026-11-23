package branding

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDefaultThemeAndCSS(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme("client-1")
	if err := theme.Validate(); err != nil {
		t.Fatal(err)
	}
	if theme.BorderRadius != "5px" || len(theme.Light.Text) != 3 || theme.Light.Text[0] != 200 || theme.Dark.Text[0] != 34 {
		t.Fatalf("unexpected defaults: %#v", theme)
	}
	wantEmail := "--text:200 5 37;--text-high:200 15 25;--bg:34 25 97;--bg-high:34 20 95;--action:34 100 40;--accent:265 100 53;--error:15 100 37;--btn-text:#10231b;--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);--border-radius:5px;"
	if got := theme.EmailCSS(); got != wantEmail {
		t.Fatalf("EmailCSS()=%q want %q", got, wantEmail)
	}
	wantCSS := "body{" + wantEmail + "}.theme-dark{--text:34 5 75;--text-high:34 7 90;--bg:200 40 6;--bg-high:200 20 17;--action:34 100 59;--accent:265 100 53;--error:15 100 37;--btn-text:hsl(var(--bg));--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);}@media (prefers-color-scheme: dark){body{--text:34 5 75;--text-high:34 7 90;--bg:200 40 6;--bg-high:200 20 17;--action:34 100 59;--accent:265 100 53;--error:15 100 37;--btn-text:hsl(var(--bg));--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);}.theme-light{" + wantEmail[:len(wantEmail)-len("--border-radius:5px;")] + "}}"
	wantCSS = strings.ReplaceAll(wantCSS, "--accent:265 100 53;--error:15 100 37;--btn-text:hsl(var(--bg));", "--accent:265 100 53;--error:15 100 70;--btn-text:hsl(var(--bg));")
	if got := theme.CSS(); got != wantCSS {
		t.Fatalf("CSS()=%q want %q", got, wantCSS)
	}
}

func TestThemeValidateRejectsMalformedJSONAndCSS(t *testing.T) {
	t.Parallel()
	valid := `{"client_id":"client-1","light":{"text":[1,2,3],"text_high":[1,2,3],"bg":[1,2,3],"bg_high":[1,2,3],"action":[1,2,3],"accent":[1,2,3],"error":[1,2,3],"btn_text":"white","theme_sun":"none","theme_moon":"none"},"dark":{"text":[1,2,3],"text_high":[1,2,3],"bg":[1,2,3],"bg_high":[1,2,3],"action":[1,2,3],"accent":[1,2,3],"error":[1,2,3],"btn_text":"white","theme_sun":"none","theme_moon":"none"},"border_radius":"5px"}`
	for name, input := range map[string]string{
		"valid":                   valid,
		"missing array":           strings.Replace(valid, `"text":[1,2,3],`, "", 1),
		"wrong array length":      strings.Replace(valid, `"text":[1,2,3]`, `"text":[1,2]`, 1),
		"hue out of range":        strings.Replace(valid, `"text":[1,2,3]`, `"text":[361,2,3]`, 1),
		"css injection":           strings.Replace(valid, `"btn_text":"white"`, `"btn_text":"white;body{display:none}"`, 1),
		"missing required string": strings.Replace(valid, `,"theme_moon":"none"`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			var theme Theme
			if err := json.Unmarshal([]byte(input), &theme); err != nil {
				t.Fatal(err)
			}
			err := theme.Validate()
			if (name == "valid") != (err == nil) {
				t.Fatalf("Validate()=%v", err)
			}
			if name != "valid" && theme.CSS() != "" {
				t.Fatalf("CSS() rendered invalid theme: %q", theme.CSS())
			}
		})
	}
}

func TestThemeValidateActionOmissionAndClientID(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme("client-1")
	theme.Light.Action = []uint16{65535, 65535, 65535}
	if err := theme.Validate(); err != nil {
		t.Fatalf("source-omitted action range rejected: %v", err)
	}
	if got := theme.CSS(); !strings.Contains(got, "--action:0 0 0;") {
		t.Fatalf("CSS() did not replace unreadable source-accepted action: %q", got)
	}
	theme.Light.Accent = []uint16{65535, 65535, 65535}
	if err := theme.Validate(); err == nil {
		t.Fatal("accent range out of bounds accepted")
	}
	theme = DefaultTheme("client-1")
	theme.ClientID = "x"
	if err := theme.Validate(); err == nil {
		t.Fatal("short client ID accepted")
	}
	theme = DefaultTheme("client-1")
	theme.ClientID = "client;1"
	if err := theme.Validate(); err == nil {
		t.Fatal("invalid client ID accepted")
	}
}

func TestThemeContrastValidationAndStoredThemeFallback(t *testing.T) {
	t.Parallel()
	if err := DefaultTheme("client-1").ValidateWriteContrast(); err != nil {
		t.Fatalf("default write contrast: %v", err)
	}
	theme := DefaultTheme("client-1")
	theme.Light.Bg = []uint16{0, 0, 100}
	theme.Light.Text = []uint16{0, 0, 100}
	theme.Light.TextHigh = []uint16{0, 0, 100}
	theme.Light.Action = []uint16{0, 0, 100}
	theme.Light.Error = []uint16{0, 0, 100}
	theme.Light.BtnText = "white"
	if err := theme.Validate(); err != nil {
		t.Fatalf("stored theme validation: %v", err)
	}
	if err := theme.ValidateWriteContrast(); !errors.Is(err, ErrThemeLowContrast) {
		t.Fatalf("write contrast error=%v", err)
	}
	css := theme.CSS()
	for _, want := range []string{"--text:0 0 0;", "--text-high:0 0 0;", "--action:0 0 0;", "--error:0 0 0;", "--btn-text:white;"} {
		if !strings.Contains(css, want) {
			t.Errorf("accessible CSS missing %q: %s", want, css)
		}
	}
}

func TestRaisedBackgroundAndRGBButtonContrast(t *testing.T) {
	theme := DefaultTheme("client-1")
	theme.Light.BgHigh = []uint16{0, 0, 0}
	if err := theme.ValidateWriteContrast(); !errors.Is(err, ErrThemeLowContrast) {
		t.Fatalf("unsafe raised background accepted: %v", err)
	}
	rendered := theme.Light.accessible()
	if !hasContrast(rendered.Text, rendered.BgHigh, 4.5) || !hasContrast(rendered.TextHigh, rendered.BgHigh, 4.5) || !hasContrast(rendered.Action, rendered.BgHigh, 3) {
		t.Fatalf("unsafe raised background in rendered theme: %+v", rendered)
	}
	if theme.Light.BgHigh[2] != 0 {
		t.Fatal("rendering changed stored color")
	}
	theme = DefaultTheme("client-1")
	theme.Light.BtnText = "rgb(0, 0, 0)"
	if err := theme.ValidateWriteContrast(); err != nil {
		t.Fatalf("safe rgb rejected: %v", err)
	}
	if got := theme.Light.accessible().BtnText; got != "rgb(0, 0, 0)" {
		t.Fatalf("safe rgb changed: %q", got)
	}
	theme.Light.BtnText = "rgb(0 0 0)"
	if got := theme.Light.accessible().BtnText; got != theme.Light.BtnText {
		t.Fatalf("safe modern rgb changed: %q", got)
	}
	if _, ok := cssColorRGB("rgb(255, 0%, 0)", theme.Light); ok {
		t.Fatal("invalid mixed-unit comma RGB accepted")
	}
	theme.Light.BtnText = "rgb(0e2 0e2 0e2)"
	if got := theme.Light.accessible().BtnText; got != theme.Light.BtnText {
		t.Fatalf("valid exponent RGB changed: %q", got)
	}
	theme.Light.BtnText = "rgb(100%, 100%, 100%)"
	if err := theme.ValidateWriteContrast(); !errors.Is(err, ErrThemeLowContrast) {
		t.Fatalf("unsafe rgb accepted: %v", err)
	}
}

func TestComplexButtonColorsRemainUnchanged(t *testing.T) {
	for _, value := range []string{"rgba(255, 255, 255, 0.9)", "hsl(210, 50%, 90%)", "color-mix(in srgb, white 80%, black)"} {
		t.Run(value, func(t *testing.T) {
			theme := DefaultTheme("client-1")
			theme.Light.BtnText = value
			if err := theme.Validate(); err != nil {
				t.Fatalf("valid theme rejected: %v", err)
			}
			if err := theme.ValidateWriteContrast(); err != nil {
				t.Fatalf("unverifiable color rejected: %v", err)
			}
			if got := theme.Light.accessible().BtnText; got != value {
				t.Fatalf("button color changed to %q", got)
			}
			if !strings.Contains(theme.CSS(), "--btn-text:"+value+";") {
				t.Fatal("generated CSS does not preserve the button color")
			}
			if !strings.Contains(theme.EmailCSS(), "--btn-text:"+value+";") {
				t.Fatal("email CSS does not preserve the button color")
			}
		})
	}
}

func TestErrorTextRequiresFourPointFiveContrast(t *testing.T) {
	theme := DefaultTheme("client-1")
	theme.Light.Error = []uint16{0, 0, 55}
	if ratio := contrast(hslRGB(theme.Light.Error), hslRGB(theme.Light.Bg)); ratio < 3 || ratio >= 4.5 {
		t.Fatalf("fixture contrast %.2f outside range", ratio)
	}
	if err := theme.ValidateWriteContrast(); !errors.Is(err, ErrThemeLowContrast) {
		t.Fatalf("low-contrast error accepted: %v", err)
	}
	rendered := theme.Light.accessible()
	if ratio := contrast(hslRGB(rendered.Error), hslRGB(rendered.Bg)); ratio < 4.5 {
		t.Fatalf("rendered error contrast %.2f", ratio)
	}
	if theme.Light.Error[2] != 55 {
		t.Fatal("render changed stored error color")
	}
}

func TestThemeCSSValidationMatchesRustWhitespace(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme("client-1")
	theme.Light.ThemeSun = "hsla(var(--action)\u00a0/\u000b.7)"
	if err := theme.Validate(); err != nil {
		t.Fatalf("Unicode whitespace rejected: %v", err)
	}
	if !strings.Contains(theme.EmailCSS(), "hsla(var(--action)\u00a0/\u000b.7)") {
		t.Fatalf("EmailCSS() did not preserve original whitespace: %q", theme.EmailCSS())
	}
	theme.Light.ThemeSun = "hsla(var(--action)\u200b/.7)"
	if err := theme.Validate(); err == nil {
		t.Fatal("non-White_Space rune accepted")
	}
}

func TestLoginAppearanceValidationCSSAndCopyFallback(t *testing.T) {
	theme := DefaultTheme("client-1")
	data, err := json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"login"`) {
		t.Fatalf("nil login appearance was not omitted: %s", data)
	}
	theme.Login = &LoginAppearance{
		Copy: map[string]LoginCopy{
			"en": {Title: "Welcome", Description: "<b>Sign in</b>", Button: "Continue"},
			"ko": {Title: "환영합니다", Button: "계속"},
		},
		LogoAlignment: "center",
		CardWidth:     640,
	}
	if err := theme.Validate(); err != nil {
		t.Fatal(err)
	}
	gotCopy := theme.Login.CopyFor("ko")
	if gotCopy.Title != "환영합니다" || gotCopy.Description != "<b>Sign in</b>" || gotCopy.Button != "계속" {
		t.Fatalf("CopyFor(ko)=%+v", gotCopy)
	}
	css := theme.CSS()
	for _, rule := range []string{
		"body.auth-page .auth-panel{width:min(100%,640px);max-width:640px}",
		"body.auth-page .auth-topbar .auth-brand{margin-inline:auto}",
	} {
		if !strings.Contains(css, rule) {
			t.Errorf("CSS missing %q: %s", rule, css)
		}
	}
	data, err = json.Marshal(theme)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Theme
	if err := json.Unmarshal(data, &roundTrip); err != nil || roundTrip.Login == nil || roundTrip.Login.Copy["ko"].Title != "환영합니다" {
		t.Fatalf("JSON round trip: theme=%+v err=%v", roundTrip, err)
	}
}

func TestLoginAppearanceRejectsInvalidValues(t *testing.T) {
	for name, login := range map[string]*LoginAppearance{
		"unsupported language": {Copy: map[string]LoginCopy{"fr": {Title: "Bonjour"}}},
		"title too long":       {Copy: map[string]LoginCopy{"en": {Title: strings.Repeat("한", 121)}}},
		"description too long": {Copy: map[string]LoginCopy{"ko": {Description: strings.Repeat("x", 501)}}},
		"button too long":      {Copy: map[string]LoginCopy{"en": {Button: strings.Repeat("x", 61)}}},
		"invalid alignment":    {LogoAlignment: "end"},
		"card too narrow":      {CardWidth: 319},
		"card too wide":        {CardWidth: 641},
	} {
		t.Run(name, func(t *testing.T) {
			theme := DefaultTheme("client-1")
			theme.Login = login
			if err := theme.Validate(); err == nil {
				t.Fatal("invalid login appearance accepted")
			}
			if theme.CSS() != "" {
				t.Fatal("invalid login appearance produced CSS")
			}
		})
	}
}
