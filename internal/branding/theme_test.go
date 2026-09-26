package branding

import (
	"encoding/json"
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
	wantEmail := "--text:200 5 37;--text-high:200 15 25;--bg:34 25 97;--bg-high:34 20 90;--action:34 100 40;--accent:265 100 53;--error:15 100 37;--btn-text:white;--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);--border-radius:5px;"
	if got := theme.EmailCSS(); got != wantEmail {
		t.Fatalf("EmailCSS()=%q want %q", got, wantEmail)
	}
	wantCSS := "body{" + wantEmail + "}.theme-dark{--text:34 5 75;--text-high:34 7 90;--bg:200 40 6;--bg-high:200 20 17;--action:34 100 59;--accent:265 100 53;--error:15 100 37;--btn-text:hsl(var(--bg));--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);}@media (prefers-color-scheme: dark){body{--text:34 5 75;--text-high:34 7 90;--bg:200 40 6;--bg-high:200 20 17;--action:34 100 59;--accent:265 100 53;--error:15 100 37;--btn-text:hsl(var(--bg));--theme-sun:hsla(var(--action) / .7);--theme-moon:hsla(var(--accent) / .85);}.theme-light{" + wantEmail[:len(wantEmail)-len("--border-radius:5px;")] + "}}"
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
	if got := theme.CSS(); !strings.Contains(got, "--action:65535 65535 65535;") {
		t.Fatalf("CSS() did not preserve source-accepted action: %q", got)
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
