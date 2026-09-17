package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmailTemplatesDefaultsAndPartialOverride(t *testing.T) {
	defaults, err := LoadEmailTemplates("")
	if err != nil {
		t.Fatal(err)
	}
	if got := defaults.PasswordReset("ko").Subject; got != "비밀번호 초기화 요청" {
		t.Fatalf("Korean default subject = %q", got)
	}
	if got := defaults.PasswordReset("missing").Subject; got != "Password Reset Request" {
		t.Fatalf("fallback subject = %q", got)
	}
	if _, err := defaults.PasswordResetExact("missing"); err == nil {
		t.Fatal("PasswordResetExact() accepted an unsupported language")
	}
	if got := defaults.PasswordNew("ko").Subject; got != "새 비밀번호" {
		t.Fatalf("Korean new-password subject = %q", got)
	}
	if got := defaults.PasswordNew("missing").Subject; got != "New Password" {
		t.Fatalf("new-password fallback subject = %q", got)
	}
	if got := defaults.AlreadyRegistered("de").Subject; got != "E-Mail bereits registriert" {
		t.Fatalf("registered-already German subject = %q", got)
	}

	path := writeEmailTemplates(t, `[[templates]]
lang = "ko"
typ = "password_reset"
subject = "사용자 지정"
text = "한 줄\n다음 줄"

[[templates]]
lang = "ko"
typ = "password_new"
subject = "새 사용자 지정"

[[templates]]
lang = "ko"
typ = "registered_already"
subject = "기존 사용자 지정"
`)
	loaded, err := LoadEmailTemplates(path)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.PasswordReset("ko")
	if got.Subject != "사용자 지정" || got.Text != "한 줄\n다음 줄" || got.Button != "비밀번호 초기화" {
		t.Fatalf("partial Korean template = %#v", got)
	}
	if got := loaded.PasswordNew("ko"); got.Subject != "새 사용자 지정" || got.Button != "비밀번호 설정" {
		t.Fatalf("partial new-password template = %#v", got)
	}
	if got := loaded.AlreadyRegistered("ko"); got.Subject != "기존 사용자 지정" || got.Text == "" {
		t.Fatalf("partial registered-already template = %#v", got)
	}
}

func TestLoadEmailTemplatesRejectsInvalidInput(t *testing.T) {
	for name, content := range map[string]string{
		"unknown type": `[[templates]]
lang = "en"
typ = "other"`,
		"unsupported language": `[[templates]]
lang = "es"
typ = "password_reset"`,
		"missing language": `[[templates]]
typ = "password_reset"`,
		"missing type": `[[templates]]
lang = "en"`,
		"duplicate pair": `[[templates]]
lang = "en"
typ = "password_reset"
[[templates]]
lang = "en"
typ = "password_reset"`,
		"duplicate new pair": `[[templates]]
lang = "en"
typ = "password_new"
[[templates]]
lang = "en"
typ = "password_new"`,
		"duplicate registered pair": `[[templates]]
lang = "en"
typ = "registered_already"
[[templates]]
lang = "en"
typ = "registered_already"`,
		"unknown field": `[[templates]]
lang = "en"
typ = "password_reset"
button = "not configurable"`,
		"subject injection": `[[templates]]
lang = "en"
typ = "password_reset"
subject = "safe\r\nBcc: victim@example.test"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadEmailTemplates(writeEmailTemplates(t, content)); err == nil {
				t.Fatal("LoadEmailTemplates() succeeded")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "too-large.toml")
	if err := os.WriteFile(path, []byte(strings.Repeat("#", maxEmailTemplatesFileSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEmailTemplates(path); err == nil {
		t.Fatal("LoadEmailTemplates() accepted oversized file")
	}
}

func TestFixedPasswordResetLayoutsEscapeHTML(t *testing.T) {
	template := defaultEmailTemplates().PasswordReset("en")
	template.Header = `<img src=x onerror=alert(1)>`
	template.Text = `<script>alert(1)</script>`
	data := passwordResetData{EmailTemplate: template, ResetURL: "https://auth.example.test/reset?a=1&b=2", ExpiresAt: "2030-01-02T03:04:05Z"}
	html, err := renderPasswordResetHTML(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img src=x") || !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "a=1&amp;b=2") {
		t.Fatalf("unsafe HTML output: %s", html)
	}
	text, err := renderPasswordResetText(data)
	if err != nil || !strings.Contains(text, `<script>alert(1)</script>`) {
		t.Fatalf("text output = %q, err=%v", text, err)
	}
}

func TestFixedPasswordNewLayoutsEscapeHTML(t *testing.T) {
	template := defaultEmailTemplates().PasswordNew("en")
	template.Header = `<img src=x onerror=alert(1)>`
	data := passwordNewData{EmailTemplate: template, ResetURL: "https://auth.example.test/new?a=1&b=2", ExpiresAt: "2030-01-02T03:04:05Z"}
	html, err := renderPasswordNewHTML(data)
	if err != nil || strings.Contains(html, "<img src=x") || !strings.Contains(html, "a=1&amp;b=2") {
		t.Fatalf("unsafe new-password HTML output: %s, err=%v", html, err)
	}
	text, err := renderPasswordNewText(data)
	if err != nil || !strings.Contains(text, template.Header) {
		t.Fatalf("new-password text output = %q, err=%v", text, err)
	}
}

func TestFixedRegisteredAlreadyLayoutsEscapeHTML(t *testing.T) {
	template := defaultEmailTemplates().AlreadyRegistered("en")
	template.Text = `<script>alert(1)</script>`
	html, err := renderRegisteredAlreadyHTML(registeredAlreadyData{EmailTemplate: template})
	if err != nil || strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("unsafe registered-already HTML output: %s, err=%v", html, err)
	}
}

func writeEmailTemplates(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "templates.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
