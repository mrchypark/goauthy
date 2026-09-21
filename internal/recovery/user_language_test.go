package recovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type languageSender struct{ new, reset, already []Message }

func (s *languageSender) SendEmailChange(context.Context, EmailChangeMessage) error { return nil }

func (s *languageSender) SendPasswordNew(_ context.Context, m Message) error {
	s.new = append(s.new, m)
	return nil
}
func (s *languageSender) SendPasswordReset(_ context.Context, m Message) error {
	s.reset = append(s.reset, m)
	return nil
}
func (s *languageSender) SendAlreadyRegistered(_ context.Context, m Message) error {
	s.already = append(s.already, m)
	return nil
}

func TestOpenRegistrationPersistsLocale(t *testing.T) {
	t.Parallel()
	s, _ := testService(t, "subject-1", "alice")
	sender := &languageSender{}
	s.sender = sender
	enableOpenRegistration(t, s, ExactRedirectURIs(nil))
	request := func(email, locale string) {
		challenge, err := s.pow.Issue(context.Background(), s.powDifficulty, s.powTTL)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/register", strings.NewReader(fmt.Sprintf(`{"email":%q,"given_name":"Locale","pow":%q}`, email, solveProof(t, challenge))))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept-Language", "fr") // Cookie must take precedence.
		r.RemoteAddr = "192.0.2.102:1234"
		r.AddCookie(&http.Cookie{Name: "locale", Value: locale})
		response := httptest.NewRecorder()
		s.RegisterOpen(response, r)
		if response.Code != http.StatusNoContent {
			t.Fatalf("registration status=%d", response.Code)
		}
	}
	request("locale@example.test", "ko-KR")
	messages := sender.new
	if len(messages) != 1 || messages[0].Language != "ko" {
		t.Fatalf("registration language=%#v", messages)
	}
	parts := strings.Split(messages[0].ResetURL, "/")
	subject := parts[len(parts)-3]
	lang, err := s.identity.UserLanguage(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if lang != "ko" {
		t.Fatalf("stored language=%q", lang)
	}
	request("locale@example.test", "de-DE")
	if len(sender.already) != 1 || sender.already[0].Language != "ko" {
		t.Fatalf("duplicate language=%#v", sender.already)
	}
	challenge, err := s.pow.Issue(context.Background(), s.powDifficulty, s.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/users/register", strings.NewReader(fmt.Sprintf(`{"email":"header@example.test","given_name":"Locale","pow":%q}`, solveProof(t, challenge))))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Language", "zh-Hans")
	r.RemoteAddr = "192.0.2.104:1234"
	response := httptest.NewRecorder()
	s.RegisterOpen(response, r)
	if response.Code != http.StatusNoContent || len(sender.new) != 2 || sender.new[1].Language != "zhhans" {
		t.Fatalf("header registration status=%d messages=%#v", response.Code, sender.new)
	}
}

func TestStoredLanguageUsedForResetMail(t *testing.T) {
	t.Parallel()
	s, _ := testService(t, "subject-1", "alice")
	sender := &languageSender{}
	s.sender = sender
	if err := s.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{RequestID: "language-legacy", SQL: `UPDATE identity_users SET language='ko' WHERE subject=?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	resetRequest(t, s, "alice@example.test", "192.0.2.103:1000", "")
	if len(sender.reset) != 1 || sender.reset[0].Language != "ko" {
		t.Fatalf("reset language=%#v", sender.reset)
	}
}

func TestUnknownStoredLanguageKeepsMailFallback(t *testing.T) {
	t.Parallel()
	s, _ := testService(t, "subject-1", "alice")
	sender := &languageSender{}
	s.sender = sender
	if err := s.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{RequestID: "language-empty", SQL: `UPDATE identity_users SET language=NULL WHERE subject=?`, Args: []any{"subject-1"}}); err != nil {
		t.Fatal(err)
	}
	resetRequest(t, s, "alice@example.test", "192.0.2.105:1000", "")
	if len(sender.reset) != 1 || sender.reset[0].Language != "" {
		t.Fatalf("legacy fallback=%#v", sender.reset)
	}
}

func TestLanguageLookupMissingResetTargetIsNonActionable(t *testing.T) {
	t.Parallel()
	s, sender := testService(t, "subject-1", "alice")
	if err := s.issueFor(context.Background(), "missing", "missing@example.test"); err != nil {
		t.Fatal(err)
	}
	if got := sender.messages(); len(got) != 0 {
		t.Fatalf("unexpected messages=%d", len(got))
	}
}
