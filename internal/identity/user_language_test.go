package identity

import (
	"context"
	"testing"
	"time"
)

func TestRegisterOpenUserLanguage(t *testing.T) {
	t.Parallel()
	s := testResetStore(t, testRules(2))
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	ctx := context.Background()
	bootstrapPassword(t, s, "legacy", "legacy", []byte("CurrentPassword1"))
	if got, err := s.UserLanguage(ctx, "legacy"); err != nil || got != "" {
		t.Fatalf("legacy language=%q err=%v", got, err)
	}
	for _, lang := range []string{"", "de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		input := OpenRegistration{Email: "language" + lang + "@example.test", Language: lang, TTL: time.Hour}
		created, err := s.RegisterOpenUser(ctx, input)
		if err != nil || !created.Created {
			t.Fatalf("language=%q created=%v err=%v", lang, created.Created, err)
		}
		want := lang
		if want == "" {
			want = "en"
		}
		if got, err := s.UserLanguage(ctx, created.Subject); err != nil || got != want {
			t.Fatalf("language=%q got=%q err=%v", lang, got, err)
		}
		input.Language = "ko"
		if lang == "ko" {
			input.Language = "fr"
		}
		duplicate, err := s.RegisterOpenUser(ctx, input)
		if err != nil || duplicate.Created || duplicate.Subject != created.Subject {
			t.Fatalf("duplicate=%+v err=%v", duplicate, err)
		}
		if got, err := s.UserLanguage(ctx, created.Subject); err != nil || got != want {
			t.Fatalf("duplicate rewrote language=%q got=%q err=%v", lang, got, err)
		}
	}
	for _, lang := range []string{"zh_hans", "en-US", "xx"} {
		if _, err := s.RegisterOpenUser(ctx, OpenRegistration{Email: "invalid@example.test", Language: lang, TTL: time.Hour}); err != ErrInvalidPasswordReset {
			t.Fatalf("invalid language=%q err=%v", lang, err)
		}
	}
	if _, err := s.UserLanguage(ctx, "missing"); err != ErrInactiveSubject {
		t.Fatalf("missing user err=%v", err)
	}
}
