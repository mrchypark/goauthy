package main

import (
	"context"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/notify"
	"strings"
	"testing"
	"time"
)

func TestNotificationsFromEnv(t *testing.T) {
	env := func(k string) string {
		switch k {
		case "GOAUTHY_EVENT_NOTIFICATION_TARGETS":
			return "slack matrix"
		case "GOAUTHY_EVENT_NOTIFICATION_SLACK_LEVEL":
			return "critical"
		case "GOAUTHY_EVENT_NOTIFICATION_MATRIX_LEVEL":
			return "notice"
		case "GOAUTHY_EVENT_SLACK_WEBHOOK":
			return "https://hooks.example.test/x"
		case "GOAUTHY_EVENT_MATRIX_HOMESERVER":
			return "https://matrix.example.test"
		case "GOAUTHY_EVENT_MATRIX_ROOM":
			return "!room:example.test"
		case "GOAUTHY_EVENT_MATRIX_ACCESS_TOKEN":
			return "token"
		}
		return ""
	}
	c, err := notificationsFromEnv(env)
	if err != nil || len(c.Targets) != 2 || c.Targets[0].Level != eventlog.Critical {
		t.Fatalf("config=%+v err=%v", c, err)
	}
}

func TestNotificationsEmailAndFailClosedConfiguration(t *testing.T) {
	base := map[string]string{
		"GOAUTHY_EVENT_NOTIFICATION_TARGETS": "email",
		"GOAUTHY_EVENT_EMAIL_TO":             "events@example.test",
		"GOAUTHY_SMTP_HOST":                  "smtp.example.test",
		"GOAUTHY_SMTP_FROM":                  "support@example.test",
	}
	get := func(k string) string { return base[k] }
	cfg, err := notificationsFromEnv(get)
	if err != nil || len(cfg.Targets) != 1 || cfg.HTTP.Email == nil {
		t.Fatalf("email configuration failed: %v", err)
	}
	if cfg.Targets[0].Name != notify.Identity("email", base["GOAUTHY_EVENT_EMAIL_TO"]) {
		t.Fatal("destination identity mismatch")
	}
	for _, tc := range []struct{ key, value string }{
		{"GOAUTHY_EVENT_EMAIL_TO", "bad\r\nBcc: leaked@example.test"},
		{"GOAUTHY_SMTP_HOST", ""}, {"GOAUTHY_SMTP_PORT", "0"},
		{"GOAUTHY_SMTP_TIMEOUT", "0s"}, {"GOAUTHY_SMTP_IMPLICIT_TLS", "invalid"},
		{"GOAUTHY_SMTP_PASSWORD", "secret-value"},
		{"GOAUTHY_EVENT_NOTIFICATION_TARGETS", "email email"},
		{"GOAUTHY_EVENT_NOTIFICATION_EMAIL_LEVEL", "unknown"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			original := base[tc.key]
			base[tc.key] = tc.value
			defer func() { base[tc.key] = original }()
			_, err := notificationsFromEnv(get)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "leaked@example.test") {
				t.Fatal("configuration error exposed input")
			}
		})
	}
	base["GOAUTHY_EVENT_NOTIFICATION_TARGETS"] = ""
	cfg, err = notificationsFromEnv(get)
	if err != nil {
		t.Fatal(err)
	}
	if runtime, err := newNotificationRuntime(t.Context(), nil, cfg); err != nil || runtime != nil {
		t.Fatal("disabled notifications accessed database")
	}
}

func TestNotificationsAliasEnvVars(t *testing.T) {
	env := func(k string) string {
		switch k {
		case "GOAUTHY_EVENT_NOTIFICATION_TARGETS":
			return "slack matrix"
		case "GOAUTHY_EVENT_NOTIFICATION_SLACK_LEVEL":
			return "critical"
		case "GOAUTHY_EVENT_NOTIFICATION_MATRIX_LEVEL":
			return "notice"
		case "GOAUTHY_SLACK_WEBHOOK_URL":
			return "https://hooks.slack.example.test/T/B/x"
		case "GOAUTHY_MATRIX_WEBHOOK_URL":
			return "https://matrix.example.test"
		case "GOAUTHY_EVENT_MATRIX_ROOM":
			return "!room:example.test"
		case "GOAUTHY_MATRIX_WEBHOOK_TOKEN":
			return "syt_token"
		}
		return ""
	}
	c, err := notificationsFromEnv(env)
	if err != nil || len(c.Targets) != 2 {
		t.Fatalf("config=%+v err=%v", c, err)
	}
	if c.HTTP.SlackWebhook != "https://hooks.slack.example.test/T/B/x" {
		t.Fatalf("slack webhook not wired: %s", c.HTTP.SlackWebhook)
	}
	if c.HTTP.MatrixHomeserver != "https://matrix.example.test" {
		t.Fatalf("matrix homeserver not wired: %s", c.HTTP.MatrixHomeserver)
	}
	if c.HTTP.MatrixToken != "syt_token" {
		t.Fatalf("matrix token not wired: %s", c.HTTP.MatrixToken)
	}
}

func TestNotificationLoopCancellationDoesNotStep(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	runNotifications(ctx, &notify.Runtime{}, func() time.Time { called = true; return time.Time{} }, func(error) { t.Fatal("cancelled worker reported error") })
	if called {
		t.Fatal("cancelled worker started a step")
	}
}

// GA66-NOTIFY-003: the reconciliation generation is the operator's fence for a
// rolling deployment, so a missing value must keep working and a malformed one
// must fail at startup instead of persisting a generation no later
// configuration can exceed.
func TestNotificationGenerationFromEnv(t *testing.T) {
	withGeneration := func(raw string) func(string) string {
		return func(k string) string {
			if k == "GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION" {
				return raw
			}
			return ""
		}
	}
	if c, err := notificationsFromEnv(withGeneration("7")); err != nil || c.Generation != 7 {
		t.Fatalf("generation=%d err=%v", c.Generation, err)
	}
	if c, err := notificationsFromEnv(withGeneration("")); err != nil || c.Generation != 1 {
		t.Fatalf("default generation=%d err=%v", c.Generation, err)
	}
	for _, raw := range []string{"0", "-1", "1.5", "abc", "9223372036854775808"} {
		if _, err := notificationsFromEnv(withGeneration(raw)); err == nil {
			t.Fatalf("generation %q was accepted", raw)
		}
	}
}
