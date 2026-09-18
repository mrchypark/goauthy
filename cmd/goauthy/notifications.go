package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/notify"
	"github.com/mrchypark/rhiza"
)

// notificationsConfig contains transport configuration only; delivery state
// remains in Rhiza. Secrets are never included in errors or logs.
type notificationsConfig struct {
	Targets []notify.Target
	HTTP    notify.HTTPFactory
}

func envOr(getenv func(string) string, keys ...string) string {
	for _, k := range keys {
		if v := getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func notificationsFromEnv(getenv func(string) string) (notificationsConfig, error) {
	if getenv == nil {
		return notificationsConfig{}, errors.New("notifications require environment reader")
	}
	var c notificationsConfig
	seenKind := map[string]bool{}
	for _, name := range strings.Fields(getenv("GOAUTHY_EVENT_NOTIFICATION_TARGETS")) {
		if name != "slack" && name != "matrix" && name != "email" {
			return c, errors.New("GOAUTHY_EVENT_NOTIFICATION_TARGETS contains an unknown target")
		}
		if seenKind[name] {
			return c, errors.New("duplicate notification target kind")
		}
		seenKind[name] = true
		level, err := notificationLevel(getenv("GOAUTHY_EVENT_NOTIFICATION_" + strings.ToUpper(name) + "_LEVEL"))
		if err != nil {
			return c, err
		}
		destination := envOr(getenv, "GOAUTHY_EVENT_"+strings.ToUpper(name)+"_WEBHOOK", "GOAUTHY_"+strings.ToUpper(name)+"_WEBHOOK_URL")
		if name == "matrix" {
			destination = envOr(getenv, "GOAUTHY_EVENT_MATRIX_HOMESERVER", "GOAUTHY_MATRIX_WEBHOOK_URL") + "\x00" + getenv("GOAUTHY_EVENT_MATRIX_ROOM")
		}
		if name == "email" {
			destination = getenv("GOAUTHY_EVENT_EMAIL_TO")
		}
		if destination == "" {
			return c, errors.New("notification destination is required")
		}
		c.Targets = append(c.Targets, notify.Target{Name: notify.Identity(name, destination), Kind: name, Level: level})
	}
	c.HTTP = notify.HTTPFactory{SlackWebhook: envOr(getenv, "GOAUTHY_EVENT_SLACK_WEBHOOK", "GOAUTHY_SLACK_WEBHOOK_URL"), MatrixHomeserver: envOr(getenv, "GOAUTHY_EVENT_MATRIX_HOMESERVER", "GOAUTHY_MATRIX_WEBHOOK_URL"), MatrixRoom: getenv("GOAUTHY_EVENT_MATRIX_ROOM"), MatrixToken: envOr(getenv, "GOAUTHY_EVENT_MATRIX_ACCESS_TOKEN", "GOAUTHY_MATRIX_WEBHOOK_TOKEN"), Client: notify.HTTPClient(10 * time.Second)}
	if seenKind["email"] {
		smtp, err := smtpConfigFromEnv(getenv)
		if err != nil {
			return notificationsConfig{}, err
		}
		c.HTTP.Email, err = notify.NewEmailSender(notify.EmailConfig{
			Host: smtp.Host, Port: smtp.Port, From: smtp.From, To: getenv("GOAUTHY_EVENT_EMAIL_TO"),
			Username: smtp.Username, Password: smtp.Password, Timeout: smtp.Timeout,
			ImplicitTLS: smtp.ImplicitTLS, AllowInsecure: smtp.AllowInsecure,
		})
		if err != nil {
			return notificationsConfig{}, err
		}
	}
	for _, target := range c.Targets {
		if _, err := c.HTTP.Sender(target); err != nil {
			return notificationsConfig{}, err
		}
	}
	return c, nil
}

func newNotificationRuntime(ctx context.Context, db *rhiza.DB, cfg notificationsConfig) (*notify.Runtime, error) {
	if len(cfg.Targets) == 0 {
		return nil, nil
	}
	queue, err := notify.NewRhizaQueue(ctx, db, cfg.Targets)
	if err != nil {
		return nil, err
	}
	return &notify.Runtime{Queue: queue, Factory: cfg.HTTP}, nil
}

func runNotifications(ctx context.Context, runtime *notify.Runtime, now func() time.Time, onError func(error)) {
	runtime.Now = now
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := runtime.Step(ctx, now()); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func notificationLevel(raw string) (eventlog.Level, error) {
	if raw == "" {
		return eventlog.Warning, nil
	}
	switch strings.ToLower(raw) {
	case "info":
		return eventlog.Info, nil
	case "notice":
		return eventlog.Notice, nil
	case "warning":
		return eventlog.Warning, nil
	case "critical":
		return eventlog.Critical, nil
	}
	return "", errors.New("notification level must be info, notice, warning, or critical")
}
