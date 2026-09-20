package main

import (
	"context"
	"errors"
	"strconv"
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
	// Generation is the operator's configuration generation for destination
	// reconciliation. Raising it fences pods that still run an older
	// configuration, so they cannot re-enable a retired destination
	// (GA66-NOTIFY-003). The default keeps a single deployment working when the
	// variable is unset.
	Generation int64
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
	generation, err := notificationGeneration(getenv("GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION"))
	if err != nil {
		return notificationsConfig{}, err
	}
	c := notificationsConfig{Generation: generation}
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

// notificationGeneration parses the reconciliation generation. The bound keeps
// the value inside the schema's INTEGER domain, so a typo fails at startup
// instead of persisting a generation no later configuration can exceed.
func notificationGeneration(raw string) (int64, error) {
	if raw == "" {
		return 1, nil
	}
	generation, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || generation < 1 {
		return 0, errors.New("GOAUTHY_EVENT_NOTIFICATION_CONFIG_GENERATION must be a positive integer")
	}
	return generation, nil
}

func newNotificationRuntime(ctx context.Context, db *rhiza.DB, cfg notificationsConfig) (*notify.Runtime, error) {
	if db == nil {
		return nil, nil
	}
	// Reconcile even when nothing is configured: retiring the last destination
	// must disable its persisted rows instead of queueing for it forever.
	queue, err := notify.NewRhizaQueue(ctx, db, cfg.Targets, cfg.Generation)
	if err != nil {
		return nil, err
	}
	return &notify.Runtime{Queue: queue, Factory: cfg.HTTP}, nil
}

// notificationMaintenanceInterval paces delivery-snapshot retention so a
// completed sweep does not add a replicated write to every delivery tick.
const notificationMaintenanceInterval = time.Hour

func runNotifications(ctx context.Context, runtime *notify.Runtime, now func() time.Time, onError func(error)) {
	runtime.Now = now
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastMaintenance time.Time
	// A sweep that filled its batch resumes on the next turn, so one turn of
	// cleanup can never delay the delivery step that shares this goroutine.
	resumeMaintenance := false
	for {
		if ctx.Err() != nil {
			return
		}
		at := now()
		if err := runtime.Step(ctx, at); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		if resumeMaintenance || lastMaintenance.IsZero() || at.Before(lastMaintenance) || at.Sub(lastMaintenance) >= notificationMaintenanceInterval {
			lastMaintenance = at
			more, err := runtime.Maintain(ctx, at)
			if err != nil && ctx.Err() == nil && onError != nil {
				onError(err)
			}
			resumeMaintenance = more
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
