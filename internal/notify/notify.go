// Package notify delivers lifecycle events to configured external targets.
// Persistence is deliberately injected: the storage package owns leases and
// retry rows, while this package only coordinates transport calls.
package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

const (
	DefaultBatch = 1
	DefaultLease = time.Minute
	MaxBackoff   = 24 * time.Hour
	// DefaultRetention bounds a delivery snapshot once it is terminal and how
	// long an undeliverable one is retried before it is aged out.
	DefaultRetention = 31 * 24 * time.Hour
)

type Target struct {
	Name  string
	Kind  string
	Level eventlog.Level
}

func Identity(kind, destination string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + destination))
	return kind + ":" + hex.EncodeToString(h[:])
}

type Delivery struct {
	Event    eventlog.Event
	Lease    string
	Attempts int
}

type Sender interface {
	Send(context.Context, eventlog.Event) error
}
type SenderFactory interface{ Sender(Target) (Sender, error) }

type Runtime struct {
	Queue   *RhizaQueue
	Factory SenderFactory
	Batch   int
	Lease   time.Duration
	// Retention overrides DefaultRetention for Maintain.
	Retention time.Duration
	Now       func() time.Time
}

// Maintain ages out delivery snapshots one bounded replicated batch at a time
// until none is left. Terminal rows, rows below the configured threshold, and
// rows that stayed undelivered past retention are removed; leased rows and
// snapshots whose source event is already gone are kept, because a pending
// delivery must not lose the payload it still owes a destination.
func (r *Runtime) Maintain(ctx context.Context, now time.Time) error {
	if r == nil || r.Queue == nil || ctx == nil || now.IsZero() {
		return errors.New("notifications are not configured")
	}
	retention := r.Retention
	if retention <= 0 {
		retention = DefaultRetention
	}
	for ctx.Err() == nil {
		removed, err := r.Queue.Cleanup(ctx, now, retention)
		if err != nil {
			return err
		}
		if removed == 0 {
			return nil
		}
	}
	return ctx.Err()
}

func (r *Runtime) Step(ctx context.Context, now time.Time) error {
	if r == nil || r.Queue == nil || r.Factory == nil || ctx == nil || now.IsZero() {
		return errors.New("notifications are not configured")
	}
	batch, lease := r.Batch, r.Lease
	if batch <= 0 {
		batch = DefaultBatch
	}
	if batch > 1 {
		batch = 1
	}
	if lease <= 0 {
		lease = DefaultLease
	}
	targets, err := r.Queue.Targets(ctx)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if r.Now != nil {
			now = r.Now()
		}
		sender, err := r.Factory.Sender(target)
		if err != nil {
			return fmt.Errorf("configure notification target %q: %w", target.Name, err)
		}
		deliveries, err := r.Queue.Claim(ctx, target.Name, now, batch, lease)
		if err != nil {
			return err
		}
		for _, d := range deliveries {
			// The claim already filters on the persisted threshold; this keeps a
			// threshold another instance changed after Targets was read from
			// reaching the destination.
			if d.Event.Type != eventlog.Test && d.Event.Level.Rank() < target.Level.Rank() {
				if err := r.Queue.Ack(ctx, target.Name, d.Event.ID, d.Lease, now); err != nil {
					return err
				}
				continue
			}
			// Each external delivery is bounded below its lease, including SMTP.
			deliveryCtx, cancel := context.WithTimeout(ctx, min(10*time.Second, lease/2))
			sendErr := sender.Send(deliveryCtx, d.Event)
			cancel()
			finished := now
			if r.Now != nil {
				finished = r.Now()
			}
			if sendErr == nil {
				if err := r.Queue.Ack(ctx, target.Name, d.Event.ID, d.Lease, finished); err != nil {
					return err
				}
			} else {
				if ferr := r.Queue.Fail(ctx, target.Name, d.Event.ID, d.Lease, finished, Backoff(d.Attempts), safeError(sendErr)); ferr != nil {
					return ferr
				}
			}
		}
	}
	return nil
}

func Backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := time.Second
	for i := 1; i < attempts && d < MaxBackoff; i++ {
		d *= 2
	}
	if d > MaxBackoff {
		return MaxBackoff
	}
	return d
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	// ponytail: fixed classification avoids persisting endpoint responses,
	// credentials, or arbitrary remote error text; add typed counters if needed.
	return "delivery failed"
}

func HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(raw) != raw || len(raw) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("notification URL must be an https URL without userinfo")
	}
	return u, nil
}
