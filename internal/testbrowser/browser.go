// Package testbrowser provides the bounded Chrome lifecycle for UI tests only.
package testbrowser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

const startupLimit = 60 * time.Second
const actionLimit = 30 * time.Second
const cleanupReserve = 5 * time.Second

func startupBudget(now, deadline time.Time) time.Duration {
	budget := startupLimit
	if !deadline.IsZero() && deadline.Sub(now)-actionLimit-cleanupReserve < budget {
		budget = deadline.Sub(now) - actionLimit - cleanupReserve
	}
	return budget
}

// The startup context also owns Chrome's lifetime. Do not cancel a temporary
// startup context after readiness: exec.CommandContext would kill Chrome.
func startBounded(ctx context.Context, budget time.Duration, cancel context.CancelFunc, start func(context.Context) error) error {
	if budget <= 0 {
		return errors.New("no browser startup budget")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.AfterFunc(budget, cancel)
	err := start(ctx)
	if !timer.Stop() {
		return fmt.Errorf("browser startup budget exhausted: %w", errors.Join(context.DeadlineExceeded, err))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Start returns an already connected browser with a separate 30-second action
// context. Cleanup cancels and waits for the owned Chrome process via allocator.
func Start(t *testing.T) context.Context {
	t.Helper()
	chrome := os.Getenv("GOAUTHY_E2E_CHROME_BIN")
	if chrome == "" {
		for _, name := range []string{"chromium", "google-chrome", "google-chrome-stable"} {
			if candidate, err := exec.LookPath(name); err == nil {
				chrome = candidate
				break
			}
		}
	}
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(chrome); err != nil {
			t.Fatal("Chrome required for browser regression tests")
		}
	}
	var deadline time.Time
	if value, ok := t.Deadline(); ok {
		deadline = value
	}
	startup := startupBudget(time.Now(), deadline)
	if startup <= 0 {
		t.Fatal("insufficient test deadline for Chrome startup, actions and cleanup")
	}
	lifetime, stopLifetime := context.WithTimeout(t.Context(), startup+actionLimit)
	options := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome), chromedp.Headless, chromedp.WSURLReadTimeout(startup))
	if os.Getenv("CI") == "true" {
		options = append(options, chromedp.NoSandbox)
	}
	allocator, stopAllocator := chromedp.NewExecAllocator(lifetime, options...)
	browser, stopBrowser := chromedp.NewContext(allocator)
	t.Cleanup(func() { stopBrowser(); stopAllocator(); stopLifetime() })
	started := time.Now()
	if err := startBounded(browser, startup, stopLifetime, func(ctx context.Context) error { return chromedp.Run(ctx) }); err != nil {
		t.Fatalf("Chrome startup failed after %s (budget %s): %v", time.Since(started), startup, err)
	}
	t.Logf("Chrome connected in %s; startup budget %s, action budget %s", time.Since(started), startup, actionLimit)
	actions, stopActions := context.WithTimeout(browser, actionLimit)
	t.Cleanup(stopActions)
	return actions
}
