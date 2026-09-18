package main

import "testing"

func TestDCRAnonymousCleanupConfigFromEnv(t *testing.T) {
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	config, err := dcrAnonymousCleanupConfigFromEnv(getenv(map[string]string{
		"GOAUTHY_DCR_ANONYMOUS_CLEANUP_MINUTES": "2",
		"GOAUTHY_DCR_ANONYMOUS_INACTIVE_DAYS":   "7",
		"GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT":   "3",
	}))
	if err != nil || config.CleanupMinutes != 2 || config.InactiveDays != 7 || config.Limit != 3 {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	if _, err := dcrAnonymousCleanupConfigFromEnv(getenv(map[string]string{"GOAUTHY_DCR_ANONYMOUS_CLEANUP_LIMIT": "0"})); err == nil {
		t.Fatal("accepted zero cleanup limit")
	}
}
