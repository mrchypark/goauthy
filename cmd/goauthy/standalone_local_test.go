package main

import (
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestStandaloneLocalRejectsLegacySignedBackupScheduler(t *testing.T) {
	config := rhiza.Config{Local: true}
	enabled := func(name string) string {
		if name == "GOAUTHY_BACKUP_ENABLED" {
			return "true"
		}
		return ""
	}
	if scheduled, err := scheduledBackupFromEnv(enabled, config); err == nil || scheduled != nil {
		t.Fatalf("Local archive accepted unsupported signed scheduler: scheduled=%v err=%v", scheduled, err)
	}
	if scheduled, err := scheduledBackupFromEnv(func(string) string { return "" }, config); err != nil || scheduled != nil {
		t.Fatalf("disabled scheduler blocked Local startup: scheduled=%v err=%v", scheduled, err)
	}
}
