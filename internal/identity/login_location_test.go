package identity

import (
	"context"
	"testing"
	"time"
)

func TestRecordLoginLocationNewLocation(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	// Bootstrap a user
	bootstrapPassword(t, store, "subject-loc-1", "alice@example.test", []byte("Password1"))

	// Record a new location
	result, err := store.RecordLoginLocation(ctx, "subject-loc-1", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsNewLocation {
		t.Fatal("expected new location")
	}
	if result.Location.IPAddress != "192.168.1.1" {
		t.Fatalf("expected IP 192.168.1.1, got %s", result.Location.IPAddress)
	}
	if result.Location.LoginCount != 1 {
		t.Fatalf("expected login count 1, got %d", result.Location.LoginCount)
	}
	if result.PreviousCount != 1 {
		t.Fatalf("expected previous location count 1, got %d", result.PreviousCount)
	}
}

func TestRecordLoginLocationExistingLocation(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-2", "bob@example.test", []byte("Password1"))

	// Record first login
	_, err := store.RecordLoginLocation(ctx, "subject-loc-2", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}

	// Record second login from same IP
	store.now = func() time.Time { return time.UnixMilli(1_800_000_001_000) }
	result, err := store.RecordLoginLocation(ctx, "subject-loc-2", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.IsNewLocation {
		t.Fatal("expected existing location")
	}
	if result.Location.LoginCount != 2 {
		t.Fatalf("expected login count 2, got %d", result.Location.LoginCount)
	}
}

func TestRecordLoginLocationMultipleLocations(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-3", "charlie@example.test", []byte("Password1"))

	// Record first location
	_, err := store.RecordLoginLocation(ctx, "subject-loc-3", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}

	// Record second location
	store.now = func() time.Time { return time.UnixMilli(1_800_000_001_000) }
	result, err := store.RecordLoginLocation(ctx, "subject-loc-3", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsNewLocation {
		t.Fatal("expected new location")
	}
	if result.PreviousCount != 2 {
		t.Fatalf("expected previous location count 2, got %d", result.PreviousCount)
	}
}

func TestIsNewLoginLocation(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-4", "dave@example.test", []byte("Password1"))

	// Record a location
	_, err := store.RecordLoginLocation(ctx, "subject-loc-4", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}

	// Check if same location is new
	isNew, err := store.IsNewLoginLocation(ctx, "subject-loc-4", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("expected existing location")
	}

	// Check if different location is new
	isNew, err = store.IsNewLoginLocation(ctx, "subject-loc-4", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("expected new location")
	}
}

func TestGetLoginLocations(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-5", "eve@example.test", []byte("Password1"))

	// Record multiple locations
	_, err := store.RecordLoginLocation(ctx, "subject-loc-5", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.UnixMilli(1_800_000_001_000) }
	_, err = store.RecordLoginLocation(ctx, "subject-loc-5", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	// Get all locations
	locations, err := store.GetLoginLocations(ctx, "subject-loc-5")
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != 2 {
		t.Fatalf("expected 2 locations, got %d", len(locations))
	}
}

func TestRecordLoginLocationInvalidIP(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-6", "frank@example.test", []byte("Password1"))

	// Test invalid IP
	_, err := store.RecordLoginLocation(ctx, "subject-loc-6", "invalid-ip")
	if err != ErrInvalidIPAddress {
		t.Fatalf("expected ErrInvalidIPAddress, got %v", err)
	}

	// Test empty IP
	_, err = store.RecordLoginLocation(ctx, "subject-loc-6", "")
	if err != ErrInvalidIPAddress {
		t.Fatalf("expected ErrInvalidIPAddress, got %v", err)
	}
}

func TestRecordLoginLocationIPv6(t *testing.T) {
	t.Parallel()
	store := testResetStore(t, testRules(3))
	store.now = func() time.Time { return time.UnixMilli(1_800_000_000_000) }
	ctx := context.Background()

	bootstrapPassword(t, store, "subject-loc-7", "grace@example.test", []byte("Password1"))

	// Record IPv6 location
	result, err := store.RecordLoginLocation(ctx, "subject-loc-7", "::1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsNewLocation {
		t.Fatal("expected new location")
	}
	if result.Location.IPAddress != "::1" {
		t.Fatalf("expected IP ::1, got %s", result.Location.IPAddress)
	}
}
