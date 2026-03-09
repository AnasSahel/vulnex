package cache

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/trustin-tech/vulnex/internal/model"
)

func TestSnapshotSaveAndRetrieve(t *testing.T) {
	c, err := NewSQLite(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	snap := model.Snapshot{
		CVEID:    "CVE-2021-44228",
		Date:     "2026-03-09",
		CVSS:     10.0,
		EPSS:     0.975,
		EPSSPctl: 0.999,
		InKEV:    true,
		Exploits: 3,
		Priority: model.PriorityCritical,
		Score:    100,
		Data:     []byte(`{"id":"CVE-2021-44228"}`),
	}

	if err := c.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	// Retrieve latest
	got, err := c.GetLatestSnapshot(ctx, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetLatestSnapshot: %v", err)
	}
	if got == nil {
		t.Fatal("GetLatestSnapshot returned nil")
	}
	if got.CVSS != 10.0 {
		t.Errorf("CVSS = %v, want 10.0", got.CVSS)
	}
	if got.EPSS != 0.975 {
		t.Errorf("EPSS = %v, want 0.975", got.EPSS)
	}
	if !got.InKEV {
		t.Error("InKEV = false, want true")
	}
	if got.Priority != model.PriorityCritical {
		t.Errorf("Priority = %v, want %v", got.Priority, model.PriorityCritical)
	}
	if string(got.Data) != `{"id":"CVE-2021-44228"}` {
		t.Errorf("Data = %q, want JSON blob", string(got.Data))
	}

	// Retrieve by time range
	snapshots, err := c.GetSnapshots(ctx, "CVE-2021-44228", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GetSnapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Errorf("GetSnapshots returned %d, want 1", len(snapshots))
	}

	// Non-existent CVE
	got, err = c.GetLatestSnapshot(ctx, "CVE-0000-0000")
	if err != nil {
		t.Fatalf("GetLatestSnapshot non-existent: %v", err)
	}
	if got != nil {
		t.Error("expected nil for non-existent CVE")
	}
}

func TestSnapshotBatchSave(t *testing.T) {
	c, err := NewSQLite(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	snapshots := []model.Snapshot{
		{CVEID: "CVE-2021-44228", Date: "2026-03-09", CVSS: 10.0, Priority: model.PriorityCritical, Score: 100},
		{CVEID: "CVE-2024-3094", Date: "2026-03-09", CVSS: 9.8, Priority: model.PriorityHigh, Score: 85},
		{CVEID: "CVE-2023-44228", Date: "2026-03-09", CVSS: 7.5, Priority: model.PriorityMedium, Score: 55},
	}

	if err := c.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("SaveSnapshots: %v", err)
	}

	stats, err := c.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.SnapshotEntries != 3 {
		t.Errorf("SnapshotEntries = %d, want 3", stats.SnapshotEntries)
	}
}

func TestSnapshotUpsert(t *testing.T) {
	c, err := NewSQLite(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Save initial snapshot
	snap1 := model.Snapshot{CVEID: "CVE-2021-44228", Date: "2026-03-09", EPSS: 0.5, Priority: model.PriorityMedium, Score: 60}
	if err := c.SaveSnapshot(ctx, snap1); err != nil {
		t.Fatalf("SaveSnapshot 1: %v", err)
	}

	// Upsert with updated EPSS
	snap2 := model.Snapshot{CVEID: "CVE-2021-44228", Date: "2026-03-09", EPSS: 0.9, Priority: model.PriorityHigh, Score: 85}
	if err := c.SaveSnapshot(ctx, snap2); err != nil {
		t.Fatalf("SaveSnapshot 2: %v", err)
	}

	got, err := c.GetLatestSnapshot(ctx, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetLatestSnapshot: %v", err)
	}
	if got.EPSS != 0.9 {
		t.Errorf("EPSS = %v, want 0.9 (upserted)", got.EPSS)
	}

	// Verify only one row exists
	snapshots, err := c.GetSnapshots(ctx, "CVE-2021-44228", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GetSnapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Errorf("expected 1 snapshot after upsert, got %d", len(snapshots))
	}
}

func TestMigrationV2CreatesSnapshotsTable(t *testing.T) {
	dir := t.TempDir()

	c, err := NewSQLite(dir)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}

	var tableName string
	err = c.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots'").Scan(&tableName)
	if err != nil {
		t.Fatalf("snapshots table not found: %v", err)
	}

	var version string
	err = c.db.QueryRow("SELECT value FROM cache_metadata WHERE key='schema_version'").Scan(&version)
	if err != nil {
		t.Fatalf("schema_version not found: %v", err)
	}
	if version != "2" {
		t.Errorf("schema_version = %q, want '2'", version)
	}

	c.Close()

	// Reopen — migration should be idempotent
	c2, err := NewSQLite(dir)
	if err != nil {
		t.Fatalf("NewSQLite (reopen): %v", err)
	}
	defer c2.Close()

	ctx := context.Background()
	snap := model.Snapshot{CVEID: "CVE-TEST", Date: "2026-03-09", Priority: model.PriorityMinimal}
	if err := c2.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot after reopen: %v", err)
	}
}

func TestMigrationFromV1(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")

	// Create a v1 database manually
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		t.Fatalf("v1 migration: %v", err)
	}
	db.Close()

	// Open with NewSQLite — should auto-migrate to v2
	c, err := NewSQLite(dir)
	if err != nil {
		t.Fatalf("NewSQLite after v1: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	snap := model.Snapshot{CVEID: "CVE-MIGRATED", Date: "2026-03-09", CVSS: 7.5, Priority: model.PriorityLow}
	if err := c.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("SaveSnapshot after migration: %v", err)
	}

	got, err := c.GetLatestSnapshot(ctx, "CVE-MIGRATED")
	if err != nil {
		t.Fatalf("GetLatestSnapshot: %v", err)
	}
	if got == nil || got.CVSS != 7.5 {
		t.Error("snapshot not found after v1→v2 migration")
	}
}
