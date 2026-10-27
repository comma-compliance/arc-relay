package store_test

import (
	"encoding/json"
	"testing"

	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/comma-compliance/arc-relay/internal/testutil"
)

func TestOptimizeStore_CRUD(t *testing.T) {
	db := testutil.OpenTestDB(t)
	s := store.NewOptimizeStore(db)

	// Create server for FK reference
	serverStore := store.NewServerStore(db, store.NewConfigEncryptor(""))
	srv := &store.Server{
		Name:        "test-server",
		DisplayName: "Test Server",
		ServerType:  store.ServerTypeStdio,
		Config:      json.RawMessage(`{}`),
	}
	if err := serverStore.Create(srv); err != nil {
		t.Fatalf("Create server: %v", err)
	}

	// Get should return nil for nonexistent
	opt, err := s.Get(srv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if opt != nil {
		t.Fatal("Expected nil for nonexistent optimization")
	}

	// Upsert
	err = s.Upsert(&store.ToolOptimization{
		ServerID:       srv.ID,
		ToolsHash:      "abc123",
		OriginalChars:  1000,
		OptimizedChars: 500,
		OptimizedTools: json.RawMessage(`[{"name":"foo","description":"optimized"}]`),
		PromptVersion:  "v1.0",
		Model:          "claude-haiku-4-5-20251001",
		Status:         "ready",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Get should return the record
	opt, err = s.Get(srv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if opt == nil {
		t.Fatal("Expected optimization record")
	}
	if opt.ToolsHash != "abc123" {
		t.Errorf("Expected hash 'abc123', got %q", opt.ToolsHash)
	}
	if opt.OriginalChars != 1000 {
		t.Errorf("Expected original 1000, got %d", opt.OriginalChars)
	}
	if opt.OptimizedChars != 500 {
		t.Errorf("Expected optimized 500, got %d", opt.OptimizedChars)
	}
	if opt.Status != "ready" {
		t.Errorf("Expected status 'ready', got %q", opt.Status)
	}

	// Upsert should update
	err = s.Upsert(&store.ToolOptimization{
		ServerID:       srv.ID,
		ToolsHash:      "def456",
		OriginalChars:  1200,
		OptimizedChars: 600,
		OptimizedTools: json.RawMessage(`[{"name":"foo","description":"re-optimized"}]`),
		PromptVersion:  "v1.1",
		Model:          "claude-haiku-4-5-20251001",
		Status:         "ready",
	})
	if err != nil {
		t.Fatalf("Upsert update: %v", err)
	}

	opt, _ = s.Get(srv.ID)
	if opt.ToolsHash != "def456" {
		t.Errorf("Expected updated hash 'def456', got %q", opt.ToolsHash)
	}

	// MarkStale
	stale, err := s.MarkStale(srv.ID, "different-hash")
	if err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if !stale {
		t.Error("Expected stale=true for different hash")
	}

	opt, _ = s.Get(srv.ID)
	if opt.Status != "stale" {
		t.Errorf("Expected status 'stale', got %q", opt.Status)
	}

	// MarkStale with same hash should not mark stale (already stale)
	stale, err = s.MarkStale(srv.ID, "another-hash")
	if err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if stale {
		t.Error("Expected stale=false when already stale")
	}

	// SetStatus
	err = s.SetStatus(srv.ID, "error", "something broke")
	if err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	opt, _ = s.Get(srv.ID)
	if opt.Status != "error" || opt.ErrorMsg != "something broke" {
		t.Errorf("Expected error status, got %q / %q", opt.Status, opt.ErrorMsg)
	}

	// Delete
	err = s.Delete(srv.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	opt, _ = s.Get(srv.ID)
	if opt != nil {
		t.Error("Expected nil after delete")
	}
}

func TestServerStore_OptimizeEnabled(t *testing.T) {
	db := testutil.OpenTestDB(t)
	serverStore := store.NewServerStore(db, store.NewConfigEncryptor(""))

	srv := &store.Server{
		Name:        "opt-test",
		DisplayName: "Optimize Test",
		ServerType:  store.ServerTypeRemote,
		Config:      json.RawMessage(`{"url":"https://example.com"}`),
	}
	if err := serverStore.Create(srv); err != nil {
		t.Fatalf("Create server: %v", err)
	}

	// Default should be false
	got, err := serverStore.Get(srv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OptimizeEnabled {
		t.Error("Expected OptimizeEnabled=false by default")
	}

	// Enable
	if err := serverStore.SetOptimizeEnabled(srv.ID, true); err != nil {
		t.Fatalf("SetOptimizeEnabled: %v", err)
	}
	got, _ = serverStore.Get(srv.ID)
	if !got.OptimizeEnabled {
		t.Error("Expected OptimizeEnabled=true after enable")
	}

	// Disable
	if err := serverStore.SetOptimizeEnabled(srv.ID, false); err != nil {
		t.Fatalf("SetOptimizeEnabled: %v", err)
	}
	got, _ = serverStore.Get(srv.ID)
	if got.OptimizeEnabled {
		t.Error("Expected OptimizeEnabled=false after disable")
	}
}

func TestOptimizeStore_ResetInFlight(t *testing.T) {
	db := testutil.OpenTestDB(t)
	s := store.NewOptimizeStore(db)
	serverStore := store.NewServerStore(db, store.NewConfigEncryptor(""))

	statuses := []string{"pending", "running", "ready"}
	ids := make([]string, len(statuses))
	for i, status := range statuses {
		srv := &store.Server{Name: "srv-" + status, ServerType: store.ServerTypeStdio, Config: json.RawMessage(`{}`)}
		if err := serverStore.Create(srv); err != nil {
			t.Fatalf("Create server: %v", err)
		}
		ids[i] = srv.ID
		if err := s.Upsert(&store.ToolOptimization{ServerID: srv.ID, OptimizedTools: json.RawMessage(`[]`), Status: status}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	n, err := s.ResetInFlight()
	if err != nil {
		t.Fatalf("ResetInFlight: %v", err)
	}
	if n != 2 {
		t.Errorf("reset %d rows, want 2", n)
	}
	want := []string{"error", "error", "ready"}
	for i, id := range ids {
		opt, err := s.Get(id)
		if err != nil || opt == nil {
			t.Fatalf("Get: %v", err)
		}
		if opt.Status != want[i] {
			t.Errorf("%s: status %q, want %q", statuses[i], opt.Status, want[i])
		}
	}
}
