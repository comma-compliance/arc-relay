package middleware

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/comma-compliance/arc-relay/internal/testutil"
)

func TestOptimizer_ServesByStatus(t *testing.T) {
	liveTools := []mcp.Tool{{Name: "a", Description: "original description", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	liveHash := mcp.HashTools(liveTools)
	optimized := json.RawMessage(`[{"name":"a","description":"opt","inputSchema":{"type":"object"}}]`)

	tests := []struct {
		status    string
		hash      string
		wantOptim bool
	}{
		{"ready", liveHash, true},
		{"pending", liveHash, true}, // re-run in flight keeps serving previous result
		{"running", liveHash, true},
		{"error", liveHash, true}, // failed re-run keeps serving previous result
		{"stale", liveHash, false},
		{"ready", mcp.HashTools(nil), false},
	}
	for _, tt := range tests {
		t.Run(tt.status+"/"+tt.hash[:5], func(t *testing.T) {
			db := testutil.OpenTestDB(t)
			servers := store.NewServerStore(db, store.NewConfigEncryptor(""))
			optStore := store.NewOptimizeStore(db)
			srv := &store.Server{Name: "demo", ServerType: store.ServerTypeStdio, Config: json.RawMessage(`{}`)}
			if err := servers.Create(srv); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := servers.SetOptimizeEnabled(srv.ID, true); err != nil {
				t.Fatalf("SetOptimizeEnabled: %v", err)
			}
			if err := optStore.Upsert(&store.ToolOptimization{
				ServerID: srv.ID, ToolsHash: tt.hash, OptimizedTools: optimized, Status: tt.status,
			}); err != nil {
				t.Fatalf("Upsert: %v", err)
			}

			result, _ := json.Marshal(mcp.ToolsListResult{Tools: liveTools})
			resp := &mcp.Response{Result: result}
			o := NewOptimizer(optStore, servers)
			got, err := o.ProcessResponse(context.Background(), &mcp.Request{}, resp,
				&RequestMeta{ServerID: srv.ID, ServerName: "demo", Method: "tools/list"})
			if err != nil {
				t.Fatalf("ProcessResponse: %v", err)
			}
			var out mcp.ToolsListResult
			if err := json.Unmarshal(got.Result, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			isOptim := out.Tools[0].Description == "opt"
			if isOptim != tt.wantOptim {
				t.Errorf("served optimized=%v, want %v", isOptim, tt.wantOptim)
			}
		})
	}
}

func TestOptimizer_MismatchOnlyMarksReadyStale(t *testing.T) {
	liveTools := []mcp.Tool{{Name: "a", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	oldHash := mcp.HashTools(nil)

	for _, status := range []string{"ready", "error", "pending"} {
		t.Run(status, func(t *testing.T) {
			db := testutil.OpenTestFileDB(t)
			servers := store.NewServerStore(db, store.NewConfigEncryptor(""))
			optStore := store.NewOptimizeStore(db)
			srv := &store.Server{Name: "demo", ServerType: store.ServerTypeStdio, Config: json.RawMessage(`{}`)}
			if err := servers.Create(srv); err != nil {
				t.Fatalf("Create: %v", err)
			}
			_ = servers.SetOptimizeEnabled(srv.ID, true)
			_ = optStore.Upsert(&store.ToolOptimization{ServerID: srv.ID, ToolsHash: oldHash, OptimizedTools: json.RawMessage(`[]`), Status: status})

			result, _ := json.Marshal(mcp.ToolsListResult{Tools: liveTools})
			o := NewOptimizer(optStore, servers)
			_, _ = o.ProcessResponse(context.Background(), &mcp.Request{}, &mcp.Response{Result: result},
				&RequestMeta{ServerID: srv.ID, ServerName: "demo", Method: "tools/list"})

			want := status
			if status == "ready" {
				want = "stale"
			}
			deadline := time.Now().Add(2 * time.Second)
			var got string
			for time.Now().Before(deadline) {
				if opt, _ := optStore.Get(srv.ID); opt != nil {
					got = opt.Status
				}
				if got == want && (status != "ready" || got == "stale") {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if got != want {
				t.Errorf("status %q, want %q", got, want)
			}
		})
	}
}
