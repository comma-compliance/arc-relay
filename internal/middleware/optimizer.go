package middleware

import (
	"context"
	"encoding/json"
	"log"

	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/store"
)

// Optimizer middleware swaps in optimized tool definitions on tools/list responses.
// It only activates for servers that have optimize_enabled=true and a stored
// optimization whose tools hash still matches the live tools.
type Optimizer struct {
	optimizeStore *store.OptimizeStore
	serverStore   *store.ServerStore
}

// NewOptimizer creates a new Optimizer middleware.
func NewOptimizer(optimizeStore *store.OptimizeStore, serverStore *store.ServerStore) *Optimizer {
	return &Optimizer{
		optimizeStore: optimizeStore,
		serverStore:   serverStore,
	}
}

func (o *Optimizer) Name() string { return "optimizer" }

func (o *Optimizer) ProcessRequest(_ context.Context, req *mcp.Request, _ *RequestMeta) (*mcp.Request, error) {
	return req, nil // pass through
}

func (o *Optimizer) ProcessResponse(_ context.Context, _ *mcp.Request, resp *mcp.Response, meta *RequestMeta) (*mcp.Response, error) {
	// Only process tools/list responses
	if meta.Method != "tools/list" {
		return resp, nil
	}

	// Check if optimization is enabled for this server
	srv, err := o.serverStore.Get(meta.ServerID)
	if err != nil || srv == nil || !srv.OptimizeEnabled {
		return resp, nil
	}

	// Get the optimization record. A pending/running/failed re-run keeps the
	// previous result, which is still served while its tools hash matches.
	opt, err := o.optimizeStore.Get(meta.ServerID)
	if err != nil || opt == nil || opt.Status == "stale" || len(opt.OptimizedTools) == 0 {
		return resp, nil
	}

	// Parse the original tools/list result
	if resp.Error != nil || resp.Result == nil {
		return resp, nil
	}

	var original mcp.ToolsListResult
	if err := json.Unmarshal(resp.Result, &original); err != nil {
		log.Printf("optimizer: failed to parse tools/list result for %s: %v", meta.ServerName, err)
		return resp, nil
	}

	// Verify the live tools hash matches the optimization - if tools have changed
	// upstream since optimization was run, serve the original to avoid stale data.
	liveHash := mcp.HashTools(original.Tools)
	if liveHash != opt.ToolsHash {
		log.Printf("optimizer: tools hash mismatch for %s (live=%s, opt=%s) - serving original",
			meta.ServerName, liveHash[:12], opt.ToolsHash[:12])
		// Mark stale in background (best-effort). Only ready rows can go stale;
		// pending/running/error rows keep their status.
		if opt.Status == "ready" {
			go func() { _, _ = o.optimizeStore.MarkStale(meta.ServerID, liveHash) }()
		}
		return resp, nil
	}

	// Parse the optimized tools
	var optimized []mcp.Tool
	if err := json.Unmarshal(opt.OptimizedTools, &optimized); err != nil {
		log.Printf("optimizer: failed to parse optimized tools for %s: %v", meta.ServerName, err)
		return resp, nil
	}

	// Build lookup map of optimized tools by name
	optMap := make(map[string]mcp.Tool, len(optimized))
	for _, t := range optimized {
		optMap[t.Name] = t
	}

	// Replace tool definitions with optimized versions where available.
	// If a tool exists in the original but not in the optimized set
	// (e.g., new tool added after optimization), keep the original.
	result := make([]mcp.Tool, 0, len(original.Tools))
	for _, t := range original.Tools {
		if optTool, ok := optMap[t.Name]; ok {
			result = append(result, optTool)
		} else {
			result = append(result, t)
		}
	}

	// Patch the tools in the original result object to preserve any sibling fields
	// (e.g., pagination cursors, vendor metadata) that aren't part of ToolsListResult.
	var resultObj map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &resultObj); err != nil {
		log.Printf("optimizer: failed to parse result object for %s: %v", meta.ServerName, err)
		return resp, nil
	}

	toolsJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("optimizer: failed to marshal optimized tools for %s: %v", meta.ServerName, err)
		return resp, nil
	}
	resultObj["tools"] = toolsJSON

	resultJSON, err := json.Marshal(resultObj)
	if err != nil {
		log.Printf("optimizer: failed to marshal patched result for %s: %v", meta.ServerName, err)
		return resp, nil
	}

	resp.Result = resultJSON
	return resp, nil
}
