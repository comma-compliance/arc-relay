// Package optimizer runs LLM tool-optimization jobs in the background.
package optimizer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/comma-compliance/arc-relay/internal/llm"
	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/store"
)

// DefaultMaxConcurrent caps how many servers optimize at once, so a bulk
// run doesn't trip Anthropic rate limits.
const DefaultMaxConcurrent = 2

var (
	ErrNoLLM          = errors.New("LLM API key not configured (set ARC_RELAY_LLM_API_KEY)")
	ErrNoTools        = errors.New("no tools available - start and enumerate the server first")
	ErrAlreadyRunning = errors.New("optimization already in progress")
)

// Runner queues and executes per-server optimization jobs.
type Runner struct {
	store  *store.OptimizeStore
	client *llm.Client
	slots  chan struct{}

	mu       sync.Mutex
	inFlight map[string]bool
	wg       sync.WaitGroup
}

// NewRunner creates a Runner. maxConcurrent <= 0 uses DefaultMaxConcurrent.
func NewRunner(st *store.OptimizeStore, client *llm.Client, maxConcurrent int) *Runner {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	return &Runner{
		store:    st,
		client:   client,
		slots:    make(chan struct{}, maxConcurrent),
		inFlight: make(map[string]bool),
	}
}

// Available reports whether an LLM client is configured.
func (r *Runner) Available() bool {
	return r != nil && r.client != nil && r.client.Available()
}

// InFlight reports whether a job for serverID is pending or running.
func (r *Runner) InFlight(serverID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inFlight[serverID]
}

// Start marks the server pending and runs the optimization in the
// background once a concurrency slot is free.
func (r *Runner) Start(serverID, serverName string, tools []mcp.Tool) error {
	if !r.Available() {
		return ErrNoLLM
	}
	if len(tools) == 0 {
		return ErrNoTools
	}

	r.mu.Lock()
	if r.inFlight[serverID] {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	r.inFlight[serverID] = true
	r.mu.Unlock()

	toolsHash := mcp.HashTools(tools)
	_, originalChars := mcp.AuditTools(tools)

	// On a re-run, only flip the status so the previous result keeps being
	// served until the new one lands (the middleware re-checks the tools hash).
	existing, err := r.store.Get(serverID)
	if err == nil && existing != nil {
		err = r.store.SetStatus(serverID, "pending", "")
	} else if err == nil {
		err = r.store.Upsert(&store.ToolOptimization{
			ServerID:       serverID,
			ToolsHash:      toolsHash,
			OriginalChars:  originalChars,
			OptimizedTools: json.RawMessage("[]"),
			PromptVersion:  mcp.PromptVersion,
			Model:          r.client.Model(),
			Status:         "pending",
		})
	}
	if err != nil {
		r.release(serverID)
		return fmt.Errorf("saving pending status: %w", err)
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(serverID, serverName, tools, toolsHash, originalChars)
	}()
	return nil
}

// Wait blocks until all started jobs have finished. Callers must ensure no
// concurrent Start calls are in progress (intended for tests and shutdown).
func (r *Runner) Wait() {
	r.wg.Wait()
}

func (r *Runner) release(serverID string) {
	r.mu.Lock()
	delete(r.inFlight, serverID)
	r.mu.Unlock()
}

// setError records a failed job. Rows left pending/running by a failed write
// are still treated as re-runnable by the page because InFlight is false.
func (r *Runner) setError(serverID, msg string) {
	if err := r.store.SetStatus(serverID, "error", msg); err != nil {
		slog.Error("optimize: failed to record error status", "server_id", serverID, "err", err)
	}
}

func (r *Runner) run(serverID, serverName string, tools []mcp.Tool, toolsHash string, originalChars int) {
	defer r.release(serverID)

	r.slots <- struct{}{}
	defer func() { <-r.slots }()

	if err := r.store.SetStatus(serverID, "running", ""); err != nil {
		slog.Warn("optimize: failed to mark running", "server_id", serverID, "err", err)
	}

	// Each LLM call is bounded by the client's HTTP timeout, so no outer deadline is needed.
	optimized, err := mcp.OptimizeTools(context.Background(), r.client, tools)
	if err != nil {
		slog.Error("optimize: failed", "server", serverName, "server_id", serverID, "err", err)
		r.setError(serverID, err.Error())
		return
	}

	optimizedJSON, err := json.Marshal(optimized)
	if err != nil {
		slog.Error("optimize: failed to marshal result", "server_id", serverID, "err", err)
		r.setError(serverID, "marshal error: "+err.Error())
		return
	}

	_, optimizedChars := mcp.AuditTools(optimized)
	if err := r.store.Upsert(&store.ToolOptimization{
		ServerID:       serverID,
		ToolsHash:      toolsHash,
		OriginalChars:  originalChars,
		OptimizedChars: optimizedChars,
		OptimizedTools: optimizedJSON,
		PromptVersion:  mcp.PromptVersion,
		Model:          r.client.Model(),
		Status:         "ready",
	}); err != nil {
		slog.Error("optimize: failed to save result", "server_id", serverID, "err", err)
		r.setError(serverID, "saving result: "+err.Error())
		return
	}

	savings := 0.0
	if originalChars > 0 {
		savings = float64(originalChars-optimizedChars) / float64(originalChars) * 100
	}
	slog.Info("optimize: completed",
		"server_id", serverID, "server", serverName,
		"tools", len(optimized),
		"original_chars", originalChars, "optimized_chars", optimizedChars,
		"savings_percent", fmt.Sprintf("%.1f%%", savings),
	)
}
