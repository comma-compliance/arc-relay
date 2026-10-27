package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// ToolOptimization stores the optimized tool definitions for a server.
type ToolOptimization struct {
	ID             string          `json:"id"`
	ServerID       string          `json:"server_id"`
	ToolsHash      string          `json:"tools_hash"`
	OriginalChars  int             `json:"original_chars"`
	OptimizedChars int             `json:"optimized_chars"`
	OptimizedTools json.RawMessage `json:"optimized_tools"`
	PromptVersion  string          `json:"prompt_version"`
	Model          string          `json:"model"`
	Status         string          `json:"status"` // pending, running, ready, stale, error
	ErrorMsg       string          `json:"error_msg,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// OptimizeStore handles CRUD for tool optimizations.
type OptimizeStore struct {
	db *DB
}

// NewOptimizeStore creates a new OptimizeStore.
func NewOptimizeStore(db *DB) *OptimizeStore {
	return &OptimizeStore{db: db}
}

// Get returns the optimization record for a server, or nil if none exists.
func (s *OptimizeStore) Get(serverID string) (*ToolOptimization, error) {
	opt := &ToolOptimization{}
	var optimizedTools, errorMsg string
	err := s.db.QueryRow(`
		SELECT id, server_id, tools_hash, original_chars, optimized_chars,
		       optimized_tools, prompt_version, model, status, COALESCE(error_msg, ''),
		       created_at, updated_at
		FROM tool_optimizations WHERE server_id = ?
	`, serverID).Scan(
		&opt.ID, &opt.ServerID, &opt.ToolsHash, &opt.OriginalChars, &opt.OptimizedChars,
		&optimizedTools, &opt.PromptVersion, &opt.Model, &opt.Status, &errorMsg,
		&opt.CreatedAt, &opt.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	opt.OptimizedTools = json.RawMessage(optimizedTools)
	opt.ErrorMsg = errorMsg
	return opt, nil
}

// Upsert creates or updates the optimization record for a server.
func (s *OptimizeStore) Upsert(opt *ToolOptimization) error {
	if opt.ID == "" {
		id, err := generateID()
		if err != nil {
			return err
		}
		opt.ID = id
	}
	now := time.Now()
	opt.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO tool_optimizations (id, server_id, tools_hash, original_chars, optimized_chars,
		    optimized_tools, prompt_version, model, status, error_msg, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
		    tools_hash = excluded.tools_hash,
		    original_chars = excluded.original_chars,
		    optimized_chars = excluded.optimized_chars,
		    optimized_tools = excluded.optimized_tools,
		    prompt_version = excluded.prompt_version,
		    model = excluded.model,
		    status = excluded.status,
		    error_msg = excluded.error_msg,
		    updated_at = excluded.updated_at
	`, opt.ID, opt.ServerID, opt.ToolsHash, opt.OriginalChars, opt.OptimizedChars,
		string(opt.OptimizedTools), opt.PromptVersion, opt.Model, opt.Status, opt.ErrorMsg,
		now, now)
	return err
}

// SetStatus updates just the status (and optionally error) for a server's optimization.
func (s *OptimizeStore) SetStatus(serverID, status, errorMsg string) error {
	_, err := s.db.Exec(`
		UPDATE tool_optimizations SET status = ?, error_msg = ?, updated_at = ?
		WHERE server_id = ?
	`, status, errorMsg, time.Now(), serverID)
	return err
}

// ResetInFlight marks jobs left pending or running by a previous process as
// errored, so they don't block new runs after a restart.
func (s *OptimizeStore) ResetInFlight() (int64, error) {
	res, err := s.db.Exec(`
		UPDATE tool_optimizations SET status = 'error', error_msg = 'interrupted by restart', updated_at = ?
		WHERE status IN ('pending', 'running')
	`, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarkStale marks the optimization as stale if the tools hash has changed.
func (s *OptimizeStore) MarkStale(serverID, currentHash string) (bool, error) {
	opt, err := s.Get(serverID)
	if err != nil || opt == nil {
		return false, err
	}
	if opt.ToolsHash != currentHash && opt.Status == "ready" {
		return true, s.SetStatus(serverID, "stale", "")
	}
	return false, nil
}

// Delete removes the optimization record for a server.
func (s *OptimizeStore) Delete(serverID string) error {
	_, err := s.db.Exec("DELETE FROM tool_optimizations WHERE server_id = ?", serverID)
	return err
}
