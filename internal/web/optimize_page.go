package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/optimizer"
	"github.com/comma-compliance/arc-relay/internal/store"
)

// optimizeRow is one server's line on the bulk optimizer page.
type optimizeRow struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	ServerStatus    string    `json:"server_status"`
	Enumerated      bool      `json:"enumerated"`
	ToolCount       int       `json:"tool_count"`
	OriginalTokens  int       `json:"original_tokens"`
	OptimizedTokens int       `json:"optimized_tokens"`
	SavingsPercent  int       `json:"savings_percent"`
	Status          string    `json:"status"` // none, pending, running, ready, stale, error
	InFlight        bool      `json:"in_flight"`
	IsStale         bool      `json:"is_stale"`
	Model           string    `json:"model"`
	ModelOutdated   bool      `json:"model_outdated"`
	ErrorMsg        string    `json:"error_msg,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	Enabled         bool      `json:"enabled"`
	NeedsRun        bool      `json:"needs_run"`
}

// handleOptimizeRoutes serves /optimize (page), /optimize/status (JSON)
// and /optimize/run (POST, JSON body {"server_ids": [...]}).
func (h *Handlers) handleOptimizeRoutes(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	switch r.URL.Path {
	case "/optimize":
		h.handleOptimizePage(w, r)
	case "/optimize/status":
		h.handleOptimizeStatus(w, r)
	case "/optimize/run":
		h.handleOptimizeRun(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handlers) optimizeRows() ([]optimizeRow, error) {
	servers, err := h.servers.List()
	if err != nil {
		return nil, err
	}
	currentModel := ""
	if h.llmClient != nil {
		currentModel = h.llmClient.Model()
	}

	rows := make([]optimizeRow, 0, len(servers))
	for _, srv := range servers {
		row := optimizeRow{
			ID:           srv.ID,
			Name:         serverLabel(srv),
			ServerStatus: string(srv.Status),
			Status:       "none",
			Enabled:      srv.OptimizeEnabled,
			InFlight:     h.optimizeRunner.InFlight(srv.ID),
		}

		var toolsHash string
		if ep := h.proxy.Endpoints.Get(srv.ID); ep != nil && len(ep.Tools) > 0 {
			_, chars := mcp.AuditTools(ep.Tools)
			row.Enumerated = true
			row.ToolCount = len(ep.Tools)
			row.OriginalTokens = chars / 4
			toolsHash = mcp.HashTools(ep.Tools)
		}

		if opt, err := h.optimizeStore.Get(srv.ID); err == nil && opt != nil {
			row.Status = opt.Status
			row.Model = opt.Model
			row.ErrorMsg = opt.ErrorMsg
			row.UpdatedAt = opt.UpdatedAt
			row.IsStale = opt.Status == "stale" || (toolsHash != "" && opt.ToolsHash != toolsHash)
			row.ModelOutdated = currentModel != "" && opt.Model != currentModel
			if opt.OptimizedChars > 0 {
				row.OptimizedTokens = opt.OptimizedChars / 4
				if opt.OriginalChars > 0 {
					row.SavingsPercent = int(float64(opt.OriginalChars-opt.OptimizedChars) / float64(opt.OriginalChars) * 100)
				}
			}
			// pending/running with no live job means the job was interrupted.
			orphaned := !row.InFlight && (opt.Status == "pending" || opt.Status == "running")
			if orphaned {
				row.Status = "interrupted"
			}
			row.NeedsRun = row.Enumerated && !row.InFlight &&
				(orphaned || row.IsStale || row.ModelOutdated || opt.Status == "error" || opt.PromptVersion != mcp.PromptVersion)
		} else {
			row.NeedsRun = row.Enumerated && !row.InFlight
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func (h *Handlers) handleOptimizePage(w http.ResponseWriter, r *http.Request) {
	rows, err := h.optimizeRows()
	if err != nil {
		slog.Error("optimize page: listing servers", "err", err)
		http.Error(w, "Failed to list servers", http.StatusInternalServerError)
		return
	}

	var totalOriginal, totalServed, needsRun int
	for _, row := range rows {
		if !row.Enumerated {
			continue // no live tools to compare against
		}
		totalOriginal += row.OriginalTokens
		served := row.OriginalTokens
		if row.Enabled && !row.IsStale && row.OptimizedTokens > 0 {
			served = row.OptimizedTokens
		}
		totalServed += served
	}
	for _, row := range rows {
		if row.NeedsRun {
			needsRun++
		}
	}
	savings := 0
	if totalOriginal > 0 {
		savings = int(float64(totalOriginal-totalServed) / float64(totalOriginal) * 100)
	}

	data := map[string]any{
		"Nav":           "optimize",
		"User":          getUser(r),
		"Rows":          rows,
		"LLMAvailable":  h.optimizeRunner.Available(),
		"TotalOriginal": totalOriginal,
		"TotalServed":   totalServed,
		"TotalSavings":  savings,
		"NeedsRunCount": needsRun,
	}
	if h.llmClient != nil {
		data["Model"] = h.llmClient.Model()
		data["Timeout"] = h.llmClient.Timeout().String()
	}
	h.render(w, r, "optimize.html", data)
}

func (h *Handlers) handleOptimizeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	rows, err := h.optimizeRows()
	if err != nil {
		slog.Error("optimize status: listing servers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list servers"})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handlers) handleOptimizeRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		ServerIDs []string `json:"server_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !h.optimizeRunner.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": optimizer.ErrNoLLM.Error()})
		return
	}

	started := []string{}
	skipped := map[string]string{}
	for _, id := range req.ServerIDs {
		srv, err := h.servers.Get(id)
		if err != nil || srv == nil {
			skipped[id] = "server not found"
			continue
		}
		var tools []mcp.Tool
		if ep := h.proxy.Endpoints.Get(id); ep != nil {
			tools = ep.Tools
		}
		if err := h.optimizeRunner.Start(id, srv.Name, tools); err != nil {
			if !errors.Is(err, optimizer.ErrAlreadyRunning) && !errors.Is(err, optimizer.ErrNoTools) {
				slog.Error("optimize: bulk start failed", "server", srv.Name, "err", err)
			}
			skipped[serverLabel(srv)] = err.Error()
			continue
		}
		started = append(started, serverLabel(srv))
	}

	writeJSON(w, http.StatusOK, map[string]any{"started": started, "skipped": skipped})
}

// optimizeStatusBadge maps an optimization status to a badge CSS class.
func optimizeStatusBadge(status string) string {
	switch status {
	case "ready":
		return "badge-success"
	case "pending", "running":
		return "badge-starting"
	case "stale":
		return "badge-denied"
	case "error", "interrupted":
		return "badge-error"
	default:
		return "badge-unknown"
	}
}

// serverLabel returns the display name, falling back to the slug.
func serverLabel(srv *store.Server) string {
	if srv.DisplayName != "" {
		return srv.DisplayName
	}
	return srv.Name
}
