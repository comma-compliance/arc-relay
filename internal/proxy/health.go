package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/safego"
	"github.com/comma-compliance/arc-relay/internal/store"
)

const (
	// failThreshold is the number of consecutive probe failures before marking a server as Error.
	failThreshold = 3
	// recoveryCooldown is the minimum time between recovery attempts for a server.
	recoveryCooldown = 5 * time.Minute
	// maxRecoverAttempts is the max consecutive recovery attempts before giving up.
	// After this many failures, the server stays in error until manually restarted.
	maxRecoverAttempts = 3
	// dockerRecoverTimeout is the context timeout for Docker container recovery operations.
	dockerRecoverTimeout = 3 * time.Minute
)

// HealthMonitor periodically checks running servers and updates their status.
type HealthMonitor struct {
	proxyMgr *Manager
	servers  *store.ServerStore
	interval time.Duration
	cancel   context.CancelFunc

	mu              sync.Mutex
	failCounts      map[string]int       // server ID -> consecutive probe failures
	lastRecover     map[string]time.Time // server ID -> last recovery attempt
	recoverAttempts map[string]int       // server ID -> consecutive recovery attempts
	recovering      map[string]bool      // server ID -> recovery goroutine in progress
}

// NewHealthMonitor creates a health monitor that checks servers at the given interval.
func NewHealthMonitor(proxyMgr *Manager, servers *store.ServerStore, interval time.Duration) *HealthMonitor {
	return &HealthMonitor{
		proxyMgr:        proxyMgr,
		servers:         servers,
		interval:        interval,
		failCounts:      make(map[string]int),
		lastRecover:     make(map[string]time.Time),
		recoverAttempts: make(map[string]int),
		recovering:      make(map[string]bool),
	}
}

// Start begins periodic health checking in a background goroutine.
func (hm *HealthMonitor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	hm.cancel = cancel

	go func() {
		ticker := time.NewTicker(hm.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// A panic in one check must not stop health monitoring.
				safego.Run("health check", func() { hm.checkAll(ctx) })
			case <-ctx.Done():
				return
			}
		}
	}()

	slog.Info("health monitor started", "interval", hm.interval)
}

// Stop stops the health monitor.
func (hm *HealthMonitor) Stop() {
	if hm.cancel != nil {
		hm.cancel()
	}
}

// CheckHealth performs an on-demand MCP health check for a single server.
// Returns the health status and any error message.
func (hm *HealthMonitor) CheckHealth(ctx context.Context, serverID string) (store.HealthStatus, string) {
	backend, ok := hm.proxyMgr.GetBackend(serverID)
	if !ok {
		return store.HealthUnknown, "no backend available"
	}

	if err := hm.pingServer(ctx, backend); err != nil {
		_ = hm.servers.UpdateHealth(serverID, store.HealthUnhealthy, err.Error())
		return store.HealthUnhealthy, err.Error()
	}

	_ = hm.servers.UpdateHealth(serverID, store.HealthHealthy, "")
	return store.HealthHealthy, ""
}

func (hm *HealthMonitor) checkAll(ctx context.Context) {
	servers, err := hm.servers.List()
	if err != nil {
		slog.Warn("health monitor: error listing servers", "err", err)
		return
	}

	for _, srv := range servers {
		if srv.Status == store.StatusRunning {
			hm.checkRunning(ctx, srv)
		} else if srv.Status == store.StatusError {
			hm.tryRecover(ctx, srv)
		} else if srv.Status == store.StatusStopped && srv.Health != store.HealthUnknown {
			// Reset health to unknown when stopped
			_ = hm.servers.UpdateHealth(srv.ID, store.HealthUnknown, "")
		}
	}
}

func (hm *HealthMonitor) checkRunning(ctx context.Context, srv *store.Server) {
	backend, ok := hm.proxyMgr.GetBackend(srv.ID)
	if !ok {
		_ = hm.servers.UpdateStatus(srv.ID, store.StatusStopped, "backend not found")
		_ = hm.servers.UpdateHealth(srv.ID, store.HealthUnknown, "")
		hm.resetFailCount(srv.ID)
		slog.Warn("health monitor: server has no backend, marking stopped", "server", srv.Name)
		return
	}

	if err := hm.pingServer(ctx, backend); err != nil {
		hm.mu.Lock()
		hm.failCounts[srv.ID]++
		count := hm.failCounts[srv.ID]
		hm.mu.Unlock()

		_ = hm.servers.UpdateHealth(srv.ID, store.HealthUnhealthy, err.Error())

		if count >= failThreshold {
			slog.Error("health monitor: server failed consecutive probes, marking error",
				"server", srv.Name, "failures", count, "err", err)
			_ = hm.servers.UpdateStatus(srv.ID, store.StatusError, err.Error())
		} else {
			slog.Warn("health monitor: probe failed",
				"server", srv.Name, "failures", count, "threshold", failThreshold, "err", err)
		}
	} else {
		hm.resetFailCount(srv.ID)
		if srv.Health != store.HealthHealthy {
			slog.Info("health monitor: server is healthy", "server", srv.Name)
		}
		_ = hm.servers.UpdateHealth(srv.ID, store.HealthHealthy, "")
	}
}

// tryRecover attempts to auto-recover errored servers.
// Stateless servers (remote, external HTTP) use RetryServer inline.
// Docker-managed servers (stdio, Docker HTTP) use RecreateContainer in a
// background goroutine to avoid blocking the health monitor loop.
// Applies a cooldown and max attempt limit to prevent restart storms.
func (hm *HealthMonitor) tryRecover(ctx context.Context, srv *store.Server) {
	hm.mu.Lock()

	// Skip if a recovery goroutine is already running for this server
	if hm.recovering[srv.ID] {
		hm.mu.Unlock()
		return
	}

	// Cooldown: skip if last attempt was too recent
	if last, ok := hm.lastRecover[srv.ID]; ok && time.Since(last) < recoveryCooldown {
		hm.mu.Unlock()
		return
	}

	// Max attempts: give up after repeated failures
	attempts := hm.recoverAttempts[srv.ID]
	if attempts >= maxRecoverAttempts {
		hm.mu.Unlock()
		return
	}

	hm.lastRecover[srv.ID] = time.Now()
	hm.recoverAttempts[srv.ID] = attempts + 1
	attempt := attempts + 1

	if hm.isStatelessServer(srv) {
		// Stateless: recover inline (fast, no Docker ops)
		hm.mu.Unlock()
		if err := hm.proxyMgr.RetryServer(ctx, srv); err != nil {
			slog.Error("health monitor: recovery failed",
				"attempt", attempt, "max_attempts", maxRecoverAttempts, "server", srv.Name, "err", err)
			sentry.CaptureException(fmt.Errorf("health recovery failed for %s (attempt %d/%d): %w",
				srv.Name, attempt, maxRecoverAttempts, err))
			if attempt >= maxRecoverAttempts {
				slog.Error("health monitor: giving up, manual restart required",
					"server", srv.Name, "attempts", maxRecoverAttempts)
			}
			return
		}
		hm.ResetRecoveryState(srv.ID)
		slog.Info("health monitor: auto-recovered server", "server", srv.Name)
		return
	}

	// Docker-managed: recover async to avoid blocking health loop
	hm.recovering[srv.ID] = true
	hm.mu.Unlock()

	go func() {
		defer safego.Recover("health recovery " + srv.Name)
		defer func() {
			hm.mu.Lock()
			delete(hm.recovering, srv.ID)
			hm.mu.Unlock()
		}()

		recoverCtx, cancel := context.WithTimeout(ctx, dockerRecoverTimeout)
		defer cancel()

		slog.Info("health monitor: attempting recovery",
			"attempt", attempt, "max_attempts", maxRecoverAttempts, "server", srv.Name, "type", srv.ServerType)

		if err := hm.proxyMgr.RecreateContainer(recoverCtx, srv); err != nil {
			slog.Error("health monitor: recovery failed",
				"attempt", attempt, "max_attempts", maxRecoverAttempts, "server", srv.Name, "err", err)
			sentry.CaptureException(fmt.Errorf("health recovery failed for %s (attempt %d/%d): %w",
				srv.Name, attempt, maxRecoverAttempts, err))
			if attempt >= maxRecoverAttempts {
				slog.Error("health monitor: giving up, manual restart required",
					"server", srv.Name, "attempts", maxRecoverAttempts)
			}
			return
		}

		hm.ResetRecoveryState(srv.ID)
		slog.Info("health monitor: auto-recovered server", "server", srv.Name, "type", srv.ServerType)
	}()
}

func (hm *HealthMonitor) resetFailCount(serverID string) {
	hm.mu.Lock()
	delete(hm.failCounts, serverID)
	hm.mu.Unlock()
}

// ResetRecoveryState clears all recovery tracking for a server.
// Call this after a successful auto-recovery or manual restart so the server
// gets a fresh retry budget if it fails again later.
func (hm *HealthMonitor) ResetRecoveryState(serverID string) {
	hm.mu.Lock()
	delete(hm.failCounts, serverID)
	delete(hm.recoverAttempts, serverID)
	delete(hm.lastRecover, serverID)
	hm.mu.Unlock()
}

// isStatelessServer returns true for server types that can be reconnected
// without managing external state (containers, processes, etc).
// Used to select the recovery strategy in tryRecover: inline RetryServer
// for stateless servers, async RecreateContainer for Docker-managed ones.
func (hm *HealthMonitor) isStatelessServer(srv *store.Server) bool {
	switch srv.ServerType {
	case store.ServerTypeRemote:
		return true
	case store.ServerTypeHTTP:
		var cfg store.HTTPConfig
		if err := json.Unmarshal(srv.Config, &cfg); err != nil {
			return false
		}
		return cfg.URL != "" // external HTTP only, not Docker-managed
	default:
		return false
	}
}

// pingServer sends an MCP ping request to verify the server is responsive.
// Uses the standard MCP ping method which works on established sessions
// without requiring re-initialization.
func (hm *HealthMonitor) pingServer(ctx context.Context, backend Backend) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	id, _ := json.Marshal(999999)
	req := &mcp.Request{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "ping",
	}

	resp, err := backend.Send(ctx, req)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// A valid JSON-RPC response (even an error response) means the MCP layer is alive
	if resp == nil {
		return fmt.Errorf("no response to ping")
	}

	return nil
}
