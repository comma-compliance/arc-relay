package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/comma-compliance/arc-relay/internal/config"
	"github.com/comma-compliance/arc-relay/internal/llm"
	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/middleware"
	"github.com/comma-compliance/arc-relay/internal/oauth"
	"github.com/comma-compliance/arc-relay/internal/optimizer"
	"github.com/comma-compliance/arc-relay/internal/proxy"
	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/comma-compliance/arc-relay/internal/web"
)

// Server is the main HTTP server for Arc Relay.
type Server struct {
	cfg             *config.Config
	servers         *store.ServerStore
	users           *store.UserStore
	proxy           *proxy.Manager
	oauthMgr        *oauth.Manager
	accessStore     *store.AccessStore
	profileStore    *store.ProfileStore
	requestLogs     *store.RequestLogStore
	sessionStore    *store.SessionStore
	middlewareStore *store.MiddlewareStore
	mwRegistry      *middleware.Registry
	healthMon       *proxy.HealthMonitor
	inviteStore     *store.InviteStore
	oauthTokenStore *store.OAuthTokenStore
	optimizeStore   *store.OptimizeStore
	llmClient       *llm.Client
	optimizeRunner  *optimizer.Runner
	optimizer       *middleware.Optimizer
	mux             *http.ServeMux
}

// New creates a new HTTP server.
func New(cfg *config.Config, servers *store.ServerStore, users *store.UserStore, proxyMgr *proxy.Manager, oauthMgr *oauth.Manager, accessStore *store.AccessStore, profileStore *store.ProfileStore, requestLogs *store.RequestLogStore, sessionStore *store.SessionStore, middlewareStore *store.MiddlewareStore, mwRegistry *middleware.Registry, healthMon *proxy.HealthMonitor, inviteStore *store.InviteStore, oauthTokenStore *store.OAuthTokenStore, optimizeStore *store.OptimizeStore, llmClient *llm.Client, optimizeRunner *optimizer.Runner) *Server {
	s := &Server{
		cfg:             cfg,
		servers:         servers,
		users:           users,
		proxy:           proxyMgr,
		oauthMgr:        oauthMgr,
		accessStore:     accessStore,
		profileStore:    profileStore,
		requestLogs:     requestLogs,
		sessionStore:    sessionStore,
		middlewareStore: middlewareStore,
		mwRegistry:      mwRegistry,
		healthMon:       healthMon,
		inviteStore:     inviteStore,
		oauthTokenStore: oauthTokenStore,
		optimizeStore:   optimizeStore,
		llmClient:       llmClient,
		optimizeRunner:  optimizeRunner,
		optimizer:       middleware.NewOptimizer(optimizeStore, servers),
		mux:             http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	baseURL := s.cfg.PublicBaseURL()

	// MCP proxy endpoints (API key + OAuth token auth + rate limiting)
	limiter := NewRateLimiter(100, 200) // 100 req/sec sustained, 200 burst
	s.mux.Handle("/mcp/", MCPAuth(s.users, s.oauthTokenStore, baseURL)(limiter.Middleware(http.HandlerFunc(s.handleMCPProxy))))

	// REST API for server management (API key auth only - no OAuth tokens)
	apiAuth := APIKeyAuth(s.users, baseURL)
	s.mux.Handle("/api/servers", apiAuth(http.HandlerFunc(s.handleServers)))
	s.mux.Handle("/api/servers/", apiAuth(http.HandlerFunc(s.handleServerByID)))

	// Health check
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Web UI
	webHandlers := web.NewHandlers(s.cfg, s.servers, s.users, s.proxy, s.oauthMgr, s.accessStore, s.profileStore, s.requestLogs, s.sessionStore, s.middlewareStore, s.mwRegistry, s.healthMon, s.inviteStore, s.oauthTokenStore, s.optimizeStore, s.llmClient, s.optimizeRunner)
	webHandlers.StartSessionCleanup(15 * time.Minute)
	webHandlers.RegisterRoutes(s.mux)
}

// responseWriter wraps http.ResponseWriter to capture the status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	bytes       int
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.status = http.StatusOK
		rw.wroteHeader = true
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// Unwrap exposes the underlying ResponseWriter for http.ResponseController.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Flush implements http.Flusher so SSE streaming works through the wrapper.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	hub := sentry.GetHubFromContext(r.Context())
	if hub == nil {
		hub = sentry.CurrentHub().Clone()
	}
	hub.Scope().SetRequest(r)

	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

	defer func() {
		if rv := recover(); rv != nil {
			rw.status = http.StatusInternalServerError
			hub.RecoverWithContext(r.Context(), rv)
			sentry.Flush(2 * time.Second)
			slog.Error("panic recovered", "method", r.Method, "path", r.URL.Path, "panic", rv)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

		// Log access for every request, including panics.
		level := slog.LevelInfo
		if r.URL.Path == "/health" {
			level = slog.LevelDebug
		}
		slog.Log(r.Context(), level, "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", rw.bytes,
			"remote", r.RemoteAddr,
		)
	}()

	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	rw.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	s.mux.ServeHTTP(rw, r)
}

func (s *Server) ListenAndServe() error {
	addr := s.cfg.Addr()
	slog.Info("arc relay listening", "addr", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// methodShouldLog returns true for methods that represent meaningful user actions.
func methodShouldLog(method string) bool {
	switch method {
	case "initialize", "ping", "tools/list", "resources/list", "prompts/list",
		"notifications/initialized":
		return false
	}
	return true
}

// extractEndpointName extracts the endpoint type and name from a JSON-RPC method+params.
func extractEndpointName(method string, params json.RawMessage) (endpointType, endpointName string) {
	switch method {
	case "tools/call":
		endpointType = "tool"
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(params, &p) == nil {
			endpointName = p.Name
		}
	case "resources/read":
		endpointType = "resource"
		var p struct {
			URI string `json:"uri"`
		}
		if json.Unmarshal(params, &p) == nil {
			endpointName = p.URI
		}
	case "prompts/get":
		endpointType = "prompt"
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(params, &p) == nil {
			endpointName = p.Name
		}
	}
	return
}

// handleMCPProxy is the core proxy handler. Routes /mcp/{server-name} to the right backend.
// Implements Streamable HTTP transport: handles both requests (with id) and notifications (without id).
func (s *Server) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed, use POST"}`, http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/mcp/")
	serverName := strings.Split(path, "/")[0]
	if serverName == "" {
		http.Error(w, `{"error":"missing server name in path"}`, http.StatusBadRequest)
		return
	}

	srv, err := s.servers.GetByName(serverName)
	if err != nil {
		slog.Error("error looking up server", "server", serverName, "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if srv == nil {
		http.Error(w, fmt.Sprintf(`{"error":"server %q not found"}`, serverName), http.StatusNotFound)
		return
	}

	backend, ok := s.proxy.GetBackend(srv.ID)
	if !ok {
		http.Error(w, fmt.Sprintf(`{"error":"server %q is not running"}`, serverName), http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}

	// Parse as generic JSON to detect if it's a notification (no "id" field) or a request
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	method := ""
	if m, ok := raw["method"]; ok {
		_ = json.Unmarshal(m, &method)
	}

	// Check if this is a notification (no "id" field)
	_, hasID := raw["id"]
	if !hasID {
		slog.Debug("proxy notification", "server", serverName, "method", method)
		// Forward notification to backend if it supports it, then return 202
		if notifier, ok := backend.(interface {
			SendNotification(n *mcp.Notification) error
		}); ok {
			var notif mcp.Notification
			_ = json.Unmarshal(body, &notif)
			_ = notifier.SendNotification(&notif)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// It's a request — forward and wait for response
	var mcpReq mcp.Request
	if err := json.Unmarshal(body, &mcpReq); err != nil {
		http.Error(w, `{"error":"invalid JSON-RPC request"}`, http.StatusBadRequest)
		return
	}

	slog.Debug("proxy request", "server", serverName, "method", mcpReq.Method, "id", string(mcpReq.ID))

	startTime := time.Now()
	_, endpointName := extractEndpointName(mcpReq.Method, mcpReq.Params)
	user := UserFromContext(r.Context())

	// Access control enforcement
	if s.accessStore != nil {
		if denied := s.checkEndpointAccess(r, srv.ID, &mcpReq); denied != nil {
			durationMs := time.Since(startTime).Milliseconds()
			if s.requestLogs != nil && methodShouldLog(mcpReq.Method) {
				go s.logRequest(user, srv.ID, mcpReq.Method, endpointName, durationMs, "denied", "access denied")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(denied)
			return
		}
	}

	// Build middleware pipeline for this server
	var mwMeta *middleware.RequestMeta
	var pipeline *middleware.Pipeline
	if s.mwRegistry != nil {
		pipeline = s.mwRegistry.BuildPipeline(srv.ID)
		if pipeline.Len() > 0 {
			mwMeta = &middleware.RequestMeta{
				ServerID:   srv.ID,
				ServerName: srv.Name,
				Method:     mcpReq.Method,
				ToolName:   endpointName,
				ClientIP:   r.RemoteAddr,
				RequestID:  string(mcpReq.ID),
			}
			if user != nil {
				mwMeta.UserID = user.ID
			}

			// Run request middleware
			modifiedReq, err := pipeline.ProcessRequest(r.Context(), &mcpReq, mwMeta)
			if err != nil {
				durationMs := time.Since(startTime).Milliseconds()
				if s.requestLogs != nil && methodShouldLog(mcpReq.Method) {
					go s.logRequest(user, srv.ID, mcpReq.Method, endpointName, durationMs, "blocked", "middleware: "+err.Error())
				}
				errResp := mcp.NewErrorResponse(mcpReq.ID, mcp.ErrCodeInternal, err.Error())
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(errResp)
				return
			}
			mcpReq = *modifiedReq
		}
	}

	resp, err := backend.Send(r.Context(), &mcpReq)
	durationMs := time.Since(startTime).Milliseconds()

	if err != nil {
		slog.Error("error proxying to server", "server", serverName, "err", err)
		if s.requestLogs != nil && methodShouldLog(mcpReq.Method) {
			go s.logRequest(user, srv.ID, mcpReq.Method, endpointName, durationMs, "error", err.Error())
		}
		errResp := mcp.NewErrorResponse(mcpReq.ID, mcp.ErrCodeInternal, "proxy error: "+err.Error())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(errResp)
		return
	}

	// Run response middleware
	if pipeline != nil && pipeline.Len() > 0 {
		resp, err = pipeline.ProcessResponse(r.Context(), &mcpReq, resp, mwMeta)
		if err != nil {
			if s.requestLogs != nil && methodShouldLog(mcpReq.Method) {
				go s.logRequest(user, srv.ID, mcpReq.Method, endpointName, durationMs, "blocked", "middleware: "+err.Error())
			}
			errResp := mcp.NewErrorResponse(mcpReq.ID, mcp.ErrCodeInternal, err.Error())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(errResp)
			return
		}
	}

	// Apply tool optimization if enabled for this server
	if s.optimizer != nil && mcpReq.Method == "tools/list" {
		if mwMeta == nil {
			mwMeta = &middleware.RequestMeta{
				ServerID:   srv.ID,
				ServerName: srv.Name,
				Method:     mcpReq.Method,
			}
		}
		resp, _ = s.optimizer.ProcessResponse(r.Context(), &mcpReq, resp, mwMeta)
	}

	// Filter list responses to only include endpoints the user has permission for
	if user != nil && user.ProfileID != nil && s.profileStore != nil {
		resp = s.filterListResponse(resp, mcpReq.Method, user, srv.ID)
	}

	if s.requestLogs != nil && methodShouldLog(mcpReq.Method) {
		go s.logRequest(user, srv.ID, mcpReq.Method, endpointName, durationMs, "success", "")
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// logRequest writes a request log entry in the background.
func (s *Server) logRequest(user *store.User, serverID, method, endpointName string, durationMs int64, status, errMsg string) {
	rl := &store.RequestLog{
		ServerID:     serverID,
		Method:       method,
		EndpointName: endpointName,
		DurationMs:   durationMs,
		Status:       status,
		ErrorMsg:     errMsg,
	}
	if user != nil {
		rl.UserID = user.ID
	}
	if err := s.requestLogs.Create(rl); err != nil {
		slog.Warn("failed to log request", "err", err)
	}
}

// checkEndpointAccess verifies the user has sufficient access level for the requested endpoint.
// Returns an error response if denied, nil if allowed.
func (s *Server) checkEndpointAccess(r *http.Request, serverID string, req *mcp.Request) *mcp.Response {
	user := UserFromContext(r.Context())
	if user == nil || user.Role == "admin" {
		return nil // admin bypasses all checks
	}

	endpointType, endpointName := extractEndpointName(req.Method, req.Params)
	if endpointType == "" || endpointName == "" {
		return nil // non-endpoint methods (initialize, ping, list) pass through
	}

	// Profile-based enforcement (new path)
	if user.ProfileID != nil && s.profileStore != nil {
		allowed, err := s.profileStore.CheckPermission(*user.ProfileID, serverID, endpointType, endpointName)
		if err != nil {
			slog.Error("profile permission check error", "err", err)
			return mcp.NewErrorResponse(req.ID, mcp.ErrCodeInternal, "permission check failed")
		}
		if !allowed {
			slog.Warn("access denied",
				"user", user.Username, "profile", *user.ProfileID,
				"endpoint_type", endpointType, "endpoint", endpointName, "server_id", serverID)
			return mcp.NewErrorResponse(req.ID, mcp.ErrCodeInternal, "access denied: not permitted by profile")
		}
		return nil
	}

	// Legacy tier-based check (keys without profile assignment)
	tier := s.accessStore.GetTier(serverID, endpointType, endpointName)
	if !s.accessStore.CheckAccess(user.AccessLevel, tier) {
		slog.Warn("access denied",
			"user", user.Username, "level", user.AccessLevel,
			"endpoint_type", endpointType, "endpoint", endpointName, "tier", tier)
		return mcp.NewErrorResponse(req.ID, mcp.ErrCodeInternal,
			fmt.Sprintf("access denied: requires %s level", tier))
	}

	return nil
}

// filterListResponse filters tools/list, resources/list, and prompts/list responses
// to only include endpoints the user's profile grants access to. This reduces the
// context window for LLM clients to only the actions they can actually perform.
func (s *Server) filterListResponse(resp *mcp.Response, method string, user *store.User, serverID string) *mcp.Response {
	if resp == nil || resp.Error != nil || user.ProfileID == nil {
		return resp
	}

	var endpointType, listKey, nameField string
	switch method {
	case "tools/list":
		endpointType, listKey, nameField = "tool", "tools", "name"
	case "resources/list":
		endpointType, listKey, nameField = "resource", "resources", "uri"
	case "prompts/list":
		endpointType, listKey, nameField = "prompt", "prompts", "name"
	default:
		return resp
	}

	// Get permitted endpoints for this user+server
	perms, err := s.profileStore.GetPermissionsForServer(*user.ProfileID, serverID)
	if err != nil {
		slog.Warn("error fetching profile permissions for filtering", "err", err)
		return resp
	}
	permSet := make(map[string]bool)
	for _, p := range perms {
		if p.EndpointType == endpointType {
			permSet[p.EndpointName] = true
		}
	}

	// Parse the result object
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return resp
	}
	listRaw, ok := result[listKey]
	if !ok {
		return resp
	}

	var items []json.RawMessage
	if err := json.Unmarshal(listRaw, &items); err != nil {
		return resp
	}

	// Filter to only permitted items
	var filtered []json.RawMessage
	for _, raw := range items {
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		nameRaw, ok := item[nameField]
		if !ok {
			continue
		}
		var name string
		if json.Unmarshal(nameRaw, &name) != nil {
			continue
		}
		if permSet[name] {
			filtered = append(filtered, raw)
		}
	}

	slog.Debug("profile filter applied",
		"method", method, "before", len(items), "after", len(filtered),
		"list_key", listKey, "user", user.Username, "server_id", serverID)

	// Reconstruct the result with filtered list
	if filtered == nil {
		filtered = []json.RawMessage{} // ensure JSON array, not null
	}
	filteredBytes, _ := json.Marshal(filtered)
	result[listKey] = filteredBytes
	newResult, _ := json.Marshal(result)
	resp.Result = newResult
	return resp
}

// REST API handlers

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listServers(w, r)
	case http.MethodPost:
		s.createServer(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listServers(w http.ResponseWriter, r *http.Request) {
	allServers, err := s.servers.List()
	if err != nil {
		http.Error(w, `{"error":"failed to list servers"}`, http.StatusInternalServerError)
		return
	}

	// Filter servers by user's profile permissions (admins see all)
	user := UserFromContext(r.Context())
	servers := allServers
	if user != nil && user.Role != "admin" {
		if user.ProfileID != nil && s.profileStore != nil {
			allowed, err := s.profileStore.ServerIDsForProfile(*user.ProfileID)
			if err != nil {
				slog.Warn("error getting server IDs for profile", "err", err)
				allowed = nil
			}
			var filtered []*store.Server
			for _, srv := range allServers {
				if allowed[srv.ID] {
					filtered = append(filtered, srv)
				}
			}
			servers = filtered
		} else {
			// No profile = no server visibility (deny-by-default)
			servers = nil
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if servers == nil {
		servers = []*store.Server{}
	}
	_ = json.NewEncoder(w).Encode(servers)
}

func (s *Server) createServer(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAccess(w, r) {
		return
	}

	var srv store.Server
	if err := json.NewDecoder(r.Body).Decode(&srv); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if srv.Name == "" || srv.DisplayName == "" || srv.ServerType == "" {
		http.Error(w, `{"error":"name, display_name, and server_type are required"}`, http.StatusBadRequest)
		return
	}

	// Check for duplicate name
	existing, _ := s.servers.GetByName(srv.Name)
	if existing != nil {
		http.Error(w, `{"error":"server name already exists"}`, http.StatusConflict)
		return
	}

	if err := s.servers.Create(&srv); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to create server: %s"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(srv)
}

// canAccessServerAPI checks if the API user has access to the given server.
// Admins can access all servers. Non-admins need profile permissions.
func (s *Server) canAccessServerAPI(r *http.Request, serverID string) bool {
	user := UserFromContext(r.Context())
	if user == nil {
		return false
	}
	if user.Role == "admin" {
		return true
	}
	if user.ProfileID == nil || s.profileStore == nil {
		return false
	}
	allowed, err := s.profileStore.ServerIDsForProfile(*user.ProfileID)
	if err != nil {
		return false
	}
	return allowed[serverID]
}

func (s *Server) handleServerByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/servers/")
	parts := strings.Split(path, "/")
	id := parts[0]

	if id == "" {
		http.Error(w, `{"error":"missing server id"}`, http.StatusBadRequest)
		return
	}

	// Management actions are admin-only (no further access check needed since admin bypasses)
	if len(parts) > 1 {
		switch parts[1] {
		case "start", "stop", "enumerate", "optimize", "optimize-toggle":
			if !requireAdminAccess(w, r) {
				return
			}
			// Admin already verified - dispatch directly
			switch parts[1] {
			case "start":
				s.startServer(w, r, id)
			case "stop":
				s.stopServer(w, r, id)
			case "enumerate":
				s.enumerateServer(w, r, id)
			case "optimize":
				s.runOptimize(w, r, id)
			case "optimize-toggle":
				s.toggleOptimize(w, r, id)
			}
			return
		}

		// Read-only actions (endpoints, health) only require server access
		if !s.canAccessServerAPI(r, id) {
			jsonError(w, `{"error":"server not found"}`, http.StatusNotFound)
			return
		}

		switch parts[1] {
		case "endpoints":
			s.getEndpoints(w, r, id)
		case "health":
			s.checkServerHealth(w, r, id)
		case "tool-audit":
			s.getToolAudit(w, r, id)
		default:
			http.Error(w, `{"error":"unknown action"}`, http.StatusNotFound)
		}
		return
	}

	// Object-level access check for GET; admin-only for PUT/DELETE
	switch r.Method {
	case http.MethodGet:
		if !s.canAccessServerAPI(r, id) {
			jsonError(w, `{"error":"server not found"}`, http.StatusNotFound)
			return
		}
		s.getServer(w, r, id)
	case http.MethodPut:
		if !requireAdminAccess(w, r) {
			return
		}
		s.updateServer(w, r, id)
	case http.MethodDelete:
		if !requireAdminAccess(w, r) {
			return
		}
		s.deleteServer(w, r, id)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getServer(w http.ResponseWriter, r *http.Request, id string) {
	srv, err := s.servers.Get(id)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(srv)
}

func (s *Server) updateServer(w http.ResponseWriter, r *http.Request, id string) {
	if !requireWriteAccess(w, r) {
		return
	}

	existing, err := s.servers.Get(id)
	if err != nil || existing == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}

	var srv store.Server
	if err := json.NewDecoder(r.Body).Decode(&srv); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	srv.ID = id

	if err := store.ValidateSlug(srv.Name); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	oldName := existing.Name
	if err := s.servers.Update(&srv); err != nil {
		if errors.Is(err, store.ErrSlugConflict) {
			http.Error(w, `{"error":"server slug already exists"}`, http.StatusConflict)
			return
		}
		http.Error(w, `{"error":"failed to update server"}`, http.StatusInternalServerError)
		return
	}

	if oldName != srv.Name {
		slog.Info("server slug renamed via API", "server_id", id, "old_name", oldName, "new_name", srv.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(srv)
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request, id string) {
	if !requireAdminAccess(w, r) {
		return
	}

	_ = s.proxy.StopServer(r.Context(), id)
	if err := s.servers.Delete(id); err != nil {
		http.Error(w, `{"error":"failed to delete server"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) startServer(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if !requireWriteAccess(w, r) {
		return
	}

	srv, err := s.servers.Get(id)
	if err != nil || srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}

	// Use a detached context so the build/start survives client disconnects.
	// Image builds can take minutes; if the CLI or browser closes the connection,
	// we still want the operation to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := s.proxy.StartServer(ctx, srv); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to start server: %s"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) stopServer(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if !requireWriteAccess(w, r) {
		return
	}

	if err := s.proxy.StopServer(r.Context(), id); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to stop server: %s"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) enumerateServer(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	endpoints, err := s.proxy.EnumerateServer(r.Context(), id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"enumeration failed: %s"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(endpoints)
}

func (s *Server) checkServerHealth(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	srv, err := s.servers.Get(id)
	if err != nil || srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}

	health, healthErr := s.healthMon.CheckHealth(r.Context(), id)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          srv.Status,
		"health":          health,
		"health_check_at": time.Now().Format(time.RFC3339),
		"health_error":    healthErr,
	})
}

func (s *Server) getEndpoints(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	endpoints := s.proxy.Endpoints.Get(id)
	if endpoints == nil {
		http.Error(w, `{"error":"no endpoints cached for this server"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(endpoints)
}

func (s *Server) getToolAudit(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	srv, err := s.servers.Get(id)
	if err != nil || srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}

	endpoints := s.proxy.Endpoints.Get(id)
	if endpoints == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.ToolAudit{
			ServerID:   id,
			ServerName: srv.Name,
			Status:     "no_endpoints",
		})
		return
	}

	stats, totalChars := mcp.AuditTools(endpoints.Tools)
	toolsHash := mcp.HashTools(endpoints.Tools)

	audit := mcp.ToolAudit{
		ServerID:      id,
		ServerName:    srv.Name,
		ToolCount:     len(endpoints.Tools),
		OriginalChars: totalChars,
		EstTokens:     totalChars / 4,
		ToolsHash:     toolsHash,
		Tools:         stats,
		Status:        "none",
	}

	// Check optimization status
	if s.optimizeStore != nil {
		opt, err := s.optimizeStore.Get(id)
		if err == nil && opt != nil {
			audit.HasOptimized = true
			audit.Status = opt.Status
			audit.IsStale = opt.Status == "stale" || opt.ToolsHash != toolsHash
			if opt.OptimizedChars > 0 { // stored result, also kept across a re-run
				audit.OptimizedChars = opt.OptimizedChars
				if totalChars > 0 {
					audit.SavingsPercent = float64(totalChars-opt.OptimizedChars) / float64(totalChars) * 100
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(audit)
}

func (s *Server) runOptimize(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	srv, err := s.servers.Get(id)
	if err != nil || srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}

	var tools []mcp.Tool
	if endpoints := s.proxy.Endpoints.Get(id); endpoints != nil {
		tools = endpoints.Tools
	}

	if err := s.optimizeRunner.Start(id, srv.Name, tools); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, optimizer.ErrNoLLM):
			status = http.StatusServiceUnavailable
		case errors.Is(err, optimizer.ErrNoTools):
			status = http.StatusBadRequest
		case errors.Is(err, optimizer.ErrAlreadyRunning):
			status = http.StatusConflict
		default:
			slog.Error("failed to start optimization", "server_id", id, "err", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// "running" is kept for API compatibility; the job may briefly be queued.
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
}

func (s *Server) toggleOptimize(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := s.servers.SetOptimizeEnabled(id, req.Enabled); err != nil {
		slog.Error("failed to toggle optimize", "server_id", id, "enabled", req.Enabled, "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	slog.Info("optimize toggled", "server_id", id, "enabled", req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"enabled": req.Enabled})
}
