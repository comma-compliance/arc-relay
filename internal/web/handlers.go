package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/comma-compliance/arc-relay/internal/catalog"
	"github.com/comma-compliance/arc-relay/internal/config"
	"github.com/comma-compliance/arc-relay/internal/llm"
	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/middleware"
	"github.com/comma-compliance/arc-relay/internal/oauth"
	"github.com/comma-compliance/arc-relay/internal/proxy"
	"github.com/comma-compliance/arc-relay/internal/store"
)

//go:embed templates/*.html templates/middleware/*.html
var templateFS embed.FS

// Flash represents a one-time notification message.
type Flash struct {
	Type    string // "success", "danger", "info"
	Message string
}

// ConfigDisplay is a view-friendly representation of server config.
type ConfigDisplay struct {
	Image            string
	Command          string
	Port             int
	URL              string
	HealthCheck      string
	AuthType         string
	EnvKeys          []string
	EnvVars          map[string]string
	OAuthAuthorized  bool
	OAuthScopes      string
	OAuthTokenExpiry string
	// Build fields
	HasBuild     bool
	BuildRuntime string
	BuildPackage string
	BuildVersion string
	BuildGitURL  string
	BuildGitRef  string
	BuildCustom  bool
	// Image staleness fields
	ImageID          string // sha256 ID of the current image tag
	ImageIDShort     string // truncated image ID for display
	ImageCreated     string // human-readable image creation time
	ImageAge         string // human-readable age (e.g., "3 days ago")
	ContainerImageID string // sha256 ID used when container was created
	ContainerIDShort string // truncated container image ID for display
	ImageStale       bool   // true if container is running an older image
	IsDocker         bool   // true if this server uses Docker (has an image)
	HasBuildConfig   bool   // true if this is a locally-built image (not from registry)
}

// MiddlewareCard is the per-card view model passed to the middleware template loop.
type MiddlewareCard struct {
	Descriptor middleware.Descriptor
	Enabled    bool
	Config     json.RawMessage
	ServerID   string
	CustomData map[string]any // middleware-specific data (e.g. ArchiveQueueStatus)
}

// loginRateLimiter tracks failed login attempts per IP.
type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	rl := &loginRateLimiter{attempts: make(map[string][]time.Time)}
	go rl.cleanup()
	return rl
}

// allow returns true if the IP is allowed to attempt login.
// Limit: 5 attempts per 15 minutes.
func (rl *loginRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	recent := rl.attempts[ip]
	filtered := recent[:0]
	for _, t := range recent {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	rl.attempts[ip] = filtered
	return len(filtered) < 5
}

func (rl *loginRateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

func (rl *loginRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-15 * time.Minute)
		for ip, attempts := range rl.attempts {
			filtered := attempts[:0]
			for _, t := range attempts {
				if t.After(cutoff) {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = filtered
			}
		}
		rl.mu.Unlock()
	}
}

// Handlers holds dependencies for web UI handlers.
type Handlers struct {
	cfg             *config.Config
	servers         *store.ServerStore
	users           *store.UserStore
	proxy           *proxy.Manager
	oauth           *oauth.Manager
	accessStore     *store.AccessStore
	profileStore    *store.ProfileStore
	requestLogs     *store.RequestLogStore
	sessionStore    *store.SessionStore
	middlewareStore *store.MiddlewareStore
	mwRegistry      *middleware.Registry
	healthMon       *proxy.HealthMonitor
	catalogClient   *catalog.Client
	deviceAuth      *deviceAuthStore
	archiveHandoff  *archiveHandoffStore
	inviteStore     *store.InviteStore
	optimizeStore   *store.OptimizeStore
	llmClient       *llm.Client
	oauthProv       *oauthProvider
	tmpls           map[string]*template.Template
	csrfSecret      []byte
	loginLimiter    *loginRateLimiter
	flashKeys       sync.Map // nonce -> raw API key (shown once after redirect)
}

func NewHandlers(cfg *config.Config, servers *store.ServerStore, users *store.UserStore, proxyMgr *proxy.Manager, oauthMgr *oauth.Manager, accessStore *store.AccessStore, profileStore *store.ProfileStore, requestLogs *store.RequestLogStore, sessionStore *store.SessionStore, middlewareStore *store.MiddlewareStore, mwRegistry *middleware.Registry, healthMon *proxy.HealthMonitor, inviteStore *store.InviteStore, oauthTokenStore *store.OAuthTokenStore, optimizeStore *store.OptimizeStore, llmClient *llm.Client) *Handlers {
	// Generate a per-process CSRF secret. Use session_secret from config if set.
	csrfSecret := []byte(cfg.Auth.SessionSecret)
	if len(csrfSecret) == 0 {
		csrfSecret = make([]byte, 32)
		if _, err := rand.Read(csrfSecret); err != nil {
			panic("failed to generate CSRF secret: " + err.Error())
		}
	}
	h := &Handlers{
		cfg:             cfg,
		servers:         servers,
		users:           users,
		proxy:           proxyMgr,
		oauth:           oauthMgr,
		accessStore:     accessStore,
		profileStore:    profileStore,
		requestLogs:     requestLogs,
		sessionStore:    sessionStore,
		middlewareStore: middlewareStore,
		mwRegistry:      mwRegistry,
		healthMon:       healthMon,
		catalogClient:   catalog.NewClient(),
		deviceAuth:      newDeviceAuthStore(),
		archiveHandoff:  newArchiveHandoffStore(),
		inviteStore:     inviteStore,
		optimizeStore:   optimizeStore,
		llmClient:       llmClient,
		oauthProv:       newOAuthProvider(oauthTokenStore, store.NewOAuthClientStore(oauthTokenStore.DB()), store.NewOAuthRefreshTokenStore(oauthTokenStore.DB())),
		tmpls:           make(map[string]*template.Template),
		csrfSecret:      csrfSecret,
		loginLimiter:    newLoginRateLimiter(),
	}

	// Template helper functions
	funcMap := template.FuncMap{
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"commas": func(n int) string {
			s := fmt.Sprintf("%d", n)
			if n < 0 {
				return "-" + commaFormat(s[1:])
			}
			return commaFormat(s)
		},
		"pages": func(current, total int) []int {
			// Returns page numbers to display, with -1 for ellipsis
			if total <= 7 {
				r := make([]int, total)
				for i := range r {
					r[i] = i + 1
				}
				return r
			}
			var r []int
			r = append(r, 1)
			if current > 3 {
				r = append(r, -1)
			}
			for i := current - 1; i <= current+1; i++ {
				if i > 1 && i < total {
					r = append(r, i)
				}
			}
			if current < total-2 {
				r = append(r, -1)
			}
			r = append(r, total)
			return r
		},
	}

	// Parse each page template together with the layout and middleware partials.
	// Middleware partials define named templates (e.g. "middleware_archive") that
	// can be invoked from server_detail.html via {{callTemplate .TemplateName .}}.
	pages := []string{"dashboard.html", "server_form.html", "server_detail.html", "users.html", "api_keys.html", "logs.html", "device_auth.html", "profiles.html", "profile_detail.html", "oauth_authorize.html", "connect_desktop.html", "change_password.html"}
	for _, page := range pages {
		t := template.New("").Funcs(funcMap)
		// Add callTemplate func that captures this template set for dynamic dispatch.
		// Go's {{template}} requires a string literal; this func lets the range loop
		// invoke a partial by name stored in a Descriptor.
		t.Funcs(template.FuncMap{
			"callTemplate": func(name string, data interface{}) (template.HTML, error) {
				var buf bytes.Buffer
				if err := t.ExecuteTemplate(&buf, name, data); err != nil {
					slog.Error("middleware partial failed", "template", name, "err", err)
					// Render an error card instead of propagating the failure
					// up to the page template, which would kill the entire page.
					return template.HTML(`<div class="mw-card" style="border-color:#dc3545"><strong>` + // #nosec G203 -- all interpolated values are HTMLEscapeString'd
						template.HTMLEscapeString(name) +
						`</strong> <span style="color:#dc3545">failed to render: ` +
						template.HTMLEscapeString(err.Error()) + `</span></div>`), nil
				}
				return template.HTML(buf.String()), nil // #nosec G203 -- output is from html/template.ExecuteTemplate which auto-escapes
			},
		})
		template.Must(t.ParseFS(templateFS, "templates/layout.html", "templates/middleware/*.html", "templates/"+page))
		h.tmpls[page] = t
	}
	// Login and invite_redeem are standalone (no layout)
	h.tmpls["login.html"] = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/login.html"))
	h.tmpls["invite_redeem.html"] = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/invite_redeem.html"))

	return h
}

// StartSessionCleanup runs a background goroutine that purges expired sessions.
func (h *Handlers) StartSessionCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			h.sessionStore.Cleanup()
		}
	}()
}

// RegisterRoutes adds web UI routes to the given mux.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	// OAuth 2.1 Authorization Server (provider) - discovery + endpoints
	mux.HandleFunc("/.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", h.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", h.handleAuthorizationServerMetadata)
	mux.HandleFunc("/oauth/authorize", h.handleOAuthAuthorize) // Session auth checked internally
	mux.HandleFunc("/authorize", h.handleOAuthAuthorize)       // Alias - some clients use /authorize directly
	mux.HandleFunc("/oauth/token", h.handleOAuthToken)         // No auth - code/PKCE is proof
	mux.HandleFunc("/token", h.handleOAuthToken)               // Alias
	mux.HandleFunc("/oauth/register", h.handleOAuthRegister)   // No auth - DCR
	mux.HandleFunc("/register", h.handleOAuthRegister)         // Alias

	// Desktop onboarding
	mux.HandleFunc("/connect/desktop", h.requireAuth(h.handleConnectDesktop))

	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc("/", h.requireAuth(h.handleDashboard))
	mux.HandleFunc("/servers", h.requireAuth(h.handleServersList))
	mux.HandleFunc("/servers/new", h.requireAuth(h.handleServerNew))
	mux.HandleFunc("/servers/", h.requireAuth(h.handleServerRoutes))
	mux.HandleFunc("/logs", h.requireAuth(h.handleLogs))
	mux.HandleFunc("/users", h.requireAuth(h.handleUsers))
	mux.HandleFunc("/users/", h.requireAuth(h.handleUserRoutes))
	mux.HandleFunc("/api-keys", h.requireAuth(h.handleAPIKeys))
	mux.HandleFunc("/api-keys/", h.requireAuth(h.handleAPIKeyRoutes))
	mux.HandleFunc("/profiles", h.requireAuth(h.handleProfiles))
	mux.HandleFunc("/profiles/", h.requireAuth(h.handleProfileRoutes))
	mux.HandleFunc("/api/middleware/", h.requireAuth(h.handleMiddlewareAPI))
	mux.HandleFunc("/api/catalog/search", h.requireAuth(h.handleCatalogSearch))
	mux.HandleFunc("/api/catalog/discover-oauth", h.requireAuth(h.handleCatalogDiscoverOAuth))
	mux.HandleFunc("/oauth/start/", h.requireAuth(h.handleOAuthStart))
	mux.HandleFunc("/oauth/callback", h.handleOAuthCallback) // No session auth — browser redirect from provider

	// Device auth flow (RFC 8628-style)
	mux.HandleFunc("/api/auth/device", h.handleDeviceAuthStart)       // No auth — CLI calls before having a key
	mux.HandleFunc("/api/auth/device/token", h.handleDeviceAuthToken) // No auth — CLI polls for token
	mux.HandleFunc("/auth/device", h.handleDeviceAuthPage)            // Session auth checked internally (redirects to login)

	// Invite token exchange (no auth — token is proof)
	mux.HandleFunc("/api/auth/invite", h.handleInviteExchange)
	mux.HandleFunc("/invite/", h.handleInviteRedeem) // Browser account setup

	// Self-service password change
	mux.HandleFunc("/account/password", h.requireAuth(h.handleChangePassword))

	// Binary hosting for arc-sync CLI
	mux.HandleFunc("/install.sh", h.handleInstallScript)
	mux.HandleFunc("/download/", h.handleDownload)
}

// --- CSRF ---

// csrfToken computes an HMAC-based CSRF token from the session ID.
func (h *Handlers) csrfToken(sessionID string) string {
	mac := hmac.New(sha256.New, h.csrfSecret)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// validateCSRF checks the CSRF token from form data or X-CSRF-Token header.
func (h *Handlers) validateCSRF(r *http.Request, sessionID string) bool {
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return false
	}
	expected := h.csrfToken(sessionID)
	return hmac.Equal([]byte(token), []byte(expected))
}

// clientIP extracts the client IP from the request for rate limiting.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- Auth ---

func (h *Handlers) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			// For non-browser clients hitting the root, return 401 with OAuth
			// discovery instead of redirecting to a login page they can't use.
			accept := r.Header.Get("Accept")
			if !strings.Contains(accept, "text/html") && r.URL.Path == "/" {
				baseURL := h.cfg.PublicBaseURL()
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(
					`Bearer resource_metadata="%s/.well-known/oauth-protected-resource%s"`, baseURL, r.URL.Path))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"error":"authentication required"}`)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user, _, ok := h.sessionStore.Get(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// Force password change before allowing any other page
		if user.MustChangePassword && r.URL.Path != "/account/password" && r.URL.Path != "/logout" {
			http.Redirect(w, r, "/account/password", http.StatusFound)
			return
		}
		// Validate CSRF for state-changing requests
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if !h.validateCSRF(r, cookie.Value) {
				// API endpoints expect JSON; HTML forms get a plain-text response.
				// This keeps the JS fetch() callers from failing JSON.parse on
				// the error body with an opaque "Unexpected token" error.
				if strings.HasPrefix(r.URL.Path, "/api/") {
					writeJSON(w, http.StatusForbidden, map[string]string{
						"error": "csrf_invalid",
						"hint":  "Your session's CSRF token is stale. Reload the page and try again.",
					})
				} else {
					http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
				}
				return
			}
		}
		ctx := setUser(r.Context(), user)
		ctx = setSessionID(ctx, cookie.Value)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		next := r.URL.Query().Get("next")
		h.renderLogin(w, "", next)
		return
	}

	ip := clientIP(r)
	if !h.loginLimiter.allow(ip) {
		h.renderLogin(w, "Too many login attempts. Please try again later.", "")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	next := r.FormValue("next")

	user, err := h.users.Authenticate(username, password)
	if err != nil || user == nil {
		h.loginLimiter.record(ip)
		h.renderLogin(w, "Invalid username or password", next)
		return
	}

	sessionID, err := generateID()
	if err != nil {
		slog.Error("failed to generate session ID", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := h.sessionStore.Create(sessionID, user.ID, expiresAt); err != nil {
		slog.Error("failed to create session", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 - Secure is conditional for local dev (http)
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // 30 days
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.cfg.PublicBaseURL(), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	// Force password change if required
	if user.MustChangePassword {
		http.Redirect(w, r, "/account/password", http.StatusFound)
		return
	}

	// Redirect to the original destination if set, but only allow local paths
	redirectTo := "/"
	if next != "" && strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		redirectTo = next
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session"); err == nil {
		h.sessionStore.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}) // #nosec G124 - clearing cookie
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- Authorization Helpers ---

// accessibleServers filters a server list based on the user's profile permissions.
// Admins see all servers. Profile users see only servers their profile grants access to.
// Users with no profile see nothing (deny-by-default).
func (h *Handlers) accessibleServers(user *store.User, servers []*store.Server) []*store.Server {
	if user.Role == "admin" {
		return servers
	}
	if user.ProfileID == nil {
		return nil
	}
	allowed, err := h.profileStore.ServerIDsForProfile(*user.ProfileID)
	if err != nil || len(allowed) == 0 {
		return nil
	}
	var result []*store.Server
	for _, s := range servers {
		if allowed[s.ID] {
			result = append(result, s)
		}
	}
	return result
}

// canAccessServer returns true if the user has profile permissions for the given server.
func (h *Handlers) canAccessServer(user *store.User, serverID string) bool {
	if user.Role == "admin" {
		return true
	}
	if user.ProfileID == nil {
		return false
	}
	allowed, err := h.profileStore.ServerIDsForProfile(*user.ProfileID)
	if err != nil {
		return false
	}
	return allowed[serverID]
}

// requireAdmin returns true if the user is an admin. If not, writes a 403 response and returns false.
func (h *Handlers) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return false
	}
	return true
}

// --- Dashboard ---

func (h *Handlers) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := getUser(r)
	isAdmin := user.Role == "admin"

	allServers, _ := h.servers.List()
	servers := h.accessibleServers(user, allServers)

	runningCount := 0
	endpointCounts := make(map[string]int) // server ID -> tool count
	for _, s := range servers {
		if s.Status == store.StatusRunning {
			runningCount++
		}
		if ep := h.proxy.Endpoints.Get(s.ID); ep != nil {
			endpointCounts[s.ID] = len(ep.Tools) + len(ep.Resources) + len(ep.Prompts)
		}
	}

	data := map[string]any{
		"Nav":            "dashboard",
		"User":           user,
		"Servers":        servers,
		"RunningCount":   runningCount,
		"EndpointCounts": endpointCounts,
		"IsAdmin":        isAdmin,
	}

	// Admin-only data: stats, logs, user count
	if isAdmin {
		users, _ := h.users.List()
		data["UserCount"] = len(users)
		if h.requestLogs != nil {
			stats, _ := h.requestLogs.Stats()
			recentLogs, _ := h.requestLogs.Recent(10)
			serverCallCounts, _ := h.requestLogs.ServerTotalCounts()
			data["Stats"] = stats
			data["RecentLogs"] = recentLogs
			data["ServerCallCounts"] = serverCallCounts
		}
	}

	h.render(w, r, "dashboard.html", data)
}

// --- Logs ---

func (h *Handlers) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	servers, _ := h.servers.List()

	q := r.URL.Query()
	serverFilter := q.Get("server")
	userFilter := q.Get("user")
	statusFilter := q.Get("status")
	pageStr := q.Get("page")

	const perPage = 50
	page := 1
	if pageStr != "" {
		_, _ = fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
	}

	var logs []*store.RequestLog
	var total int
	var logUsers []struct{ ID, Username string }

	if h.requestLogs != nil {
		logs, total, _ = h.requestLogs.FilteredLogs(store.LogFilter{
			ServerID: serverFilter,
			UserID:   userFilter,
			Status:   statusFilter,
			Limit:    perPage,
			Offset:   (page - 1) * perPage,
		})
		logUsers, _ = h.requestLogs.DistinctUsers()
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}

	h.render(w, r, "logs.html", map[string]any{
		"Nav":          "logs",
		"User":         getUser(r),
		"Logs":         logs,
		"Servers":      servers,
		"LogUsers":     logUsers,
		"ServerFilter": serverFilter,
		"UserFilter":   userFilter,
		"StatusFilter": statusFilter,
		"Page":         page,
		"TotalPages":   totalPages,
		"Total":        total,
	})
}

// --- Servers ---

func (h *Handlers) handleServersList(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) handleServerNew(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		h.render(w, r, "server_form.html", map[string]any{
			"Nav":             "servers",
			"User":            getUser(r),
			"IsEdit":          false,
			"Server":          &store.Server{},
			"ServerType":      "stdio",
			"RemoteAuthType":  "none",
			"StdioMode":       "image",
			"BuildRuntime":    "",
			"BuildPackage":    "",
			"BuildVersion":    "",
			"BuildGitURL":     "",
			"BuildDockerfile": "",
		})
		return
	}

	srv, err := h.parseServerForm(r)
	if err != nil {
		h.render(w, r, "server_form.html", h.serverFormData(r, nil, err.Error()))
		return
	}

	if err := h.servers.Create(srv); err != nil {
		h.render(w, r, "server_form.html", h.serverFormData(r, srv, fmt.Sprintf("Failed to create server: %s", err)))
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/servers/%s", srv.ID), http.StatusFound)
}

func (h *Handlers) handleServerRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/servers/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	if id == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	// Server detail is accessible to users with profile permissions; all other actions are admin-only
	switch action {
	case "":
		h.handleServerDetail(w, r, id)
	case "edit", "start", "stop", "delete", "enumerate", "rebuild",
		"rebuild-restart", "recreate", "recreate-stream",
		"access-tier", "middleware", "health-check",
		"optimize", "optimize-toggle", "tool-audit":
		if !h.requireAdmin(w, r) {
			return
		}
		switch action {
		case "edit":
			h.handleServerEdit(w, r, id)
		case "start":
			h.handleServerStart(w, r, id)
		case "stop":
			h.handleServerStop(w, r, id)
		case "delete":
			h.handleServerDelete(w, r, id)
		case "enumerate":
			h.handleServerEnumerate(w, r, id)
		case "rebuild":
			h.handleServerRebuild(w, r, id)
		case "rebuild-restart":
			h.handleServerRebuildRestart(w, r, id)
		case "recreate":
			h.handleServerRecreate(w, r, id)
		case "recreate-stream":
			h.handleRecreateStream(w, r, id)
		case "access-tier":
			h.handleAccessTier(w, r, id)
		case "middleware":
			h.handleServerMiddleware(w, r, id)
		case "health-check":
			h.handleServerHealthCheck(w, r, id)
		case "optimize":
			h.handleServerOptimize(w, r, id)
		case "optimize-toggle":
			h.handleServerOptimizeToggle(w, r, id)
		case "tool-audit":
			h.handleServerToolAudit(w, r, id)
		}
	default:
		http.NotFound(w, r)
	}
}

func (h *Handlers) handleServerDetail(w http.ResponseWriter, r *http.Request, id string) {
	user := getUser(r)
	srv, err := h.servers.Get(id)
	if err != nil || srv == nil {
		http.NotFound(w, r)
		return
	}

	// Non-admins can only view servers they have profile permissions for
	if !h.canAccessServer(user, id) {
		http.NotFound(w, r)
		return
	}

	isAdmin := user.Role == "admin"

	data := map[string]any{
		"Nav":     "servers",
		"User":    user,
		"Server":  srv,
		"BaseURL": h.cfg.PublicBaseURL(),
		"IsAdmin": isAdmin,
	}

	// Non-admins see basic server info and their permitted endpoints only
	if isAdmin {
		// Build access tier lookup map: "type:name" -> tier
		tierMap := make(map[string]string)
		if tiers, err := h.accessStore.GetAllTiers(srv.ID); err == nil {
			for _, t := range tiers {
				tierMap[t.EndpointType+":"+t.EndpointName] = t.AccessTier
			}
		}

		// Endpoint usage counts and recent logs
		endpointUsage := make(map[string]store.EndpointCallCount)
		var serverLogs []*store.RequestLog
		if h.requestLogs != nil {
			if counts, err := h.requestLogs.EndpointCounts(srv.ID); err == nil {
				for _, ec := range counts {
					endpointUsage[ec.EndpointName] = ec
				}
			}
			serverLogs, _ = h.requestLogs.ByServer(srv.ID, 20)
		}

		// Middleware configs and events - build per-card view models
		var mwCards []MiddlewareCard
		var mwEvents []*store.MiddlewareEvent
		if h.middlewareStore != nil {
			mwConfigs, _ := h.middlewareStore.GetForServer(srv.ID)
			mwEvents, _ = h.middlewareStore.RecentEvents(srv.ID, 20)

			// Index DB configs by middleware name for easy lookup
			configByName := make(map[string]*store.MiddlewareConfig, len(mwConfigs))
			for _, mc := range mwConfigs {
				configByName[mc.Middleware] = mc
			}

			for _, desc := range h.mwRegistry.Descriptors() {
				card := MiddlewareCard{
					Descriptor: desc,
					ServerID:   srv.ID,
					CustomData: make(map[string]any),
				}
				if mc, ok := configByName[desc.Name]; ok {
					card.Enabled = mc.Enabled
					card.Config = mc.Config
				}
				// Archive-specific custom data
				if desc.Name == "archive" {
					if gac, err := h.middlewareStore.GetGlobal("archive"); err == nil && gac != nil {
						card.CustomData["GlobalArchiveConfig"] = decorateArchiveConfigForDisplay(gac.Config)
					}
					if disp := h.mwRegistry.ArchiveDispatcher(); disp != nil {
						card.CustomData["ArchiveQueueStatus"] = disp.Status()
					}
				}
				mwCards = append(mwCards, card)
			}
		}

		cd := buildConfigDisplay(srv)

		// Populate image staleness info for Docker-managed servers
		if cd.Image != "" && h.proxy.Docker() != nil {
			ctx := r.Context()
			if imgInfo, err := h.proxy.Docker().InspectImage(ctx, cd.Image); err == nil {
				cd.ImageID = imgInfo.ID
				cd.ImageIDShort = truncateImageID(imgInfo.ID)
				if !imgInfo.Created.IsZero() {
					cd.ImageCreated = imgInfo.Created.Format("2006-01-02 15:04:05")
					cd.ImageAge = humanizeAge(imgInfo.Created)
				}
			}
			if containerID, ok := h.proxy.GetContainerID(srv.ID); ok {
				if cImgID, err := h.proxy.Docker().GetContainerImageID(ctx, containerID); err == nil {
					cd.ContainerImageID = cImgID
					cd.ContainerIDShort = truncateImageID(cImgID)
					cd.ImageStale = cd.ImageID != "" && cd.ImageID != cImgID
				}
			}
		}

		data["ConfigDisplay"] = cd
		data["TierMap"] = tierMap
		data["EndpointUsage"] = endpointUsage
		data["RecentLogs"] = serverLogs
		data["MiddlewareCards"] = mwCards
		data["MiddlewareEvents"] = mwEvents
	}

	// All users see their permitted endpoints
	endpoints := h.proxy.Endpoints.Get(srv.ID)
	data["Endpoints"] = endpoints

	// Tool optimization audit data (admin only)
	if isAdmin && h.optimizeStore != nil && endpoints != nil && len(endpoints.Tools) > 0 {
		stats, totalChars := mcp.AuditTools(endpoints.Tools)
		toolsHash := mcp.HashTools(endpoints.Tools)
		auditData := map[string]any{
			"ToolCount":     len(endpoints.Tools),
			"OriginalChars": totalChars,
			"EstTokens":     totalChars / 4,
			"ToolsHash":     toolsHash,
			"Tools":         stats,
			"LLMAvailable":  h.llmClient != nil && h.llmClient.Available(),
		}
		if opt, err := h.optimizeStore.Get(srv.ID); err == nil && opt != nil {
			auditData["HasOptimized"] = true
			auditData["Status"] = opt.Status
			auditData["IsStale"] = opt.ToolsHash != toolsHash
			auditData["Model"] = opt.Model
			auditData["ErrorMsg"] = opt.ErrorMsg
			if opt.Status == "ready" || opt.Status == "stale" {
				auditData["OptimizedChars"] = opt.OptimizedChars
				auditData["OptimizedTokens"] = opt.OptimizedChars / 4
				if totalChars > 0 {
					auditData["SavingsPercent"] = int(float64(totalChars-opt.OptimizedChars) / float64(totalChars) * 100)
				}
				var optTools []mcp.Tool
				if json.Unmarshal(opt.OptimizedTools, &optTools) == nil {
					optMap := make(map[string]mcp.Tool, len(optTools))
					for _, t := range optTools {
						optMap[t.Name] = t
					}
					for i, s := range stats {
						if ot, ok := optMap[s.Name]; ok {
							stats[i].OptDescChars = len(ot.Description)
							stats[i].OptSchemaChar = len(ot.InputSchema)
							stats[i].OptTotalChars = len(ot.Description) + len(ot.InputSchema)
						}
					}
					auditData["Tools"] = stats
				}
			}
		}
		data["ToolAudit"] = auditData
	}

	h.render(w, r, "server_detail.html", data)
}

func (h *Handlers) handleServerEdit(w http.ResponseWriter, r *http.Request, id string) {
	srv, err := h.servers.Get(id)
	if err != nil || srv == nil {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		formData := serverToFormData(srv)
		formData["Nav"] = "servers"
		formData["User"] = getUser(r)
		formData["IsEdit"] = true
		formData["Server"] = srv
		h.render(w, r, "server_form.html", formData)
		return
	}

	updated, err := h.parseServerForm(r)
	if err != nil {
		formData := serverToFormData(srv)
		formData["Nav"] = "servers"
		formData["User"] = getUser(r)
		formData["IsEdit"] = true
		formData["Server"] = srv
		formData["Error"] = err.Error()
		h.render(w, r, "server_form.html", formData)
		return
	}

	// Validate slug format
	if err := store.ValidateSlug(updated.Name); err != nil {
		formData := serverToFormData(updated)
		formData["Nav"] = "servers"
		formData["User"] = getUser(r)
		formData["IsEdit"] = true
		formData["Server"] = srv
		formData["Error"] = err.Error()
		h.render(w, r, "server_form.html", formData)
		return
	}

	// Preserve fields not in the form
	updated.ID = id
	updated.Status = srv.Status
	updated.ErrorMsg = srv.ErrorMsg
	updated.CreatedAt = srv.CreatedAt

	// For build-mode stdio servers, preserve the built image tag if package hasn't changed
	if updated.ServerType == store.ServerTypeStdio {
		var oldCfg, newCfg store.StdioConfig
		if json.Unmarshal(srv.Config, &oldCfg) == nil && json.Unmarshal(updated.Config, &newCfg) == nil {
			if newCfg.Build != nil && oldCfg.Build != nil && oldCfg.Image != "" {
				if newCfg.Build.Package == oldCfg.Build.Package &&
					newCfg.Build.Version == oldCfg.Build.Version &&
					newCfg.Build.Runtime == oldCfg.Build.Runtime {
					newCfg.Image = oldCfg.Image
					updated.Config, _ = json.Marshal(newCfg)
				}
			}
		}
	}

	// For OAuth servers, preserve tokens from the existing config
	if updated.ServerType == store.ServerTypeRemote {
		var oldCfg, newCfg store.RemoteConfig
		if json.Unmarshal(srv.Config, &oldCfg) == nil && json.Unmarshal(updated.Config, &newCfg) == nil {
			if newCfg.Auth.AccessToken == "" && oldCfg.Auth.AccessToken != "" {
				newCfg.Auth.AccessToken = oldCfg.Auth.AccessToken
				newCfg.Auth.RefreshToken = oldCfg.Auth.RefreshToken
				newCfg.Auth.TokenExpiry = oldCfg.Auth.TokenExpiry
			}
			// Preserve registration tracking fields
			if newCfg.Auth.RegisteredRedirectURI == "" {
				newCfg.Auth.RegisteredRedirectURI = oldCfg.Auth.RegisteredRedirectURI
			}
			if newCfg.Auth.RegistrationEndpoint == "" {
				newCfg.Auth.RegistrationEndpoint = oldCfg.Auth.RegistrationEndpoint
			}
			updated.Config, _ = json.Marshal(newCfg)
		}
	}

	oldName := srv.Name
	if err := h.servers.Update(updated); err != nil {
		if errors.Is(err, store.ErrSlugConflict) {
			formData := serverToFormData(updated)
			formData["Nav"] = "servers"
			formData["User"] = getUser(r)
			formData["IsEdit"] = true
			formData["Server"] = srv
			formData["Error"] = fmt.Sprintf("Slug %q is already taken by another server.", updated.Name)
			h.render(w, r, "server_form.html", formData)
			return
		}
		slog.Error("error updating server", "server_id", id, "err", err)
		http.Error(w, "Failed to update server", http.StatusInternalServerError)
		return
	}

	if oldName != updated.Name {
		slog.Info("server slug renamed", "server_id", id, "old_name", oldName, "new_name", updated.Name)
	}

	http.Redirect(w, r, fmt.Sprintf("/servers/%s", id), http.StatusFound) // #nosec G710 - id is a single path segment; target is a same-host relative path
}

func (h *Handlers) handleServerStart(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	srv, _ := h.servers.Get(id)
	if srv == nil {
		http.NotFound(w, r)
		return
	}
	// Clean up stale backend/container if server is in error state
	if srv.Status == store.StatusError {
		_ = h.proxy.StopServer(r.Context(), id)
	}
	if err := h.proxy.StartServer(r.Context(), srv); err != nil {
		slog.Error("error starting server", "server", srv.Name, "err", err) // #nosec G706 - server name from DB
	} else if h.healthMon != nil {
		h.healthMon.ResetRecoveryState(id)
	}
	redirectBack(w, r, fmt.Sprintf("/servers/%s", id))
}

func (h *Handlers) handleServerStop(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = h.proxy.StopServer(r.Context(), id)
	redirectBack(w, r, fmt.Sprintf("/servers/%s", id))
}

func (h *Handlers) handleServerDelete(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = h.proxy.StopServer(r.Context(), id)
	if err := h.servers.Delete(id); err != nil {
		slog.Error("error deleting server", "server_id", id, "err", err)
		http.Error(w, "Failed to delete server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) handleServerEnumerate(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := h.proxy.EnumerateServer(r.Context(), id)
	if err != nil {
		slog.Error("error enumerating server", "server_id", id, "err", err) // #nosec G706
	}
	http.Redirect(w, r, fmt.Sprintf("/servers/%s", id), http.StatusFound) // #nosec G710 - id is a single path segment; target is a same-host relative path
}

func (h *Handlers) handleServerHealthCheck(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.healthMon != nil {
		health, healthErr := h.healthMon.CheckHealth(r.Context(), id)
		slog.Info("on-demand health check", "server_id", id, "health", health, "health_err", healthErr) // #nosec G706
	}
	http.Redirect(w, r, fmt.Sprintf("/servers/%s", id), http.StatusFound) // #nosec G710 - id is a single path segment; target is a same-host relative path
}

func (h *Handlers) handleServerRebuild(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	srv, _ := h.servers.Get(id)
	if srv == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.proxy.RebuildImage(r.Context(), srv); err != nil {
		slog.Error("error rebuilding image", "server", srv.Name, "err", err) // #nosec G706
	}
	redirectBack(w, r, fmt.Sprintf("/servers/%s", id))
}

func (h *Handlers) handleServerRebuildRestart(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	srv, _ := h.servers.Get(id)
	if srv == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.proxy.RebuildAndRestart(r.Context(), srv); err != nil {
		slog.Error("error rebuild+restart", "server", srv.Name, "err", err) // #nosec G706
	} else if h.healthMon != nil {
		h.healthMon.ResetRecoveryState(id)
	}
	redirectBack(w, r, fmt.Sprintf("/servers/%s", id))
}

func (h *Handlers) handleServerRecreate(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	srv, _ := h.servers.Get(id)
	if srv == nil {
		http.NotFound(w, r)
		return
	}
	pull := r.FormValue("pull") == "1"
	var err error
	if pull {
		err = h.proxy.PullAndRecreateContainer(r.Context(), srv)
	} else {
		err = h.proxy.RecreateContainer(r.Context(), srv)
	}
	if err != nil {
		slog.Error("error recreating container", "server", srv.Name, "err", err) // #nosec G706
	} else if h.healthMon != nil {
		h.healthMon.ResetRecoveryState(id)
	}
	redirectBack(w, r, fmt.Sprintf("/servers/%s", id))
}

func (h *Handlers) handleRecreateStream(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	srv, _ := h.servers.Get(id)
	if srv == nil {
		http.NotFound(w, r)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(msg string) {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
		flusher.Flush()
	}

	pull := r.FormValue("pull") == "1"
	err := h.proxy.RecreateWithProgress(r.Context(), srv, pull, send)
	if err != nil {
		slog.Error("error recreating container", "server", srv.Name, "err", err)
		// Sanitize error for SSE output to satisfy gosec G705 (XSS taint).
		// SSE data is consumed by JS, not rendered as HTML, but we sanitize anyway.
		safeErr := strings.ReplaceAll(err.Error(), "<", "&lt;")
		safeErr = strings.ReplaceAll(safeErr, ">", "&gt;")
		_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", safeErr) // #nosec G705
		flusher.Flush()
		return
	}

	if h.healthMon != nil {
		h.healthMon.ResetRecoveryState(id)
	}
	_, _ = fmt.Fprintf(w, "event: done\ndata: Container recreated successfully\n\n")
	flusher.Flush()
}

// --- Access Tiers ---

func (h *Handlers) handleAccessTier(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	var body struct {
		EndpointType string `json:"endpoint_type"`
		EndpointName string `json:"endpoint_name"`
		AccessTier   string `json:"access_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if body.AccessTier != "read" && body.AccessTier != "write" && body.AccessTier != "admin" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid access tier"})
		return
	}

	if err := h.accessStore.SetTier(id, body.EndpointType, body.EndpointName, body.AccessTier); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set tier"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Middleware ---

func (h *Handlers) handleServerMiddleware(w http.ResponseWriter, r *http.Request, serverID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	var body struct {
		Middleware string          `json:"middleware"`
		Enabled    *bool           `json:"enabled"`
		Config     json.RawMessage `json:"config"`
		Priority   int             `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if body.Middleware == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "middleware name required"})
		return
	}

	// Validate middleware name against registry
	desc, ok := h.mwRegistry.Descriptor(body.Middleware)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown middleware: " + body.Middleware})
		return
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	priority := body.Priority
	if priority == 0 {
		priority = desc.DefaultPriority
	}
	if priority == 0 {
		priority = 100
	}

	// Toggle-only (no config provided): update enabled without overwriting config
	if body.Config == nil {
		if err := h.middlewareStore.UpsertEnabled(serverID, body.Middleware, enabled, priority); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	mc := &store.MiddlewareConfig{
		ServerID:   &serverID,
		Middleware: body.Middleware,
		Enabled:    enabled,
		Config:     body.Config,
		Priority:   priority,
	}

	if err := h.middlewareStore.Upsert(mc); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMiddlewareAPI routes /api/middleware/{name}/config and /api/middleware/{name}/action/{action}.
func (h *Handlers) handleMiddlewareAPI(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/middleware/{name}/config or /api/middleware/{name}/action/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/middleware/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	mwName := parts[0]
	if !h.mwRegistry.IsRegistered(mwName) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown middleware: " + mwName})
		return
	}
	switch parts[1] {
	case "config":
		h.handleMiddlewareConfig(w, r, mwName)
	case "action":
		action := ""
		if len(parts) == 3 {
			action = parts[2]
		}
		h.handleMiddlewareAction(w, r, mwName, action)
	default:
		http.NotFound(w, r)
	}
}

// handleMiddlewareConfig saves global middleware config (server_id NULL).
// Requires target=global query param. Per-server config uses /servers/{id}/middleware.
func (h *Handlers) handleMiddlewareConfig(w http.ResponseWriter, r *http.Request, mwName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	desc, ok := h.mwRegistry.Descriptor(mwName)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown middleware: " + mwName})
		return
	}
	target := r.URL.Query().Get("target")
	if target != "global" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target=global required; per-server config uses /servers/{id}/middleware"})
		return
	}
	if desc.Scope != "global" && desc.Scope != "both" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": mwName + " does not support global config"})
		return
	}

	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Archive-specific validation
	if mwName == "archive" {
		archiveCfg, err := middleware.ParseArchiveConfig(body.Config)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if _, err := middleware.ValidateArchiveConfig(archiveCfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		normalized, err := json.Marshal(archiveCfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to normalize config"})
			return
		}
		body.Config = normalized

		// Rewrite held rows and reset circuit breaker
		mc := &store.MiddlewareConfig{
			Middleware: mwName,
			Enabled:    false,
			Config:     body.Config,
			Priority:   desc.DefaultPriority,
		}
		if err := h.middlewareStore.UpsertGlobal(mc); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save: " + err.Error()})
			return
		}
		rewritten := int64(0)
		if disp := h.mwRegistry.ArchiveDispatcher(); disp != nil {
			if n, rwErr := disp.RewriteHeldDelivery(archiveCfg); rwErr == nil {
				rewritten = n
			}
			disp.ResetCircuit()
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "rewritten": rewritten})
		return
	}

	// Generic global save
	mc := &store.MiddlewareConfig{
		Middleware: mwName,
		Enabled:    false,
		Config:     body.Config,
		Priority:   desc.DefaultPriority,
	}
	if err := h.middlewareStore.UpsertGlobal(mc); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMiddlewareAction dispatches POST /api/middleware/{name}/action/{action}.
// Actions are validated against the descriptor's whitelist plus the special
// handoff_begin / handoff_complete actions for archive.
func (h *Handlers) handleMiddlewareAction(w http.ResponseWriter, r *http.Request, mwName string, action string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	desc, ok := h.mwRegistry.Descriptor(mwName)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown middleware: " + mwName})
		return
	}

	// Check action whitelist. Handoff actions are always allowed for archive.
	allowed := false
	for _, a := range desc.Actions {
		if a == action {
			allowed = true
			break
		}
	}
	if mwName == "archive" && (action == "handoff_begin" || action == "handoff_complete") {
		allowed = true
	}
	if !allowed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action})
		return
	}

	// Dispatch to middleware-specific handler funcs
	switch mwName {
	case "archive":
		h.dispatchArchiveAction(w, r, action)
	default:
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": mwName + " has no action handlers"})
	}
}

// dispatchArchiveAction handles archive-specific actions.
func (h *Handlers) dispatchArchiveAction(w http.ResponseWriter, r *http.Request, action string) {
	switch action {
	case "test":
		h.archiveActionTest(w, r)
	case "retry":
		h.archiveActionRetry(w, r)
	case "clear":
		h.archiveActionClear(w, r)
	case "status":
		h.archiveActionStatus(w, r)
	case "handoff_begin":
		h.handleArchiveHandoffBegin(w, r)
	case "handoff_complete":
		h.handleArchiveHandoffComplete(w, r)
	}
}

func (h *Handlers) archiveActionTest(w http.ResponseWriter, r *http.Request) {
	disp := h.mwRegistry.ArchiveDispatcher()
	if disp == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "archive dispatcher not available"})
		return
	}
	globalCfg, err := h.middlewareStore.GetGlobal("archive")
	if err != nil || globalCfg == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no archive config found - save config first"})
		return
	}
	var archiveCfg middleware.ArchiveConfig
	if err := json.Unmarshal(globalCfg.Config, &archiveCfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid archive config: " + err.Error()})
		return
	}
	if archiveCfg.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "archive URL not configured"})
		return
	}
	statusCode, testErr := disp.SendTest(archiveCfg)
	if testErr != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":     false,
			"status_code": statusCode,
			"error":       testErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"status_code": statusCode,
	})
}

func (h *Handlers) archiveActionRetry(w http.ResponseWriter, r *http.Request) {
	disp := h.mwRegistry.ArchiveDispatcher()
	if disp == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "archive dispatcher not available"})
		return
	}
	rewritten := int64(0)
	if globalCfg, err := h.middlewareStore.GetGlobal("archive"); err == nil && globalCfg != nil {
		var archiveCfg middleware.ArchiveConfig
		if err := json.Unmarshal(globalCfg.Config, &archiveCfg); err == nil && archiveCfg.URL != "" {
			if n, rwErr := disp.RewriteHeldDelivery(archiveCfg); rwErr == nil {
				rewritten = n
			}
		}
	}
	count, err := disp.RetryHeld()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"retried":   count,
		"rewritten": rewritten,
	})
}

func (h *Handlers) archiveActionClear(w http.ResponseWriter, r *http.Request) {
	disp := h.mwRegistry.ArchiveDispatcher()
	if disp == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "archive dispatcher not available"})
		return
	}
	count, err := disp.ClearHeld()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "cleared": count})
}

func (h *Handlers) archiveActionStatus(w http.ResponseWriter, r *http.Request) {
	disp := h.mwRegistry.ArchiveDispatcher()
	if disp == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, disp.Status())
}

// --- Users ---

func (h *Handlers) handleUsers(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}
	// Consume one-time invite flash nonce from Post-Redirect-Get.
	if nonce := r.URL.Query().Get("invite"); nonce != "" {
		users, _ := h.users.List()
		profiles, _ := h.profileStore.List()
		pendingInvites, _ := h.inviteStore.ListPending()
		data := map[string]any{
			"Nav":            "users",
			"User":           user,
			"Users":          users,
			"Profiles":       profiles,
			"PendingInvites": pendingInvites,
		}
		if cmd, ok := h.flashKeys.LoadAndDelete("invite-cmd-" + nonce); ok {
			data["InviteCmd"] = cmd
		}
		if link, ok := h.flashKeys.LoadAndDelete("invite-link-" + nonce); ok {
			data["InviteLink"] = link
		}
		h.render(w, r, "users.html", data)
		return
	}
	h.renderUsersList(w, r, "")
}

func (h *Handlers) renderUsersList(w http.ResponseWriter, r *http.Request, errMsg string) {
	users, _ := h.users.List()
	profiles, _ := h.profileStore.List()
	pendingInvites, _ := h.inviteStore.ListPending()
	data := map[string]any{
		"Nav":            "users",
		"User":           getUser(r),
		"Users":          users,
		"Profiles":       profiles,
		"PendingInvites": pendingInvites,
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	h.render(w, r, "users.html", data)
}

func (h *Handlers) handleUserRoutes(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/users/")
	parts := strings.SplitN(path, "/", 2)

	if parts[0] == "new" && r.Method == http.MethodPost {
		h.handleUserCreate(w, r)
		return
	}
	if parts[0] == "invite-new" && r.Method == http.MethodPost {
		h.handleCreateAccountInvite(w, r)
		return
	}
	if parts[0] == "invite-revoke" && len(parts) > 1 && r.Method == http.MethodPost {
		_ = h.inviteStore.Delete(parts[1])
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}
	if len(parts) > 1 && r.Method == http.MethodPost {
		userID := parts[0]
		switch parts[1] {
		case "delete":
			_ = h.users.Delete(userID)
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		case "update":
			h.handleUserUpdate(w, r, userID)
			return
		case "reset-password":
			h.handleUserResetPassword(w, r, userID)
			return
		}
	}
	http.NotFound(w, r)
}

// handleCreateAccountInvite creates a new account-template invite (admin action).
func (h *Handlers) handleCreateAccountInvite(w http.ResponseWriter, r *http.Request) {
	admin := getUser(r)
	if admin == nil || admin.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	role := r.FormValue("role")
	if role != "admin" {
		role = "user"
	}
	accessLevel := r.FormValue("access_level")
	if accessLevel != "read" && accessLevel != "write" && accessLevel != "admin" {
		accessLevel = "write"
	}
	var profileID *string
	if pid := strings.TrimSpace(r.FormValue("profile_id")); pid != "" {
		profileID = &pid
	}

	expiresAt := time.Now().Add(48 * time.Hour)
	rawToken, _, err := h.inviteStore.CreateAccountInvite(role, accessLevel, profileID, admin.ID, expiresAt)
	if err != nil {
		h.renderUsersList(w, r, "Failed to create invite: "+err.Error())
		return
	}

	baseURL := h.cfg.PublicBaseURL()
	inviteLink := fmt.Sprintf("%s/invite/%s", baseURL, rawToken)
	installCmd := fmt.Sprintf("curl -fsSL %s/install.sh | bash -s -- --token %s", baseURL, rawToken)

	// Store invite details in flash and redirect (Post-Redirect-Get) to
	// prevent duplicate invite creation on browser refresh.
	nonce, err := generateID()
	if err != nil {
		slog.Error("error generating flash nonce", "err", err)
		http.Redirect(w, r, "/users", http.StatusFound)
		return
	}
	h.flashKeys.Store("invite-cmd-"+nonce, installCmd)
	h.flashKeys.Store("invite-link-"+nonce, inviteLink)
	go func() {
		time.Sleep(60 * time.Second)
		h.flashKeys.Delete("invite-cmd-" + nonce)
		h.flashKeys.Delete("invite-link-" + nonce)
	}()
	http.Redirect(w, r, "/users?invite="+nonce, http.StatusFound)
}

// handleInviteExchange handles POST /api/auth/invite - creates account and returns API key.
func (h *Handlers) handleInviteExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		http.Error(w, `{"error":"token is required"}`, http.StatusBadRequest)
		return
	}
	if body.Username == "" || body.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "username and password are required"})
		return
	}
	if len(body.Password) < 8 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "password must be at least 8 characters"})
		return
	}

	// Transactional: consume token + create user + create API key atomically
	tx, err := h.inviteStore.DB().Begin()
	if err != nil {
		slog.Error("invite exchange: failed to begin transaction", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback() }()

	invite, err := h.inviteStore.ValidateAndConsumeTx(tx, body.Token)
	if err != nil {
		slog.Error("invite exchange error", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if invite == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid, expired, or already used token"})
		return
	}

	user, err := h.users.CreateWithAccessLevelTx(tx, body.Username, body.Password, invite.Role, invite.AccessLevel, invite.ProfileID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "username already taken"})
			return
		}
		slog.Error("invite exchange: failed to create user", "err", err)
		http.Error(w, `{"error":"failed to create account"}`, http.StatusInternalServerError)
		return
	}

	rawKey, _, err := h.users.CreateAPIKeyTx(tx, user.ID, "arc-sync invite", invite.ProfileID)
	if err != nil {
		slog.Error("invite exchange: failed to create API key", "err", err)
		http.Error(w, `{"error":"failed to create API key"}`, http.StatusInternalServerError)
		return
	}

	if err := h.inviteStore.SetRedeemedUserTx(tx, invite.ID, user.ID); err != nil {
		slog.Error("invite exchange: failed to record redeemed user", "err", err)
	}

	if err := tx.Commit(); err != nil {
		slog.Error("invite exchange: failed to commit transaction", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	slog.Info("invite exchange: created user and API key", "username", user.Username, "invite_id", invite.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"api_key": rawKey})
}

// handleInviteRedeem handles GET/POST /invite/{token} - browser account setup.
func (h *Handlers) handleInviteRedeem(w http.ResponseWriter, r *http.Request) {
	rawToken := strings.TrimPrefix(r.URL.Path, "/invite/")
	if rawToken == "" {
		http.Error(w, "Missing invite token", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		invite, err := h.inviteStore.Peek(rawToken)
		if err != nil {
			slog.Error("invite redeem peek error", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		data := map[string]any{"Token": rawToken}
		if invite == nil {
			data["Expired"] = true
		} else {
			data["Role"] = invite.Role
		}
		h.renderInviteRedeem(w, data)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	renderErr := func(msg string) {
		// Peek again to check if token is still valid
		invite, _ := h.inviteStore.Peek(rawToken)
		data := map[string]any{"Token": rawToken, "Error": msg, "Username": username}
		if invite == nil {
			data["Expired"] = true
		} else {
			data["Role"] = invite.Role
		}
		h.renderInviteRedeem(w, data)
	}

	if username == "" || password == "" {
		renderErr("Username and password are required")
		return
	}
	if len(password) < 8 {
		renderErr("Password must be at least 8 characters")
		return
	}
	if password != confirmPassword {
		renderErr("Passwords do not match")
		return
	}

	// Transactional: consume token + create user atomically
	tx, err := h.inviteStore.DB().Begin()
	if err != nil {
		slog.Error("invite redeem: failed to begin transaction", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback() }()

	invite, err := h.inviteStore.ValidateAndConsumeTx(tx, rawToken)
	if err != nil {
		slog.Error("invite redeem error", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if invite == nil {
		h.renderInviteRedeem(w, map[string]any{"Token": rawToken, "Expired": true})
		return
	}

	user, err := h.users.CreateWithAccessLevelTx(tx, username, password, invite.Role, invite.AccessLevel, invite.ProfileID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			renderErr("Username already taken")
			return
		}
		slog.Error("invite redeem: failed to create user", "err", err)
		renderErr("Failed to create account")
		return
	}

	if err := h.inviteStore.SetRedeemedUserTx(tx, invite.ID, user.ID); err != nil {
		slog.Error("invite redeem: failed to record redeemed user", "err", err)
	}

	if err := tx.Commit(); err != nil {
		slog.Error("invite redeem: failed to commit", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a session and log the user in
	sessionID, err := generateID()
	if err != nil {
		slog.Error("invite redeem: failed to generate session ID", "err", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := h.sessionStore.Create(sessionID, user.ID, expiresAt); err != nil {
		slog.Error("invite redeem: failed to create session", "err", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 - Secure is conditional for local dev
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.cfg.PublicBaseURL(), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	slog.Info("invite redeem: created user via browser", "username", user.Username, "invite_id", invite.ID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// renderInviteRedeem renders the standalone invite_redeem template.
func (h *Handlers) renderInviteRedeem(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := h.tmpls["invite_redeem.html"]
	if err := t.ExecuteTemplate(w, "content", data); err != nil {
		slog.Error("template error", "err", err)
	}
}

// handleChangePassword handles GET/POST /account/password - self-service password change.
func (h *Handlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)

	if r.Method == http.MethodGet {
		h.render(w, r, "change_password.html", map[string]any{
			"Nav":        "",
			"User":       user,
			"MustChange": user.MustChangePassword,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	renderErr := func(msg string) {
		h.render(w, r, "change_password.html", map[string]any{
			"Nav":        "",
			"User":       user,
			"MustChange": user.MustChangePassword,
			"Error":      msg,
		})
	}

	// If not a forced change, verify current password
	if !user.MustChangePassword {
		authed, err := h.users.Authenticate(user.Username, currentPassword)
		if err != nil || authed == nil {
			renderErr("Current password is incorrect")
			return
		}
	}

	if len(newPassword) < 8 {
		renderErr("New password must be at least 8 characters")
		return
	}
	if newPassword != confirmPassword {
		renderErr("Passwords do not match")
		return
	}

	if err := h.users.SetPassword(user.ID, newPassword); err != nil {
		renderErr("Failed to update password: " + err.Error())
		return
	}

	// Invalidate all sessions, then create a fresh one for this browser
	h.sessionStore.DeleteByUser(user.ID)

	newSessionID, err := generateID()
	if err != nil {
		slog.Error("failed to generate session ID after password change", "err", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := h.sessionStore.Create(newSessionID, user.ID, expiresAt); err != nil {
		slog.Error("failed to create session after password change", "err", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 - Secure is conditional for local dev
		Name:     "session",
		Value:    newSessionID,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.cfg.PublicBaseURL(), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect rather than render - the old session in the request context is gone,
	// so the CSRF token would be stale. A fresh GET will use the new session cookie.
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handlers) handleUserUpdate(w http.ResponseWriter, r *http.Request, userID string) {
	role := r.FormValue("role")
	if role == "admin" || role == "user" {
		_ = h.users.UpdateRole(userID, role)
	}

	var profileID *string
	if pid := strings.TrimSpace(r.FormValue("default_profile_id")); pid != "" {
		profileID = &pid
	}
	_ = h.users.UpdateProfile(userID, profileID)

	http.Redirect(w, r, "/users", http.StatusFound)
}

func (h *Handlers) handleUserResetPassword(w http.ResponseWriter, r *http.Request, userID string) {
	newPassword := r.FormValue("new_password")
	if newPassword == "" {
		h.renderUsersList(w, r, "New password is required")
		return
	}
	if len(newPassword) < 8 {
		h.renderUsersList(w, r, "Password must be at least 8 characters")
		return
	}

	targetUser, err := h.users.Get(userID)
	if err != nil || targetUser == nil {
		h.renderUsersList(w, r, "User not found")
		return
	}

	if err := h.users.SetPassword(userID, newPassword); err != nil {
		h.renderUsersList(w, r, "Failed to reset password: "+err.Error())
		return
	}

	// Force the user to change their password on next login
	_ = h.users.SetMustChangePassword(userID, true)

	// Invalidate all sessions for the target user
	h.sessionStore.DeleteByUser(userID)

	slog.Debug("admin reset password for user", "admin", getUser(r).Username, "target_user", targetUser.Username)

	users, _ := h.users.List()
	profiles, _ := h.profileStore.List()
	pendingInvites, _ := h.inviteStore.ListPending()
	h.render(w, r, "users.html", map[string]any{
		"Nav":            "users",
		"User":           getUser(r),
		"Users":          users,
		"Profiles":       profiles,
		"PendingInvites": pendingInvites,
		"Flash":          &Flash{Type: "success", Message: fmt.Sprintf("Password reset for %s. They will be required to change it on next login.", targetUser.Username)},
	})
}

func (h *Handlers) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role != "admin" {
		role = "user"
	}
	accessLevel := r.FormValue("access_level")
	if accessLevel != "read" && accessLevel != "write" && accessLevel != "admin" {
		accessLevel = "write"
	}
	var defaultProfileID *string
	if pid := strings.TrimSpace(r.FormValue("default_profile_id")); pid != "" {
		defaultProfileID = &pid
	}

	if username == "" || password == "" {
		h.renderUsersList(w, r, "Username and password are required")
		return
	}

	if _, err := h.users.CreateWithAccessLevel(username, password, role, accessLevel, defaultProfileID); err != nil {
		h.renderUsersList(w, r, fmt.Sprintf("Failed to create user: %s", err))
		return
	}
	http.Redirect(w, r, "/users", http.StatusFound)
}

// --- API Keys ---

func (h *Handlers) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	keys, _ := h.users.ListAPIKeys(user.ID)

	// Admins can see all profiles; non-admins see only their own (if assigned)
	var profiles []*store.AgentProfile
	if user.Role == "admin" {
		profiles, _ = h.profileStore.List()
	} else if user.DefaultProfileID != nil {
		if p, err := h.profileStore.Get(*user.DefaultProfileID); err == nil {
			profiles = []*store.AgentProfile{p}
		}
	}

	data := map[string]any{
		"Nav": "apikeys", "User": user, "Keys": keys, "Profiles": profiles,
	}
	// Consume one-time flash nonce to display newly created key.
	// LoadAndDelete ensures the key is shown only once; refreshing
	// the redirected URL won't re-display it.
	if nonce := r.URL.Query().Get("new"); nonce != "" {
		if rawKey, ok := h.flashKeys.LoadAndDelete(nonce); ok {
			data["NewKey"] = rawKey
		} else {
			data["Flash"] = "Your API key was created, but its secret value can no longer be displayed. Please revoke it and create a new one if needed."
		}
	}
	h.render(w, r, "api_keys.html", data)
}

func (h *Handlers) handleAPIKeyRoutes(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	path := strings.TrimPrefix(r.URL.Path, "/api-keys/")
	parts := strings.SplitN(path, "/", 2)

	if parts[0] == "new" && r.Method == http.MethodPost {
		name := strings.TrimSpace(r.FormValue("key_name"))
		if name == "" {
			name = "unnamed"
		}
		var profileID *string
		if pid := strings.TrimSpace(r.FormValue("profile_id")); pid != "" {
			// Non-admins can only use their own profile
			if user.Role != "admin" && (user.DefaultProfileID == nil || *user.DefaultProfileID != pid) {
				http.Error(w, "You can only create keys with your assigned profile", http.StatusForbidden)
				return
			}
			profileID = &pid
		} else {
			// Default to user's profile if no explicit selection
			fullUser, _ := h.users.Get(user.ID)
			if fullUser != nil && fullUser.DefaultProfileID != nil {
				profileID = fullUser.DefaultProfileID
			}
		}
		rawKey, _, err := h.users.CreateAPIKey(user.ID, name, profileID)
		if err != nil {
			slog.Error("error creating API key", "err", err)
			http.Redirect(w, r, "/api-keys", http.StatusFound)
			return
		}
		// Store key in flash and redirect (Post-Redirect-Get) to prevent
		// duplicate key creation on browser refresh.
		nonce, err := generateID()
		if err != nil {
			slog.Error("error generating flash nonce", "err", err)
			http.Redirect(w, r, "/api-keys", http.StatusFound)
			return
		}
		h.flashKeys.Store(nonce, rawKey)
		go func() {
			time.Sleep(60 * time.Second)
			h.flashKeys.Delete(nonce)
		}()
		http.Redirect(w, r, "/api-keys?new="+nonce, http.StatusFound)
		return
	}

	if len(parts) > 1 && parts[1] == "revoke" && r.Method == http.MethodPost {
		// Verify the key belongs to the current user (or user is admin)
		keyID := parts[0]
		ownerKeys, _ := h.users.ListAPIKeys(user.ID)
		ownsKey := false
		for _, k := range ownerKeys {
			if k.ID == keyID {
				ownsKey = true
				break
			}
		}
		if !ownsKey && user.Role != "admin" {
			http.Error(w, "You can only revoke your own API keys", http.StatusForbidden)
			return
		}
		_ = h.users.RevokeAPIKey(keyID)
		http.Redirect(w, r, "/api-keys", http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

// --- Profiles ---

func (h *Handlers) handleProfiles(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost {
		// Create new profile
		name := strings.TrimSpace(r.FormValue("name"))
		desc := strings.TrimSpace(r.FormValue("description"))
		if name == "" {
			h.renderProfilesList(w, r, &Flash{Type: "danger", Message: "Profile name is required"})
			return
		}
		profile, err := h.profileStore.Create(name, desc)
		if err != nil {
			h.renderProfilesList(w, r, &Flash{Type: "danger", Message: "Failed to create profile: " + err.Error()})
			return
		}
		http.Redirect(w, r, "/profiles/"+profile.ID, http.StatusFound)
		return
	}

	h.renderProfilesList(w, r, nil)
}

func (h *Handlers) renderProfilesList(w http.ResponseWriter, r *http.Request, flash *Flash) {
	user := getUser(r)
	profiles, _ := h.profileStore.List()

	type profileRow struct {
		*store.AgentProfile
		PermCount int
		KeyCount  int
	}
	var rows []profileRow
	for _, p := range profiles {
		pc, _ := h.profileStore.PermissionCount(p.ID)
		kc, _ := h.profileStore.APIKeyCount(p.ID)
		rows = append(rows, profileRow{AgentProfile: p, PermCount: pc, KeyCount: kc})
	}

	data := map[string]any{
		"Nav": "profiles", "User": user, "Profiles": rows,
	}
	if flash != nil {
		data["Flash"] = flash
	}
	h.render(w, r, "profiles.html", data)
}

func (h *Handlers) handleProfileRoutes(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/profiles/")
	parts := strings.SplitN(path, "/", 2)
	profileID := parts[0]
	if profileID == "" {
		http.NotFound(w, r)
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "update":
		h.handleProfileUpdate(w, r, profileID)
	case "delete":
		h.handleProfileDelete(w, r, profileID)
	case "permission":
		h.handleProfilePermission(w, r, profileID)
	case "seed":
		h.handleProfileSeed(w, r, profileID)
	default:
		h.handleProfileDetail(w, r, profileID)
	}
}

func (h *Handlers) handleProfileDetail(w http.ResponseWriter, r *http.Request, profileID string) {
	profile, err := h.profileStore.Get(profileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get all servers with their endpoints and current permissions
	allServers, _ := h.servers.List()
	perms, _ := h.profileStore.GetPermissions(profileID)

	// Build a set of granted permissions for quick lookup
	permSet := make(map[string]bool) // "serverID:type:name" -> true
	for _, p := range perms {
		permSet[p.ServerID+":"+p.EndpointType+":"+p.EndpointName] = true
	}

	type endpointRow struct {
		Type    string
		Name    string
		Tier    string
		Allowed bool
	}
	type serverSection struct {
		ID        string
		Name      string
		Endpoints []endpointRow
	}
	var sections []serverSection
	for _, srv := range allServers {
		tiers, err := h.accessStore.GetAllTiers(srv.ID)
		if err != nil || len(tiers) == 0 {
			continue
		}
		sec := serverSection{ID: srv.ID, Name: srv.DisplayName}
		for _, t := range tiers {
			key := srv.ID + ":" + t.EndpointType + ":" + t.EndpointName
			sec.Endpoints = append(sec.Endpoints, endpointRow{
				Type:    t.EndpointType,
				Name:    t.EndpointName,
				Tier:    t.AccessTier,
				Allowed: permSet[key],
			})
		}
		sections = append(sections, sec)
	}

	h.render(w, r, "profile_detail.html", map[string]any{
		"Nav":      "profiles",
		"User":     getUser(r),
		"Profile":  profile,
		"Sections": sections,
	})
}

func (h *Handlers) handleProfileUpdate(w http.ResponseWriter, r *http.Request, profileID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/profiles/"+profileID, http.StatusFound) // #nosec G710 - profileID is a single path segment; target is a same-host relative path
		return
	}
	_ = h.profileStore.Update(profileID, name, desc)
	http.Redirect(w, r, "/profiles/"+profileID, http.StatusFound) // #nosec G710 - profileID is a single path segment; target is a same-host relative path
}

func (h *Handlers) handleProfileDelete(w http.ResponseWriter, r *http.Request, profileID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = h.profileStore.Delete(profileID)
	http.Redirect(w, r, "/profiles", http.StatusFound)
}

func (h *Handlers) handleProfilePermission(w http.ResponseWriter, r *http.Request, profileID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := r.FormValue("server_id")
	endpointType := r.FormValue("endpoint_type")
	endpointName := r.FormValue("endpoint_name")
	action := r.FormValue("action") // "grant" or "revoke"

	if serverID == "" || endpointType == "" || endpointName == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	if action == "grant" {
		_ = h.profileStore.SetPermission(profileID, serverID, endpointType, endpointName)
	} else {
		_ = h.profileStore.RemovePermission(profileID, serverID, endpointType, endpointName)
	}

	// Return 200 for JS fetch calls
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *Handlers) handleProfileSeed(w http.ResponseWriter, r *http.Request, profileID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := r.FormValue("server_id")
	tier := r.FormValue("tier") // "read", "write", or "admin"

	if serverID == "" || tier == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	if err := h.profileStore.SeedFromTier(profileID, serverID, tier); err != nil {
		slog.Error("error seeding profile", "profile_id", profileID, "err", err) // #nosec G706
		if r.Header.Get("Accept") == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			errJSON, _ := json.Marshal(err.Error())
			_, _ = w.Write([]byte(`{"error":` + string(errJSON) + `}`))
			return
		}
	}

	// AJAX callers get JSON; form submissions get a redirect
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	http.Redirect(w, r, "/profiles/"+profileID, http.StatusFound) // #nosec G710 - profileID is a single path segment; target is a same-host relative path
}

// --- OAuth ---

func (h *Handlers) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	serverID := strings.TrimPrefix(r.URL.Path, "/oauth/start/")
	if serverID == "" {
		http.NotFound(w, r)
		return
	}

	srv, err := h.servers.Get(serverID)
	if err != nil || srv == nil {
		http.NotFound(w, r)
		return
	}

	if srv.ServerType != store.ServerTypeRemote {
		http.Error(w, "OAuth is only supported for remote servers", http.StatusBadRequest)
		return
	}

	var cfg store.RemoteConfig
	if err := json.Unmarshal(srv.Config, &cfg); err != nil {
		http.Error(w, "Invalid server config", http.StatusInternalServerError)
		return
	}

	if cfg.Auth.Type != "oauth" {
		http.Error(w, "Server is not configured for OAuth", http.StatusBadRequest)
		return
	}

	// Auto-re-register if redirect URI has changed (e.g. base URL update),
	// or force re-register if requested (e.g. provider state out of sync after DB recovery).
	// Force re-registration is admin-only since it rotates shared client credentials.
	force := r.URL.Query().Get("force") == "1"
	if force {
		user := getUser(r)
		if user == nil || user.Role != "admin" {
			http.Error(w, "Admin access required for force re-registration", http.StatusForbidden)
			return
		}
	}
	if reregistered, err := h.oauth.ReRegisterIfNeeded(r.Context(), serverID, srv, &cfg, force); err != nil {
		slog.Error("OAuth re-registration failed", "server", srv.Name, "err", err) // #nosec G706
		http.Error(w, fmt.Sprintf("OAuth re-registration failed: %s", err), http.StatusInternalServerError)
		return
	} else if reregistered {
		slog.Info("OAuth re-registered with updated redirect URI", "server", srv.Name) // #nosec G706
	}

	authURL, err := h.oauth.StartAuthFlow(serverID, cfg.Auth)
	if err != nil {
		slog.Error("error starting OAuth flow", "server", srv.Name, "err", err) // #nosec G706
		http.Error(w, "Failed to start OAuth flow", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 - authURL is the configured OAuth provider's authorization endpoint (validated absolute https URL in StartAuthFlow); intended external redirect
}

func (h *Handlers) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		errMsg := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		if errMsg != "" {
			http.Error(w, fmt.Sprintf("OAuth error: %s — %s", errMsg, errDesc), http.StatusBadRequest)
			return
		}
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	serverID, err := h.oauth.HandleCallback(r.Context(), state, code)
	if err != nil {
		// On duplicate callbacks (browser double-request), the state is already
		// consumed but tokens were acquired. Redirect to dashboard gracefully.
		if strings.Contains(err.Error(), "unknown or expired OAuth state") {
			slog.Warn("OAuth callback: duplicate or expired state, redirecting to dashboard")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		slog.Error("OAuth callback error", "err", err)
		http.Error(w, fmt.Sprintf("OAuth callback failed: %s", err), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/servers/%s", serverID), http.StatusFound) // #nosec G710 - serverID is a server-generated id from the validated OAuth state; target is a same-host relative path
}

// --- Catalog API ---

func (h *Handlers) handleCatalogSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, []catalog.ResolvedServer{})
		return
	}

	results, err := h.catalogClient.Search(r.Context(), q, 20)
	if err != nil {
		slog.Warn("catalog search error", "err", err)
		writeJSON(w, http.StatusOK, []catalog.ResolvedServer{}) // graceful degradation
		return
	}
	if results == nil {
		results = []catalog.ResolvedServer{}
	}

	writeJSON(w, http.StatusOK, results)
}

func (h *Handlers) handleCatalogDiscoverOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAdmin(w, r) {
		return
	}

	var body struct {
		RemoteURL string `json:"remote_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RemoteURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	// Validate URL scheme and block private/loopback hosts to prevent SSRF
	if err := validateExternalURL(body.RemoteURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	discovery, err := oauth.DiscoverOAuth(r.Context(), body.RemoteURL)
	if err != nil || discovery == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	// If a registration endpoint is available, try dynamic client registration.
	// Validate the endpoint URL to prevent SSRF via adversarial discovery responses.
	if discovery.RegistrationEndpoint != "" {
		if err := validateExternalURL(discovery.RegistrationEndpoint); err != nil {
			slog.Debug("registration endpoint blocked by SSRF check", "endpoint", discovery.RegistrationEndpoint)
		} else {
			reg, err := oauth.RegisterClient(r.Context(), discovery.RegistrationEndpoint, h.oauth.CallbackURL())
			if err != nil {
				slog.Debug("dynamic client registration failed", "err", err)
			} else if reg != nil {
				discovery.ClientID = reg.ClientID
				discovery.ClientSecret = reg.ClientSecret
				discovery.RegisteredRedirectURI = h.oauth.CallbackURL()
			}
		}
	}

	writeJSON(w, http.StatusOK, discovery)
}

// handleConnectDesktop shows the Desktop onboarding page with accessible servers.
func (h *Handlers) handleConnectDesktop(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	allServers, _ := h.servers.List()

	// Filter to running servers the user has access to
	permitted := h.accessibleServers(user, allServers)
	var running []*store.Server
	for _, s := range permitted {
		if s.Status == "running" {
			running = append(running, s)
		}
	}

	isAdmin := user != nil && user.Role == "admin"
	h.render(w, r, "connect_desktop.html", map[string]any{
		"Nav":     "connect",
		"User":    user,
		"IsAdmin": isAdmin,
		"Servers": running,
		"BaseURL": h.cfg.PublicBaseURL(),
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// --- Helpers ---

func (h *Handlers) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	t, ok := h.tmpls[name]
	if !ok {
		slog.Error("template not found", "template", name)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Auto-inject CSRF token from session context
	if sessionID := getSessionID(r.Context()); sessionID != "" {
		data["CSRFToken"] = h.csrfToken(sessionID)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Login page has no layout wrapper
	if name == "login.html" {
		if err := t.ExecuteTemplate(w, "content", data); err != nil {
			slog.Error("template error", "err", err)
		}
		return
	}

	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("template error", "template", name, "err", err)
	}
}

func (h *Handlers) renderLogin(w http.ResponseWriter, errMsg, next string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Login - Arc Relay</title>
<style>body{font-family:system-ui,sans-serif;background:#f8f9fa;color:#212529;}
.card{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:1.25rem;max-width:400px;margin:4rem auto;}
.card h2{font-size:1.1rem;margin-bottom:1rem;}
.form-group{margin-bottom:1rem;}
.form-group label{display:block;font-weight:500;margin-bottom:.3rem;font-size:.9rem;}
.form-group input{width:100%%;padding:.45rem .7rem;border:1px solid #dee2e6;border-radius:6px;font-size:.9rem;box-sizing:border-box;}
.btn{display:block;width:100%%;padding:.5rem;background:#0d6efd;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:.9rem;}
.btn:hover{background:#0b5ed7;}
.alert{background:#f8d7da;color:#842029;padding:.75rem;border-radius:6px;margin-bottom:1rem;font-size:.9rem;}
</style></head><body>
<div class="card"><h2>Log in to Arc Relay</h2>`)
	if errMsg != "" {
		_, _ = fmt.Fprintf(w, `<div class="alert">%s</div>`, template.HTMLEscapeString(errMsg))
	}
	_, _ = fmt.Fprint(w, `<form method="POST" action="/login">`)
	if next != "" && strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		_, _ = fmt.Fprintf(w, `<input type="hidden" name="next" value="%s">`, template.HTMLEscapeString(next))
	}
	_, _ = fmt.Fprint(w, `<div class="form-group"><label for="username">Username</label><input type="text" id="username" name="username" required autofocus></div>
<div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
<button type="submit" class="btn">Log In</button>
</form></div></body></html>`)
}

func (h *Handlers) serverFormData(r *http.Request, srv *store.Server, errMsg string) map[string]any {
	if srv == nil {
		srv = &store.Server{Name: r.FormValue("name"), DisplayName: r.FormValue("display_name")}
	}
	return map[string]any{
		"Nav":               "servers",
		"User":              getUser(r),
		"IsEdit":            false,
		"Server":            srv,
		"ServerType":        r.FormValue("server_type"),
		"RemoteAuthType":    r.FormValue("remote_auth_type"),
		"StdioImage":        r.FormValue("stdio_image"),
		"StdioEntrypoint":   r.FormValue("stdio_entrypoint"),
		"StdioCommand":      r.FormValue("stdio_command"),
		"StdioEnv":          r.FormValue("stdio_env"),
		"StdioMode":         r.FormValue("stdio_mode"),
		"BuildRuntime":      r.FormValue("build_runtime"),
		"BuildPackage":      r.FormValue("build_package"),
		"BuildVersion":      r.FormValue("build_version"),
		"BuildGitURL":       r.FormValue("build_git_url"),
		"BuildDockerfile":   r.FormValue("build_dockerfile"),
		"HTTPImage":         r.FormValue("http_image"),
		"HTTPPort":          r.FormValue("http_port"),
		"HTTPURL":           r.FormValue("http_url"),
		"HTTPHealth":        r.FormValue("http_health"),
		"HTTPEnv":           r.FormValue("http_env"),
		"RemoteURL":         r.FormValue("remote_url"),
		"RemoteToken":       r.FormValue("remote_token"),
		"RemoteHeaderName":  r.FormValue("remote_header_name"),
		"OAuthClientID":     r.FormValue("oauth_client_id"),
		"OAuthClientSecret": r.FormValue("oauth_client_secret"),
		"OAuthAuthURL":      r.FormValue("oauth_auth_url"),
		"OAuthTokenURL":     r.FormValue("oauth_token_url"),
		"OAuthScopes":       r.FormValue("oauth_scopes"),
		"Error":             errMsg,
	}
}

func (h *Handlers) parseServerForm(r *http.Request) (*store.Server, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	serverType := r.FormValue("server_type")

	if name == "" || displayName == "" {
		return nil, fmt.Errorf("name and display name are required")
	}

	var configJSON []byte
	var err error

	switch store.ServerType(serverType) {
	case store.ServerTypeStdio:
		img := strings.TrimSpace(r.FormValue("stdio_image"))
		stdioMode := r.FormValue("stdio_mode") // "image" or "build"
		cfg := store.StdioConfig{
			Image:      img,
			Entrypoint: parseCommand(r.FormValue("stdio_entrypoint")),
			Command:    parseCommand(r.FormValue("stdio_command")),
			Env:        parseEnvVars(r.FormValue("stdio_env")),
		}

		if stdioMode == "build" {
			runtime := r.FormValue("build_runtime")
			pkg := strings.TrimSpace(r.FormValue("build_package"))
			version := strings.TrimSpace(r.FormValue("build_version"))
			gitURL := strings.TrimSpace(r.FormValue("build_git_url"))
			gitRef := strings.TrimSpace(r.FormValue("build_git_ref"))
			customDockerfile := strings.TrimSpace(r.FormValue("build_dockerfile"))

			if pkg == "" && gitURL == "" && customDockerfile == "" {
				return nil, fmt.Errorf("package name, git URL, or custom Dockerfile is required for build mode")
			}
			if runtime != "python" && runtime != "node" {
				return nil, fmt.Errorf("runtime must be python or node")
			}

			cfg.Build = &store.StdioBuildConfig{
				Runtime:    runtime,
				Package:    pkg,
				Version:    version,
				GitURL:     gitURL,
				GitRef:     gitRef,
				Dockerfile: customDockerfile,
			}
			cfg.Image = "" // will be set after build
		} else if img == "" {
			return nil, fmt.Errorf("docker image is required for stdio servers")
		}
		configJSON, err = json.Marshal(cfg)

	case store.ServerTypeHTTP:
		img := strings.TrimSpace(r.FormValue("http_image"))
		url := strings.TrimSpace(r.FormValue("http_url"))
		if img == "" && url == "" {
			return nil, fmt.Errorf("docker image or external URL is required for HTTP servers")
		}
		if url != "" {
			if err := validateServerURL(url); err != nil {
				return nil, err
			}
		}
		cfg := store.HTTPConfig{
			Image:       img,
			Port:        parseInt(r.FormValue("http_port")),
			URL:         url,
			HealthCheck: strings.TrimSpace(r.FormValue("http_health")),
			Env:         parseEnvVars(r.FormValue("http_env")),
		}
		configJSON, err = json.Marshal(cfg)

	case store.ServerTypeRemote:
		url := strings.TrimSpace(r.FormValue("remote_url"))
		if url == "" {
			return nil, fmt.Errorf("url is required for remote servers")
		}
		if err := validateServerURL(url); err != nil {
			return nil, err
		}
		auth := store.RemoteAuth{
			Type:       r.FormValue("remote_auth_type"),
			Token:      r.FormValue("remote_token"),
			HeaderName: r.FormValue("remote_header_name"),
		}
		if auth.Type == "oauth" {
			auth.ClientID = strings.TrimSpace(r.FormValue("oauth_client_id"))
			auth.ClientSecret = strings.TrimSpace(r.FormValue("oauth_client_secret"))
			auth.AuthURL = strings.TrimSpace(r.FormValue("oauth_auth_url"))
			auth.TokenURL = strings.TrimSpace(r.FormValue("oauth_token_url"))
			auth.Scopes = strings.TrimSpace(r.FormValue("oauth_scopes"))

			// Auto-discover OAuth endpoints + dynamic client registration when fields are missing
			if auth.ClientID == "" || auth.AuthURL == "" || auth.TokenURL == "" {
				disc, _ := oauth.DiscoverOAuth(r.Context(), url)
				if disc != nil {
					if auth.AuthURL == "" {
						auth.AuthURL = disc.AuthURL
					}
					if auth.TokenURL == "" {
						auth.TokenURL = disc.TokenURL
					}
					if auth.Scopes == "" && len(disc.ScopesSupported) > 0 {
						auth.Scopes = strings.Join(disc.ScopesSupported, " ")
					}
					if disc.RegistrationEndpoint != "" {
						// Validate registration endpoint to prevent SSRF via adversarial discovery responses
						if err := validateExternalURL(disc.RegistrationEndpoint); err != nil {
							slog.Debug("registration endpoint blocked by SSRF check in server form", "endpoint", disc.RegistrationEndpoint)
						} else {
							auth.RegistrationEndpoint = disc.RegistrationEndpoint
						}
					}
					if auth.ClientID == "" && auth.RegistrationEndpoint != "" {
						reg, _ := oauth.RegisterClient(r.Context(), auth.RegistrationEndpoint, h.oauth.CallbackURL())
						if reg != nil {
							auth.ClientID = reg.ClientID
							auth.ClientSecret = reg.ClientSecret
							auth.RegisteredRedirectURI = h.oauth.CallbackURL()
						}
					}
				}
			}

			if auth.ClientID == "" || auth.AuthURL == "" || auth.TokenURL == "" {
				return nil, fmt.Errorf("OAuth auto-discovery failed for this server — provide client ID, authorization URL, and token URL manually")
			}
		}
		cfg := store.RemoteConfig{
			URL:  url,
			Auth: auth,
		}
		configJSON, err = json.Marshal(cfg)

	default:
		return nil, fmt.Errorf("invalid server type: %s", serverType)
	}

	if err != nil {
		return nil, fmt.Errorf("encoding config: %w", err)
	}

	return &store.Server{
		Name:        name,
		DisplayName: displayName,
		ServerType:  store.ServerType(serverType),
		Config:      configJSON,
	}, nil
}

func buildConfigDisplay(srv *store.Server) *ConfigDisplay {
	cd := &ConfigDisplay{}
	switch srv.ServerType {
	case store.ServerTypeStdio:
		var cfg store.StdioConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		cd.Image = cfg.Image
		cd.IsDocker = true
		cd.Command = strings.Join(cfg.Command, " ")
		cd.EnvKeys = envKeys(cfg.Env)
		cd.EnvVars = cfg.Env
		if cfg.Build != nil {
			cd.HasBuild = true
			cd.HasBuildConfig = true
			cd.BuildRuntime = cfg.Build.Runtime
			cd.BuildPackage = cfg.Build.Package
			cd.BuildVersion = cfg.Build.Version
			cd.BuildGitURL = cfg.Build.GitURL
			cd.BuildGitRef = cfg.Build.GitRef
			cd.BuildCustom = cfg.Build.Dockerfile != ""
		}
	case store.ServerTypeHTTP:
		var cfg store.HTTPConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		cd.Image = cfg.Image
		cd.IsDocker = cfg.Image != "" && cfg.URL == "" // Docker-managed only when no external URL
		cd.Port = cfg.Port
		cd.URL = cfg.URL
		cd.HealthCheck = cfg.HealthCheck
		cd.EnvKeys = envKeys(cfg.Env)
		cd.EnvVars = cfg.Env
	case store.ServerTypeRemote:
		var cfg store.RemoteConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		cd.URL = cfg.URL
		cd.AuthType = cfg.Auth.Type
		if cfg.Auth.Type == "oauth" {
			cd.OAuthAuthorized = cfg.Auth.AccessToken != ""
			cd.OAuthScopes = cfg.Auth.Scopes
			cd.OAuthTokenExpiry = cfg.Auth.TokenExpiry
		}
	}
	return cd
}

func serverToFormData(srv *store.Server) map[string]any {
	data := map[string]any{
		"ServerType":     string(srv.ServerType),
		"RemoteAuthType": "none",
	}
	switch srv.ServerType {
	case store.ServerTypeStdio:
		var cfg store.StdioConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		data["StdioImage"] = cfg.Image
		data["StdioEntrypoint"] = strings.Join(cfg.Entrypoint, " ")
		data["StdioCommand"] = joinQuoted(cfg.Command)
		data["StdioEnv"] = envToText(cfg.Env)
		if cfg.Build != nil {
			data["StdioMode"] = "build"
			data["BuildRuntime"] = cfg.Build.Runtime
			data["BuildPackage"] = cfg.Build.Package
			data["BuildVersion"] = cfg.Build.Version
			data["BuildGitURL"] = cfg.Build.GitURL
			data["BuildGitRef"] = cfg.Build.GitRef
			data["BuildDockerfile"] = cfg.Build.Dockerfile
		} else {
			data["StdioMode"] = "image"
			data["BuildRuntime"] = ""
			data["BuildPackage"] = ""
			data["BuildVersion"] = ""
			data["BuildGitURL"] = ""
			data["BuildGitRef"] = ""
			data["BuildDockerfile"] = ""
		}
	case store.ServerTypeHTTP:
		var cfg store.HTTPConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		data["HTTPImage"] = cfg.Image
		data["HTTPPort"] = cfg.Port
		data["HTTPURL"] = cfg.URL
		data["HTTPHealth"] = cfg.HealthCheck
		data["HTTPEnv"] = envToText(cfg.Env)
	case store.ServerTypeRemote:
		var cfg store.RemoteConfig
		_ = json.Unmarshal(srv.Config, &cfg)
		data["RemoteURL"] = cfg.URL
		data["RemoteAuthType"] = cfg.Auth.Type
		data["RemoteToken"] = cfg.Auth.Token
		data["RemoteHeaderName"] = cfg.Auth.HeaderName
		data["OAuthClientID"] = cfg.Auth.ClientID
		data["OAuthClientSecret"] = cfg.Auth.ClientSecret
		data["OAuthAuthURL"] = cfg.Auth.AuthURL
		data["OAuthTokenURL"] = cfg.Auth.TokenURL
		data["OAuthScopes"] = cfg.Auth.Scopes
	}
	return data
}

// truncateImageID shortens a Docker image ID for display, matching
// Docker's standard short-ID format (12 hex chars, no sha256: prefix).
func truncateImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func humanizeAge(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func parseEnvVars(text string) map[string]string {
	env := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			env[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return env
}

// parseCommand splits a command string into arguments, respecting quoted strings.
// e.g. `-c "from foo import bar; bar.run()"` → ["-c", "from foo import bar; bar.run()"]
func parseCommand(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	var args []string
	var current strings.Builder
	inQuote := byte(0)

	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			} else {
				current.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == ' ' || c == '\t':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func parseInt(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// joinQuoted joins command args, quoting any that contain spaces.
func joinQuoted(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			parts[i] = `"` + a + `"`
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

func envToText(env map[string]string) string {
	keys := envKeys(env)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+env[k])
	}
	return strings.Join(lines, "\n")
}

// hasASCIIControl reports whether s contains any ASCII control character.
func hasASCIIControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	})
}

// localRefererPath derives a same-host, host-less redirect target from the
// Referer header, or returns ("", false) if the Referer is missing, malformed,
// control-character-laden, or points at a different host. The returned value is
// always a rooted relative path (path+query), so redirecting to it cannot leave
// this app's host even though the Referer header itself is untrusted.
func localRefererPath(r *http.Request, ref string) (string, bool) {
	if ref == "" || hasASCIIControl(ref) || strings.TrimSpace(ref) != ref {
		return "", false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", false
	}
	// Browsers send the Referer as an absolute URL; honor it only when it is an
	// http(s) URL on this same host.
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	if u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
		return "", false
	}
	// Rebuild as a host-less reference so the redirect target is structurally
	// incapable of leaving this host.
	path := u.Path
	if path == "" {
		path = "/"
	}
	dest := (&url.URL{Path: path, RawQuery: u.RawQuery}).String()
	if !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") || strings.Contains(dest, `\`) {
		return "", false
	}
	return dest, true
}

// redirectBack sends the user back to the page named by the Referer when it
// stays on this host, otherwise to fallback. The Referer is untrusted, so it is
// reduced to a same-host relative path by localRefererPath to avoid an open
// redirect (gosec G710).
func redirectBack(w http.ResponseWriter, r *http.Request, fallback string) {
	if dest, ok := localRefererPath(r, r.Header.Get("Referer")); ok {
		http.Redirect(w, r, dest, http.StatusFound) // #nosec G710 - reduced to a same-host relative path by localRefererPath
		return
	}
	http.Redirect(w, r, fallback, http.StatusFound) // #nosec G710 - fallback is a server-constructed relative path
}

// validateServerURL checks that a URL is a valid http or https URL.
func validateServerURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}

// validateExternalURL checks that a URL is safe to make outbound requests to.
// Rejects non-HTTPS schemes and private/loopback IP ranges to prevent SSRF.
// Hostnames are resolved to check that they don't point to private addresses.
func validateExternalURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("only https URLs are allowed")
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid URL")
	}
	host := parsed.Hostname()

	// Check literal IP addresses directly
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private/loopback addresses are not allowed")
		}
		return nil
	}

	// Resolve hostname and check all resulting IPs
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host: %w", err)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("host resolves to private/loopback address")
		}
	}
	return nil
}

// isPrivateIP returns true if the IP is loopback, private, link-local, or unspecified.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// commaFormat inserts commas into a numeric string (e.g., "35165" -> "35,165").
func commaFormat(s string) string {
	n := len(s)
	if n <= 3 {
		return s
	}
	return commaFormat(s[:n-3]) + "," + s[n-3:]
}

// handleServerOptimize triggers an LLM optimization run for a server's tools.
func (h *Handlers) handleServerOptimize(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.llmClient == nil || !h.llmClient.Available() {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"LLM API key not configured (set ARC_RELAY_LLM_API_KEY)"}`, http.StatusServiceUnavailable)
		return
	}

	if existing, err := h.optimizeStore.Get(id); err == nil && existing != nil && existing.Status == "running" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running", "message": "Optimization already in progress"})
		return
	}

	endpoints := h.proxy.Endpoints.Get(id)
	if endpoints == nil || len(endpoints.Tools) == 0 {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"no tools available - server may not be running"}`, http.StatusNotFound)
		return
	}

	toolsHash := mcp.HashTools(endpoints.Tools)
	_, originalChars := mcp.AuditTools(endpoints.Tools)

	if err := h.optimizeStore.Upsert(&store.ToolOptimization{
		ServerID:       id,
		ToolsHash:      toolsHash,
		OriginalChars:  originalChars,
		OptimizedChars: 0,
		OptimizedTools: json.RawMessage("[]"),
		PromptVersion:  mcp.PromptVersion,
		Model:          h.llmClient.Model(),
		Status:         "running",
	}); err != nil {
		slog.Error("optimize: failed to save running status", "server", id, "err", err)
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		optimized, err := mcp.OptimizeTools(ctx, h.llmClient, endpoints.Tools)
		if err != nil {
			slog.Error("optimize: failed", "server", id, "err", err)
			_ = h.optimizeStore.SetStatus(id, "error", err.Error())
			return
		}

		optimizedJSON, err := json.Marshal(optimized)
		if err != nil {
			slog.Error("optimize: failed to marshal result", "server", id, "err", err)
			_ = h.optimizeStore.SetStatus(id, "error", err.Error())
			return
		}

		_, optimizedChars := mcp.AuditTools(optimized)
		if err := h.optimizeStore.Upsert(&store.ToolOptimization{
			ServerID:       id,
			ToolsHash:      toolsHash,
			OriginalChars:  originalChars,
			OptimizedChars: optimizedChars,
			OptimizedTools: optimizedJSON,
			PromptVersion:  mcp.PromptVersion,
			Model:          h.llmClient.Model(),
			Status:         "ready",
		}); err != nil {
			slog.Error("optimize: failed to save result", "server", id, "err", err)
		} else {
			slog.Info("optimize: completed", "server", id,
				"original", originalChars, "optimized", optimizedChars,
				"reduction_pct", int(float64(originalChars-optimizedChars)/float64(originalChars)*100))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "running", "message": "Optimization started"})
}

// handleServerOptimizeToggle enables or disables serving optimized tools.
func (h *Handlers) handleServerOptimizeToggle(w http.ResponseWriter, r *http.Request, id string) {
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
	if err := h.servers.SetOptimizeEnabled(id, req.Enabled); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to update: %s"}`, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"optimize_enabled": req.Enabled})
}

// handleServerToolAudit returns tool size statistics and optimization status.
func (h *Handlers) handleServerToolAudit(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	srv, err := h.servers.Get(id)
	if err != nil || srv == nil {
		http.Error(w, `{"error":"server not found"}`, http.StatusNotFound)
		return
	}
	endpoints := h.proxy.Endpoints.Get(id)
	if endpoints == nil || len(endpoints.Tools) == 0 {
		http.Error(w, `{"error":"no tools available"}`, http.StatusNotFound)
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
	}
	if opt, err := h.optimizeStore.Get(id); err == nil && opt != nil {
		audit.HasOptimized = true
		audit.Status = opt.Status
		audit.IsStale = opt.ToolsHash != toolsHash
		if (opt.Status == "ready" || opt.Status == "stale") && totalChars > 0 {
			audit.OptimizedChars = opt.OptimizedChars
			audit.SavingsPercent = float64(totalChars-opt.OptimizedChars) / float64(totalChars) * 100
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(audit)
}
