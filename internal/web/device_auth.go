package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// deviceAuthRequest represents a pending device authorization request.
type deviceAuthRequest struct {
	DeviceCode string
	UserCode   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Status     string // "pending", "approved", "denied"
	APIKey     string // set on approval
}

// deviceAuthStore is an in-memory store for pending device auth requests.
type deviceAuthStore struct {
	mu       sync.Mutex
	requests map[string]*deviceAuthRequest // keyed by device_code
	byUser   map[string]string             // user_code -> device_code
}

func newDeviceAuthStore() *deviceAuthStore {
	s := &deviceAuthStore{
		requests: make(map[string]*deviceAuthRequest),
		byUser:   make(map[string]string),
	}
	go s.cleanup()
	return s
}

// create generates a new device auth request and returns it.
func (s *deviceAuthStore) create() (*deviceAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceCode, err := generateDeviceCode()
	if err != nil {
		return nil, err
	}
	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	req := &deviceAuthRequest{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		Status:     "pending",
	}
	s.requests[deviceCode] = req
	s.byUser[userCode] = deviceCode
	return req, nil
}

// get returns the request for a device code, or nil if not found/expired.
func (s *deviceAuthStore) get(deviceCode string) *deviceAuthRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[deviceCode]
	if !ok || time.Now().After(req.ExpiresAt) {
		return nil
	}
	return req
}

// getByUserCode returns the request for a user code, or nil if not found/expired.
func (s *deviceAuthStore) getByUserCode(userCode string) *deviceAuthRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	deviceCode, ok := s.byUser[userCode]
	if !ok {
		return nil
	}
	req, ok := s.requests[deviceCode]
	if !ok || time.Now().After(req.ExpiresAt) {
		return nil
	}
	return req
}

// approve marks a device code as approved with the given API key.
func (s *deviceAuthStore) approve(deviceCode, apiKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.requests[deviceCode]; ok {
		req.Status = "approved"
		req.APIKey = apiKey
	}
}

// deny marks a device code as denied.
func (s *deviceAuthStore) deny(deviceCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.requests[deviceCode]; ok {
		req.Status = "denied"
	}
}

// consume retrieves and removes a completed (approved/denied) request.
// Returns nil if still pending or not found.
func (s *deviceAuthStore) consume(deviceCode string) *deviceAuthRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[deviceCode]
	if !ok || time.Now().After(req.ExpiresAt) {
		return nil
	}
	if req.Status == "pending" {
		return req // still pending, don't consume
	}
	// Remove consumed request
	delete(s.requests, deviceCode)
	delete(s.byUser, req.UserCode)
	return req
}

// cleanup removes expired requests periodically.
func (s *deviceAuthStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for code, req := range s.requests {
			if now.After(req.ExpiresAt) {
				delete(s.byUser, req.UserCode)
				delete(s.requests, code)
			}
		}
		s.mu.Unlock()
	}
}

// generateDeviceCode returns a crypto-random hex string.
func generateDeviceCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating device code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode returns a short, human-readable code like "ABCD-1234".
func generateUserCode() (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1 to avoid confusion
	code := make([]byte, 8)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("generating user code: %w", err)
		}
		code[i] = chars[n.Int64()]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// --- HTTP Handlers ---

// handleDeviceAuthStart handles POST /api/auth/device — initiates device auth flow.
func (h *Handlers) handleDeviceAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	req, err := h.deviceAuth.create()
	if err != nil {
		slog.Error("Device auth: failed to create request", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
		return
	}

	baseURL := h.cfg.PublicBaseURL()
	verificationURL := fmt.Sprintf("%s/auth/device?code=%s", baseURL, req.UserCode)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":      req.DeviceCode,
		"user_code":        req.UserCode,
		"verification_url": verificationURL,
		"expires_in":       300,
		"interval":         5,
	})
}

// handleDeviceAuthToken handles POST /api/auth/device/token — polls for token.
func (h *Handlers) handleDeviceAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeviceCode == "" {
		http.Error(w, `{"error":"invalid request, device_code required"}`, http.StatusBadRequest)
		return
	}

	req := h.deviceAuth.consume(body.DeviceCode)
	if req == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch req.Status {
	case "approved":
		_ = json.NewEncoder(w).Encode(map[string]string{"api_key": req.APIKey})
	case "denied":
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	default: // pending
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	}
}

// handleDeviceAuthPage handles GET/POST /auth/device — browser approval page.
func (h *Handlers) handleDeviceAuthPage(w http.ResponseWriter, r *http.Request) {
	// Check session — if not logged in, redirect to login with return URL
	cookie, err := r.Cookie("session")
	if err != nil {
		returnURL := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(returnURL), http.StatusFound)
		return
	}
	user, _, ok := h.sessionStore.Get(cookie.Value)
	if !ok {
		returnURL := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(returnURL), http.StatusFound)
		return
	}

	// Inject context for CSRF and user display
	ctx := setUser(r.Context(), user)
	ctx = setSessionID(ctx, cookie.Value)
	r = r.WithContext(ctx)

	if r.Method == http.MethodGet {
		h.handleDeviceAuthPageGet(w, r)
		return
	}

	if r.Method == http.MethodPost {
		// Validate CSRF
		if !h.validateCSRF(r, cookie.Value) {
			http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		h.handleDeviceAuthPagePost(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (h *Handlers) handleDeviceAuthPageGet(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	userCode := r.URL.Query().Get("code")

	data := map[string]any{
		"Nav":  "",
		"User": user,
	}

	// After POST approval redirect, show success without re-creating anything.
	// Validate the flash nonce to prevent forging the approved state.
	if nonce := r.URL.Query().Get("approved"); nonce != "" {
		if _, ok := h.flashKeys.LoadAndDelete("device-approved-" + nonce); ok {
			data["Approved"] = true
		}
		// If nonce is invalid/expired, just show the normal page
		h.render(w, r, "device_auth.html", data)
		return
	}

	if userCode == "" {
		data["Error"] = "No device code provided. Please run arc-sync init to start the authorization flow."
		h.render(w, r, "device_auth.html", data)
		return
	}

	req := h.deviceAuth.getByUserCode(strings.ToUpper(userCode))
	if req == nil {
		data["Error"] = "This device code has expired or is invalid. Please run arc-sync init again."
		h.render(w, r, "device_auth.html", data)
		return
	}

	if req.Status != "pending" {
		data["Error"] = "This device code has already been used."
		h.render(w, r, "device_auth.html", data)
		return
	}

	data["UserCode"] = req.UserCode
	data["DeviceCode"] = req.DeviceCode
	h.render(w, r, "device_auth.html", data)
}

func (h *Handlers) handleDeviceAuthPagePost(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	deviceCode := r.FormValue("device_code")
	action := r.FormValue("action")

	if deviceCode == "" {
		http.Redirect(w, r, "/auth/device", http.StatusFound)
		return
	}

	req := h.deviceAuth.get(deviceCode)
	if req == nil || req.Status != "pending" {
		h.render(w, r, "device_auth.html", map[string]any{
			"Nav":   "",
			"User":  user,
			"Error": "This device code has expired or is invalid.",
		})
		return
	}

	if action == "deny" {
		h.deviceAuth.deny(deviceCode)
		h.render(w, r, "device_auth.html", map[string]any{
			"Nav":    "",
			"User":   user,
			"Denied": true,
		})
		return
	}

	// Approve: create a new API key for this user, inheriting their default profile
	fullUser, _ := h.users.Get(user.ID)
	var deviceProfileID *string
	if fullUser != nil && fullUser.DefaultProfileID != nil {
		deviceProfileID = fullUser.DefaultProfileID
	}
	rawKey, _, err := h.users.CreateAPIKey(user.ID, "arc-sync device auth", deviceProfileID)
	if err != nil {
		slog.Error("device auth: failed to create API key", "user", user.Username, "err", err)
		h.render(w, r, "device_auth.html", map[string]any{
			"Nav":   "",
			"User":  user,
			"Error": "Failed to create API key. Please try again.",
		})
		return
	}

	h.deviceAuth.approve(deviceCode, rawKey)
	slog.Debug("device auth: approved", "user", user.Username)

	// Redirect to prevent duplicate key creation on browser refresh.
	// Use a flash nonce to prevent forging the approved state.
	nonce, err := generateID()
	if err != nil {
		slog.Error("device auth: failed to generate flash nonce", "err", err)
		http.Redirect(w, r, "/auth/device", http.StatusFound)
		return
	}
	h.flashKeys.Store("device-approved-"+nonce, true)
	go func() {
		time.Sleep(60 * time.Second)
		h.flashKeys.Delete("device-approved-" + nonce)
	}()
	http.Redirect(w, r, "/auth/device?approved="+nonce, http.StatusFound)
}

// --- Install script handler ---

// handleInstallScript serves GET /install.sh — a templated shell installer.
func (h *Handlers) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := h.cfg.PublicBaseURL()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, `#!/bin/bash
set -e

RELAY_URL=%q

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BINARY="arc-sync-${OS}-${ARCH}"
DOWNLOAD_URL="${RELAY_URL}/download/${BINARY}"

# Determine install location
if [ "$(id -u)" = "0" ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

echo "Downloading arc-sync for ${OS}/${ARCH}..."
curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/arc-sync"
chmod +x "${INSTALL_DIR}/arc-sync"
echo "Installed to ${INSTALL_DIR}/arc-sync"

# Ensure install dir is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "Add to your PATH:  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# Pass through flags if provided
INVITE_TOKEN=""
INVITE_USERNAME=""
INVITE_PASSWORD=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) INVITE_TOKEN="$2"; shift 2 ;;
    --username) INVITE_USERNAME="$2"; shift 2 ;;
    --password) INVITE_PASSWORD="$2"; shift 2 ;;
    *) shift ;;
  esac
done

echo ""
echo "Setting up connection to ${RELAY_URL}..."

# Build args
INIT_ARGS="init ${RELAY_URL}"
[ -n "$INVITE_TOKEN" ]    && INIT_ARGS="${INIT_ARGS} --token ${INVITE_TOKEN}"
[ -n "$INVITE_USERNAME" ] && INIT_ARGS="${INIT_ARGS} --username ${INVITE_USERNAME}"
[ -n "$INVITE_PASSWORD" ] && INIT_ARGS="${INIT_ARGS} --password ${INVITE_PASSWORD}"

# When piped (curl | bash), stdin is consumed by bash reading the script.
# Redirect from /dev/tty so arc-sync can prompt interactively.
if [ -t 0 ]; then
  "${INSTALL_DIR}/arc-sync" ${INIT_ARGS}
else
  "${INSTALL_DIR}/arc-sync" ${INIT_ARGS} < /dev/tty
fi
`, baseURL)
}

// handleDownload serves GET /download/arc-sync-{os}-{arch}.
// Serves from local /data/downloads/ directory if the file exists,
// otherwise falls back to GitHub releases redirect.
func (h *Handlers) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	binary := strings.TrimPrefix(r.URL.Path, "/download/")
	if binary == "" {
		http.Error(w, "Missing binary name", http.StatusBadRequest)
		return
	}

	// Validate binary name to prevent path traversal
	validBinaries := map[string]bool{
		"arc-sync-linux-amd64":       true,
		"arc-sync-linux-arm64":       true,
		"arc-sync-darwin-arm64":      true,
		"arc-sync-darwin-amd64":      true,
		"arc-sync-windows-amd64.exe": true,
		"arc-sync-windows-arm64.exe": true,
	}
	if !validBinaries[binary] {
		http.Error(w, "Unknown binary", http.StatusNotFound)
		return
	}

	// Serve from local downloads directory if available.
	// Use /data/downloads inside the container (matches the volume mount).
	dataDir := filepath.Dir(h.cfg.Database.Path)
	localPath := filepath.Join(dataDir, "downloads", binary)
	if info, err := os.Lstat(localPath); err == nil && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 { // #nosec G703 - binary is validated against a fixed allowlist above, so localPath cannot traverse
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", binary))
		http.ServeFile(w, r, localPath) // #nosec G703 - binary is validated against a fixed allowlist above, so localPath cannot traverse
		return
	}

	// Fall back to GitHub releases
	githubURL := fmt.Sprintf("https://github.com/comma-compliance/arc-relay/releases/latest/download/%s", binary)
	http.Redirect(w, r, githubURL, http.StatusFound) // #nosec G710 - fixed github.com host, binary is allowlisted above
}
