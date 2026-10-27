package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/comma-compliance/arc-relay/internal/oauth"
	"github.com/comma-compliance/arc-relay/internal/safego"
	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/google/uuid"
)

// --- OAuth 2.1 Authorization Server (Provider) ---
//
// Enables Claude Desktop and other MCP clients to authenticate via standard
// OAuth 2.1 Authorization Code + PKCE flow. Auth codes are in-memory (ephemeral,
// 5-min TTL). Clients and refresh tokens are persisted to SQLite.

// oauthProvider bundles state for the OAuth authorization server.
type oauthProvider struct {
	codes        *oauthAuthCodeStore
	clientStore  *store.OAuthClientStore
	refreshStore *store.OAuthRefreshTokenStore
	tokenStore   *store.OAuthTokenStore
}

func newOAuthProvider(tokenStore *store.OAuthTokenStore, clientStore *store.OAuthClientStore, refreshStore *store.OAuthRefreshTokenStore) *oauthProvider {
	return &oauthProvider{
		codes:        newOAuthAuthCodeStore(),
		clientStore:  clientStore,
		refreshStore: refreshStore,
		tokenStore:   tokenStore,
	}
}

// --- Auth Code Store (in-memory, ephemeral) ---

type oauthAuthCode struct {
	Code          string
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type oauthAuthCodeStore struct {
	mu    sync.Mutex
	codes map[string]*oauthAuthCode
}

func newOAuthAuthCodeStore() *oauthAuthCodeStore {
	s := &oauthAuthCodeStore{codes: make(map[string]*oauthAuthCode)}
	go s.cleanup()
	return s
}

func (s *oauthAuthCodeStore) create(clientID, userID, redirectURI, codeChallenge, scope, resource string) (string, error) {
	code, err := generateOAuthCode()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = &oauthAuthCode{
		Code:          code,
		ClientID:      clientID,
		UserID:        userID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Scope:         scope,
		Resource:      resource,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	return code, nil
}

func (s *oauthAuthCodeStore) consume(code string) *oauthAuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok || time.Now().After(ac.ExpiresAt) {
		delete(s.codes, code)
		return nil
	}
	delete(s.codes, code)
	return ac
}

func (s *oauthAuthCodeStore) cleanup() {
	defer safego.Recover("oauth code cleanup")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for code, ac := range s.codes {
			if now.After(ac.ExpiresAt) {
				delete(s.codes, code)
			}
		}
		s.mu.Unlock()
	}
}

// --- Helpers ---

func generateOAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func oauthError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

// mintAccessToken creates a new OAuth access token stored in the DB, returns raw token.
func (h *Handlers) mintAccessToken(userID, clientID, scope, resource string) (string, error) {
	rawToken := uuid.New().String()
	tokenH := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenH[:])
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := h.oauthProv.tokenStore.Create(tokenHash, userID, clientID, scope, resource, expiresAt); err != nil {
		return "", err
	}
	return rawToken, nil
}

// mintRefreshToken creates a new refresh token stored in the DB, returns raw token.
func (h *Handlers) mintRefreshToken(userID, clientID, scope, resource string) (string, error) {
	rawToken := uuid.New().String()
	tokenH := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenH[:])
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	if err := h.oauthProv.refreshStore.Create(tokenHash, userID, clientID, scope, resource, expiresAt); err != nil {
		return "", err
	}
	return rawToken, nil
}

// --- HTTP Handlers ---

// handleProtectedResourceMetadata serves GET /.well-known/oauth-protected-resource[/path] (RFC 9728).
func (h *Handlers) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	baseURL := h.cfg.PublicBaseURL()

	subPath := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource")
	resource := baseURL
	if subPath != "" && subPath != "/" {
		resource = baseURL + subPath
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{baseURL},
		"bearer_methods_supported": []string{"header"},
	})
}

// handleAuthorizationServerMetadata serves GET /.well-known/oauth-authorization-server (RFC 8414).
func (h *Handlers) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	baseURL := h.cfg.PublicBaseURL()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/authorize",
		"token_endpoint":                        baseURL + "/token",
		"registration_endpoint":                 baseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	})
}

// handleOAuthRegister handles POST /register (RFC 7591 Dynamic Client Registration).
func (h *Handlers) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}

	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris required")
		return
	}

	for _, uri := range req.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("invalid URI: %s", uri))
			return
		}
		host := parsed.Hostname()
		if parsed.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && !strings.HasPrefix(host, "[::1]") {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "http redirect_uri only allowed for localhost")
			return
		}
	}

	if req.ClientName == "" {
		req.ClientName = "MCP Client"
	}

	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}

	clientID := uuid.New().String()
	var clientSecret string
	var secretHash string
	if authMethod == "client_secret_post" {
		clientSecret = uuid.New().String()
		h := sha256.Sum256([]byte(clientSecret))
		secretHash = hex.EncodeToString(h[:])
	}

	if err := h.oauthProv.clientStore.Create(clientID, secretHash, req.ClientName, authMethod, req.RedirectURIs); err != nil {
		slog.Error("oauth DCR: failed to register client", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to register client")
		return
	}

	slog.Debug("oauth DCR: registered client", "client_name", req.ClientName, "client_id", clientID)

	resp := map[string]any{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"response_types":             req.ResponseTypes,
		"token_endpoint_auth_method": authMethod,
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleOAuthAuthorize handles GET/POST /authorize.
func (h *Handlers) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
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

	ctx := setUser(r.Context(), user)
	ctx = setSessionID(ctx, cookie.Value)
	r = r.WithContext(ctx)

	switch r.Method {
	case http.MethodGet:
		h.handleOAuthAuthorizeGet(w, r)
	case http.MethodPost:
		if !h.validateCSRF(r, cookie.Value) {
			http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		h.handleOAuthAuthorizePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handlers) handleOAuthAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	q := r.URL.Query()

	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	scope := q.Get("scope")
	resource := q.Get("resource")

	if responseType != "code" {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Unsupported response_type. Only 'code' is supported.",
		})
		return
	}

	if clientID == "" {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Missing client_id parameter.",
		})
		return
	}

	client := h.oauthProv.clientStore.Get(clientID)
	if client == nil {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Unknown application. It may need to re-register.",
		})
		return
	}

	if redirectURI == "" || !client.HasRedirectURI(redirectURI) {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Invalid redirect_uri.",
		})
		return
	}

	if codeChallenge == "" || codeChallengeMethod != "S256" {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "PKCE with S256 code_challenge is required.",
		})
		return
	}

	if scope == "" {
		scope = "mcp"
	}

	h.render(w, r, "oauth_authorize.html", map[string]any{
		"Nav":                 "",
		"User":                user,
		"ClientName":          client.ClientName,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Scope":               scope,
		"Resource":            resource,
		"ShowConsent":         true,
	})
}

func (h *Handlers) handleOAuthAuthorizePost(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	action := r.FormValue("action")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	scope := r.FormValue("scope")
	resource := r.FormValue("resource")

	if scope == "" {
		scope = "mcp"
	}

	// Re-validate client_id and redirect_uri server-side (don't just trust hidden form inputs)
	client := h.oauthProv.clientStore.Get(clientID)
	if client == nil {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Unknown application. It may need to re-register.",
		})
		return
	}
	if redirectURI == "" || !client.HasRedirectURI(redirectURI) {
		h.render(w, r, "oauth_authorize.html", map[string]any{
			"Nav": "", "User": user,
			"Error": "Invalid redirect_uri.",
		})
		return
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := redirect.Query()

	if action == "deny" {
		params.Set("error", "access_denied")
		if state != "" {
			params.Set("state", state)
		}
		redirect.RawQuery = params.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		return
	}

	code, err := h.oauthProv.codes.create(clientID, user.ID, redirectURI, codeChallenge, scope, resource)
	if err != nil {
		slog.Error("oauth authorize: failed to create auth code", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	slog.Debug("oauth authorize: approved", "username", user.Username, "client_id", clientID)

	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	redirect.RawQuery = params.Encode()
	redirectURL := redirect.String()

	// Render a success page with JS redirect instead of HTTP redirect.
	// The redirect URL typically goes to localhost where the MCP client catches it,
	// which means the browser tab would stay on the consent page if we used HTTP redirect.
	// By rendering a success page first and redirecting via JS, the user sees confirmation.
	h.render(w, r, "oauth_authorize.html", map[string]any{
		"Nav":         "",
		"User":        user,
		"ShowSuccess": true,
		"RedirectURL": redirectURL,
		"ClientName":  client.ClientName,
	})
}

// handleOAuthToken handles POST /token.
func (h *Handlers) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form body")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleTokenAuthorizationCode(w, r)
	case "refresh_token":
		h.handleTokenRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("grant_type %q is not supported", grantType))
	}
}

func (h *Handlers) handleTokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || clientID == "" || codeVerifier == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code, client_id, and code_verifier are required")
		return
	}

	client := h.oauthProv.clientStore.Get(clientID)
	if client == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}

	if client.TokenEndpointAuthMethod == "client_secret_post" {
		clientSecret := r.FormValue("client_secret")
		if !h.oauthProv.clientStore.ValidateSecret(clientID, clientSecret) {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
			return
		}
	}

	ac := h.oauthProv.codes.consume(code)
	if ac == nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired, or already-used authorization code")
		return
	}

	if ac.ClientID != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	if ac.RedirectURI != redirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	challenge := oauth.ComputeCodeChallenge(codeVerifier)
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(ac.CodeChallenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier does not match code_challenge")
		return
	}

	accessToken, err := h.mintAccessToken(ac.UserID, clientID, ac.Scope, ac.Resource)
	if err != nil {
		slog.Error("oauth token: failed to mint access token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}

	refreshToken, err := h.mintRefreshToken(ac.UserID, clientID, ac.Scope, ac.Resource)
	if err != nil {
		slog.Error("oauth token: failed to mint refresh token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to create refresh token")
		return
	}

	slog.Debug("oauth token: issued access+refresh tokens", "user_id", ac.UserID, "client_id", clientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         ac.Scope,
	})
}

func (h *Handlers) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenRaw := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshTokenRaw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	if clientID != "" {
		client := h.oauthProv.clientStore.Get(clientID)
		if client == nil {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
			return
		}
	}

	rt := h.oauthProv.refreshStore.Consume(refreshTokenRaw)
	if rt == nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}

	if clientID != "" && rt.ClientID != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	accessToken, err := h.mintAccessToken(rt.UserID, rt.ClientID, rt.Scope, rt.Resource)
	if err != nil {
		slog.Error("oauth refresh: failed to mint access token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}

	newRefreshToken, err := h.mintRefreshToken(rt.UserID, rt.ClientID, rt.Scope, rt.Resource)
	if err != nil {
		slog.Error("oauth refresh: failed to mint refresh token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to create refresh token")
		return
	}

	slog.Debug("oauth refresh: rotated tokens", "user_id", rt.UserID, "client_id", rt.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": newRefreshToken,
		"scope":         rt.Scope,
	})
}
