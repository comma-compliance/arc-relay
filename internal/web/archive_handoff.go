package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/comma-compliance/arc-relay/internal/middleware"
	"github.com/comma-compliance/arc-relay/internal/safego"
	"github.com/comma-compliance/arc-relay/internal/store"
)

// archiveHandoffTTL is how long a begun handoff is valid for the user to
// complete signup on the compliance side and bounce back. Short enough
// that a stolen nonce is useless by the time it is noticed, long enough
// for a real user to finish signup in the popup tab.
const archiveHandoffTTL = 10 * time.Minute

// archiveHandoffRequest tracks a pending handoff started by an admin.
// The nonce is bound to the starting user so a nonce leaked to another
// session cannot be redeemed. The compliance side is required to echo
// the nonce verbatim in the return fragment; we validate that echo
// before applying any config changes.
type archiveHandoffRequest struct {
	Nonce     string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// archiveHandoffStore is an in-memory store for pending handoff nonces.
// In-memory is correct here because handoff is a short-lived interactive
// flow; a relay restart mid-handoff is rare and the user can simply
// retry. Kept close to deviceAuthStore in shape so the patterns rhyme.
type archiveHandoffStore struct {
	mu       sync.Mutex
	requests map[string]*archiveHandoffRequest // keyed by nonce
}

func newArchiveHandoffStore() *archiveHandoffStore {
	s := &archiveHandoffStore{
		requests: make(map[string]*archiveHandoffRequest),
	}
	go s.cleanup()
	return s
}

// create generates a new nonce bound to the given user and returns it.
func (s *archiveHandoffStore) create(userID string) (string, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[nonce] = &archiveHandoffRequest{
		Nonce:     nonce,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(archiveHandoffTTL),
	}
	return nonce, nil
}

// consume looks up a nonce, validates it belongs to the given user and
// is not expired, deletes it from the store, and returns true on
// success. Single-use: any subsequent call with the same nonce fails.
func (s *archiveHandoffStore) consume(nonce, userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[nonce]
	if !ok {
		return false
	}
	// Always delete on lookup - either we accept and consume, or the
	// nonce is stale/mismatched and should not linger for another try.
	delete(s.requests, nonce)
	if time.Now().After(req.ExpiresAt) {
		return false
	}
	if req.UserID != userID {
		return false
	}
	return true
}

// cleanup removes expired requests periodically.
func (s *archiveHandoffStore) cleanup() {
	defer safego.Recover("archive handoff cleanup")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for nonce, req := range s.requests {
			if now.After(req.ExpiresAt) {
				delete(s.requests, nonce)
			}
		}
		s.mu.Unlock()
	}
}

// decorateArchiveConfigForDisplay takes a raw stored archive config
// blob and returns a JSON string with an added nacl_key_id field
// derived from the recipient pubkey when one is present. Used only
// for template display - the stored blob is left untouched so we
// never persist a value that can drift from the pubkey. Returns the
// input unchanged if the config is unparseable or has no key.
//
// Pre-existing concern (not introduced by this function): the raw
// blob still carries auth_value into the data-config attribute so
// the form can round-trip existing bearer tokens. An XSS or hostile
// browser extension on this page would see the token. Addressing
// that properly requires a separate UX for "show/reset token" and
// is tracked outside this change.
func decorateArchiveConfigForDisplay(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return string(raw)
	}
	keyB64, _ := cfg["nacl_recipient_key"].(string)
	if keyB64 == "" {
		return string(raw)
	}
	key, err := middleware.DecodeRecipientKey(keyB64)
	if err != nil {
		return string(raw)
	}
	cfg["nacl_key_id"] = middleware.ComputeKeyID(key)
	out, err := json.Marshal(cfg)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// handleArchiveHandoffBegin starts a stateful handoff to the compliance
// archive signup flow. Returns a one-time nonce the browser must pass
// in the ?state= parameter of the popup URL and echo back in the
// fragment so handleArchiveHandoffComplete can prove the fragment
// originated from a handoff this session initiated.
func (h *Handlers) handleArchiveHandoffBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := getUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}
	nonce, err := h.archiveHandoff.create(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start handoff"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"state":      nonce,
		"expires_in": int(archiveHandoffTTL.Seconds()),
	})
}

// handleArchiveHandoffComplete applies a config delivered via the
// handoff fragment after validating the nonce. This is the single
// source of truth for handoff-applied config: the browser is not
// allowed to write archive config directly from the fragment; it must
// POST here with the echoed nonce, and server-side validation
// (middleware.ValidateArchiveConfig) is authoritative over whatever
// the fragment contained.
//
// Request shape:
//
//	{
//	  "state":              "<nonce>",
//	  "archive_url":        "https://...",
//	  "archive_token":      "...",        // optional
//	  "nacl_recipient_key": "<base64>",   // optional
//	  "nacl_key_id":        "<base64>"    // optional, advisory only
//	}
//
// nacl_key_id is accepted but not trusted - we recompute the kid from
// the pubkey at runtime via computeKeyID so a fraudulent or stale
// key_id from the fragment cannot poison routing on the compliance
// side.
func (h *Handlers) handleArchiveHandoffComplete(w http.ResponseWriter, r *http.Request) {
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
		State            string `json:"state"`
		ArchiveURL       string `json:"archive_url"`
		ArchiveToken     string `json:"archive_token"`
		NaClRecipientKey string `json:"nacl_recipient_key"`
		NaClKeyID        string `json:"nacl_key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.State == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state is required"})
		return
	}
	if !h.archiveHandoff.consume(body.State, user.ID) {
		// Do not distinguish "unknown nonce" from "expired" from
		// "wrong user" - all three return the same message so an
		// attacker learns nothing about the store's contents.
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "handoff expired or invalid, please retry setup",
		})
		return
	}

	// Build the archive config from the fragment values. We preserve
	// any existing include/auth_type settings from a prior config if
	// the handoff does not override them, so re-running the flow does
	// not wipe customizations the admin made locally.
	existing, _ := h.middlewareStore.GetGlobal("archive")
	var cfg middleware.ArchiveConfig
	if existing != nil {
		parsed, parseErr := middleware.ParseArchiveConfig(existing.Config)
		if parseErr == nil {
			cfg = parsed
		}
	}
	if cfg.Include == "" {
		cfg.Include = "both"
	}
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = "X-API-Key"
	}
	cfg.URL = body.ArchiveURL
	if body.ArchiveToken != "" {
		cfg.AuthType = "bearer"
		cfg.AuthValue = body.ArchiveToken
	}
	// Explicit downgrade path: an empty recipient key in the handoff
	// payload clears any previously saved key. This lets a tenant
	// re-run setup to disable envelope encryption without having to
	// hand-edit the form.
	cfg.NaClRecipientKey = body.NaClRecipientKey

	if _, err := middleware.ValidateArchiveConfig(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	normalized, err := json.Marshal(cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to normalize config"})
		return
	}

	mc := &store.MiddlewareConfig{
		Middleware: "archive",
		Enabled:    false,
		Config:     normalized,
		Priority:   40,
	}
	if err := h.middlewareStore.UpsertGlobal(mc); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save"})
		return
	}

	// Retarget the queue and resume delivery the same way a manual
	// Save Config would, so a handoff that happens while a backlog is
	// draining does not strand messages on the old destination. The
	// nil guard on mwRegistry exists so handler tests can wire a
	// minimal Handlers without having to stand up a full registry;
	// production always sets it via NewHandlers.
	rewritten := int64(0)
	if h.mwRegistry != nil {
		if disp := h.mwRegistry.ArchiveDispatcher(); disp != nil {
			if n, rwErr := disp.RewriteHeldDelivery(cfg); rwErr == nil {
				rewritten = n
			}
			disp.ResetCircuit()
		}
	}

	// Return the saved config so the browser can update its form
	// state without having to re-fetch. We echo auth_value here on
	// purpose: the server_detail template already ships the stored
	// config (including auth_value) into a data-config attribute on
	// page load, so the handoff response is not a new exposure. The
	// alternative - omitting auth_value - would leave the form field
	// empty after a handoff and let any subsequent saveArchiveConfig
	// click silently clobber the just-saved token.
	resp := map[string]interface{}{
		"status":    "ok",
		"rewritten": rewritten,
		"config": map[string]interface{}{
			"url":                cfg.URL,
			"auth_type":          cfg.AuthType,
			"auth_value":         cfg.AuthValue,
			"include":            cfg.Include,
			"nacl_recipient_key": cfg.NaClRecipientKey,
		},
	}
	if cfg.NaClRecipientKey != "" {
		if key, err := middleware.DecodeRecipientKey(cfg.NaClRecipientKey); err == nil {
			resp["nacl_key_id"] = middleware.ComputeKeyID(key)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
