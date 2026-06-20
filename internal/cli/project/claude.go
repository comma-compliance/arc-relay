package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/comma-compliance/arc-relay/internal/safefile"
)

const claudeConfigFile = ".mcp.json"

// ClaudeCodeTarget implements Target for Claude Code's .mcp.json format.
type ClaudeCodeTarget struct{}

func (c *ClaudeCodeTarget) Name() string {
	return "claude-code"
}

func (c *ClaudeCodeTarget) ConfigFileName() string {
	return claudeConfigFile
}

func (c *ClaudeCodeTarget) Detect(projectDir string) bool {
	path := filepath.Join(projectDir, claudeConfigFile)
	_, err := os.Stat(path)
	return err == nil
}

// mcpJSON is the top-level structure of .mcp.json.
// We use map[string]json.RawMessage for mcpServers to preserve entries we don't manage.
type mcpJSON struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
	// Capture any other top-level keys we don't know about
	Extra map[string]json.RawMessage `json:"-"`
}

// mcpServerEntry is the structure of a single server entry in .mcp.json.
type mcpServerEntry struct {
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (c *ClaudeCodeTarget) Read(projectDir, relayBaseURL string) ([]ManagedServer, error) {
	path := filepath.Join(projectDir, claudeConfigFile)
	// Confine the read to projectDir so a symlinked .mcp.json in a hostile
	// project tree cannot redirect us outside it.
	data, err := safefile.ReadFile(projectDir, claudeConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	parsed, err := parseMCPJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	relayPrefix := strings.TrimRight(relayBaseURL, "/") + "/mcp/"

	var managed []ManagedServer
	for name, raw := range parsed.MCPServers {
		var entry mcpServerEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue // skip entries we can't parse
		}
		if strings.HasPrefix(entry.URL, relayPrefix) {
			managed = append(managed, ManagedServer{
				Name: name,
				URL:  entry.URL,
			})
		}
	}

	return managed, nil
}

func (c *ClaudeCodeTarget) Write(projectDir, relayBaseURL, apiKey string, servers []ManagedServer) error {
	path := filepath.Join(projectDir, claudeConfigFile)

	// Load existing file or start fresh
	var raw map[string]json.RawMessage
	data, err := safefile.ReadFile(projectDir, claudeConfigFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		raw = make(map[string]json.RawMessage)
	} else {
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parsing existing %s: %w", path, err)
		}
	}

	// Get or create mcpServers
	var mcpServers map[string]json.RawMessage
	if existing, ok := raw["mcpServers"]; ok {
		if err := json.Unmarshal(existing, &mcpServers); err != nil {
			mcpServers = make(map[string]json.RawMessage)
		}
	} else {
		mcpServers = make(map[string]json.RawMessage)
	}

	// Add/update relay-managed servers
	for _, s := range servers {
		entry := mcpServerEntry{
			Type: "http",
			URL:  s.URL,
			Headers: map[string]string{
				"Authorization": "Bearer " + apiKey,
			},
		}
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshaling server %s: %w", s.Name, err)
		}
		mcpServers[s.Name] = json.RawMessage(entryJSON)
	}

	// Write back
	mcpServersJSON, err := json.Marshal(mcpServers)
	if err != nil {
		return fmt.Errorf("marshaling mcpServers: %w", err)
	}
	raw["mcpServers"] = json.RawMessage(mcpServersJSON)

	output, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling .mcp.json: %w", err)
	}
	output = append(output, '\n')

	if err := safefile.WriteFile(projectDir, claudeConfigFile, output, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}

func (c *ClaudeCodeTarget) Remove(projectDir string, names []string) ([]string, error) {
	path := filepath.Join(projectDir, claudeConfigFile)

	data, err := safefile.ReadFile(projectDir, claudeConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var mcpServers map[string]json.RawMessage
	if existing, ok := raw["mcpServers"]; ok {
		if err := json.Unmarshal(existing, &mcpServers); err != nil {
			return nil, fmt.Errorf("parsing mcpServers: %w", err)
		}
	}
	if mcpServers == nil {
		return nil, nil
	}

	removeSet := make(map[string]bool)
	for _, n := range names {
		removeSet[n] = true
	}

	var removed []string
	for name := range mcpServers {
		if removeSet[name] {
			delete(mcpServers, name)
			removed = append(removed, name)
		}
	}

	if len(removed) == 0 {
		return nil, nil
	}

	mcpServersJSON, err := json.Marshal(mcpServers)
	if err != nil {
		return nil, fmt.Errorf("marshaling mcpServers: %w", err)
	}
	raw["mcpServers"] = json.RawMessage(mcpServersJSON)

	output, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling .mcp.json: %w", err)
	}
	output = append(output, '\n')

	if err := safefile.WriteFile(projectDir, claudeConfigFile, output, 0600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}

	return removed, nil
}

// parseMCPJSON parses the .mcp.json file, handling both well-formed and edge cases.
func parseMCPJSON(data []byte) (*mcpJSON, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	result := &mcpJSON{
		MCPServers: make(map[string]json.RawMessage),
		Extra:      make(map[string]json.RawMessage),
	}

	for key, val := range raw {
		if key == "mcpServers" {
			if err := json.Unmarshal(val, &result.MCPServers); err != nil {
				return nil, fmt.Errorf("parsing mcpServers: %w", err)
			}
		} else {
			result.Extra[key] = val
		}
	}

	return result, nil
}
