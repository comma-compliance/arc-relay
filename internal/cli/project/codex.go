package project

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/comma-compliance/arc-relay/internal/safefile"
)

const codexConfigFile = ".codex/config.toml"

// CodexTarget implements Target for Codex CLI's .codex/config.toml format.
type CodexTarget struct{}

func (c *CodexTarget) Name() string {
	return "codex"
}

func (c *CodexTarget) ConfigFileName() string {
	return codexConfigFile
}

func (c *CodexTarget) Detect(projectDir string) bool {
	path := filepath.Join(projectDir, codexConfigFile)
	_, err := os.Stat(path)
	return err == nil
}

func (c *CodexTarget) Read(projectDir, relayBaseURL string) ([]ManagedServer, error) {
	raw, err := loadCodexConfig(projectDir)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	mcpServers, ok := getCodexMCPServers(raw)
	if !ok {
		return nil, nil
	}

	relayPrefix := strings.TrimRight(relayBaseURL, "/") + "/mcp/"

	var managed []ManagedServer
	for name, value := range mcpServers {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}

		url, _ := entry["url"].(string)
		if strings.HasPrefix(url, relayPrefix) {
			managed = append(managed, ManagedServer{
				Name: name,
				URL:  url,
			})
		}
	}

	return managed, nil
}

func (c *CodexTarget) Write(projectDir, relayBaseURL, apiKey string, servers []ManagedServer) error {
	raw, err := loadCodexConfig(projectDir)
	if err != nil {
		return err
	}
	if raw == nil {
		raw = make(map[string]any)
	}

	mcpServers, ok := getCodexMCPServers(raw)
	if !ok {
		mcpServers = make(map[string]any)
	}

	for _, s := range servers {
		mcpServers[s.Name] = map[string]any{
			"url": s.URL,
			"http_headers": map[string]string{
				"Authorization": "Bearer " + apiKey,
			},
		}
	}

	raw["mcp_servers"] = mcpServers
	return writeCodexConfig(projectDir, raw)
}

func (c *CodexTarget) Remove(projectDir string, names []string) ([]string, error) {
	raw, err := loadCodexConfig(projectDir)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	mcpServers, ok := getCodexMCPServers(raw)
	if !ok {
		if _, exists := raw["mcp_servers"]; exists {
			return nil, fmt.Errorf("parsing mcp_servers: expected table")
		}
		return nil, nil
	}

	removeSet := make(map[string]bool)
	for _, name := range names {
		removeSet[name] = true
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

	raw["mcp_servers"] = mcpServers
	if err := writeCodexConfig(projectDir, raw); err != nil {
		return nil, err
	}

	return removed, nil
}

// loadCodexConfig reads projectDir/.codex/config.toml, confined to projectDir so
// a symlinked config in a hostile project tree cannot redirect the read.
func loadCodexConfig(projectDir string) (map[string]any, error) {
	path := filepath.Join(projectDir, codexConfigFile)
	data, err := safefile.ReadFile(projectDir, codexConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if raw == nil {
		raw = make(map[string]any)
	}

	return raw, nil
}

// writeCodexConfig writes projectDir/.codex/config.toml, confined to projectDir.
// The .codex parent directory is created first so the confined write has an
// existing, in-base parent to resolve against.
func writeCodexConfig(projectDir string, raw map[string]any) error {
	path := filepath.Join(projectDir, codexConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(raw); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}

	if err := safefile.WriteFile(projectDir, codexConfigFile, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}

func getCodexMCPServers(raw map[string]any) (map[string]any, bool) {
	value, ok := raw["mcp_servers"]
	if !ok || value == nil {
		return nil, false
	}

	mcpServers, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}

	return mcpServers, true
}
