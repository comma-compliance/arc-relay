package config

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/comma-compliance/arc-relay/internal/safefile"
)

const (
	configDirName  = "arc-sync"
	configFileName = "config.json"
)

// Config holds the relay connection details.
type Config struct {
	RelayURL string `json:"relay_url"`
	APIKey   string `json:"api_key"`
}

// Credentials holds resolved credentials with metadata about where they came from.
type Credentials struct {
	RelayURL string
	APIKey   string
	Source   string // "environment", "config file", "flags"
}

// DefaultConfigDir returns the default config directory path for the current platform.
func DefaultConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config directory: %w", err)
	}
	return filepath.Join(base, configDirName), nil
}

// ConfigPath returns the full path to config.json within the given config directory.
func ConfigPath(configDir string) string {
	return filepath.Join(configDir, configFileName)
}

// LoadConfig loads configuration from the given directory, or returns an error
// if the config file doesn't exist or is invalid.
func LoadConfig(configDir string) (*Config, error) {
	path := ConfigPath(configDir)
	// Confine the read to configDir; the file holds the relay API key.
	data, err := safefile.ReadFile(configDir, configFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no configuration found — run 'arc-sync init' to get started, or 'arc-sync --help' for usage")
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if cfg.RelayURL == "" {
		return nil, fmt.Errorf("config %s: relay_url is required", path)
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("config %s: api_key is required", path)
	}

	return &cfg, nil
}

// SaveConfig writes the config to the given directory, creating the directory
// with 0700 permissions and the file with 0600 permissions.
func SaveConfig(configDir string, cfg *Config) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("creating config directory %s: %w", configDir, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	data = append(data, '\n')

	path := ConfigPath(configDir)
	if err := safefile.WriteFile(configDir, configFileName, data, 0600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}

	return nil
}

// ResolveCredentials resolves credentials from environment variables first, then
// config file. Returns the resolved credentials with their source.
func ResolveCredentials(configDir string) (*Credentials, error) {
	url := os.Getenv("ARC_SYNC_URL")
	key := os.Getenv("ARC_SYNC_API_KEY")
	if url != "" && key != "" {
		return &Credentials{
			RelayURL: url,
			APIKey:   key,
			Source:   "environment",
		}, nil
	}

	cfg, err := LoadConfig(configDir)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		RelayURL: cfg.RelayURL,
		APIKey:   cfg.APIKey,
		Source:   fmt.Sprintf("config file (%s)", ConfigPath(configDir)),
	}, nil
}

// CheckPermissions checks if the config file has secure permissions (0600).
// Returns a warning message if permissions are too open, or empty string if OK.
func CheckPermissions(configDir string) string {
	path := ConfigPath(configDir)
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return fmt.Sprintf("⚠  %s has permissions %04o, should be 0600\n   Fix with: chmod 600 %s", path, mode, path)
	}
	return ""
}

// CheckPermissionsFS is like CheckPermissions but accepts an fs.FileInfo directly
// for testing purposes.
func CheckPermissionsFS(path string, info fs.FileInfo) string {
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return fmt.Sprintf("⚠  %s has permissions %04o, should be 0600\n   Fix with: chmod 600 %s", path, mode, path)
	}
	return ""
}
