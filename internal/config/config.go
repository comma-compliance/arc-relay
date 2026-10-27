package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server     ServerConfig     `toml:"server"`
	Database   DatabaseConfig   `toml:"database"`
	Docker     DockerConfig     `toml:"docker"`
	Encryption EncryptionConfig `toml:"encryption"`
	Auth       AuthConfig       `toml:"auth"`
	LLM        LLMConfig        `toml:"llm"`
	SentryDSN  string           `toml:"sentry_dsn"`
	LogLevel   string           `toml:"log_level"`
}

type LLMConfig struct {
	APIKey string `toml:"api_key"`
	Model  string `toml:"model"`
	// Timeout bounds a single LLM request, as a Go duration ("5m") or
	// plain seconds ("300"). Empty means the client default.
	Timeout string `toml:"timeout"`
}

// TimeoutDuration parses Timeout. Returns 0 (client default) when unset or invalid.
func (c LLMConfig) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	if d, err := time.ParseDuration(c.Timeout); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(c.Timeout); err == nil {
		return time.Duration(secs) * time.Second
	}
	return 0
}

type ServerConfig struct {
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	BaseURL string `toml:"base_url"`
}

type DatabaseConfig struct {
	Path string `toml:"path"`
}

type DockerConfig struct {
	Socket  string `toml:"socket"`
	Network string `toml:"network"`
}

type EncryptionConfig struct {
	Key string `toml:"key"`
}

type AuthConfig struct {
	SessionSecret string `toml:"session_secret"`
	AdminPassword string `toml:"admin_password"`
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// PublicBaseURL returns the externally-reachable base URL for this server.
// Used to construct OAuth callback URLs.
func (c *Config) PublicBaseURL() string {
	if c.Server.BaseURL != "" {
		return c.Server.BaseURL
	}
	return fmt.Sprintf("http://localhost:%d", c.Server.Port)
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Path: "arc-relay.db",
		},
		Docker: DockerConfig{
			Socket:  "unix:///var/run/docker.sock",
			Network: "arc-relay",
		},
	}

	if path != "" {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, fmt.Errorf("loading config %s: %w", path, err)
		}
	}

	// Environment variable overrides
	if v := os.Getenv("ARC_RELAY_ENCRYPTION_KEY"); v != "" {
		cfg.Encryption.Key = v
	}
	if v := os.Getenv("ARC_RELAY_SESSION_SECRET"); v != "" {
		cfg.Auth.SessionSecret = v
	}
	if v := os.Getenv("ARC_RELAY_ADMIN_PASSWORD"); v != "" {
		cfg.Auth.AdminPassword = v
	}
	if v := os.Getenv("ARC_RELAY_DB_PATH"); v != "" {
		cfg.Database.Path = v
	}
	if v := os.Getenv("ARC_RELAY_BASE_URL"); v != "" {
		cfg.Server.BaseURL = v
	} else if v := os.Getenv("RENDER_EXTERNAL_URL"); v != "" {
		// Render exposes the full https URL at this env var.
		cfg.Server.BaseURL = v
	} else if v := os.Getenv("RAILWAY_PUBLIC_DOMAIN"); v != "" {
		// Railway exposes only the hostname; assume https.
		cfg.Server.BaseURL = "https://" + v
	}
	if v := os.Getenv("ARC_RELAY_LLM_API_KEY"); v != "" {
		cfg.LLM.APIKey = v
	}
	if v := os.Getenv("ARC_RELAY_LLM_MODEL"); v != "" {
		cfg.LLM.Model = v
	}
	if v := os.Getenv("ARC_RELAY_LLM_TIMEOUT"); v != "" {
		cfg.LLM.Timeout = v
	}
	if v := os.Getenv("ARC_RELAY_SENTRY_DSN"); v != "" {
		cfg.SentryDSN = v
	}
	if v := os.Getenv("ARC_RELAY_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("ARC_RELAY_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.Server.Port = port
		}
	} else if v := os.Getenv("PORT"); v != "" {
		// PaaS platforms (Render, Heroku, Railway, Fly) inject PORT.
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.Server.Port = port
		}
	}

	return cfg, nil
}

// SlogLevel parses the LogLevel string into a slog.Level.
// Defaults to Info if unset or unrecognized.
func (c *Config) SlogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
