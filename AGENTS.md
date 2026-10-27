# Arc Relay - AI Contributor Guide

This file provides context for AI coding tools (Claude Code, Cursor, Copilot) working on Arc Relay.

## What is Arc Relay?

An open-source MCP (Model Context Protocol) control plane. Not just a proxy - it provides auth, user management, middleware-based policy controls, traffic interception, and archiving for AI tool calls. Built in Go with SQLite storage and a server-rendered web UI.

## Project Structure

```
cmd/
  arc-relay/          Server binary (CGO required - SQLite)
  arc-sync/           CLI tool (pure Go, no CGO)
internal/
  config/             TOML config parsing + env var overrides
  docker/             Docker container lifecycle management
  mcp/                MCP protocol types and endpoint classification
  middleware/          Bidirectional middleware pipeline
    archive.go         Archive middleware (observe-only, sends to webhook)
    archive_dispatcher.go  Durable delivery with retry + circuit breaker
    archive_encrypt.go     NaCl Box payload encryption
    sanitizer.go       Pattern-based PII redaction/blocking
    sizer.go           Response size enforcement
    alerter.go         Pattern + size alerting (log/webhook)
    middleware.go      Pipeline core, registry, factory pattern
  proxy/               MCP proxy backends
    proxy.go           Server manager, lifecycle, enumeration
    stdio_bridge.go    Docker stdin/stdout bridge
    http_proxy.go      HTTP forward proxy
    remote_proxy.go    Remote servers with OAuth
    sse.go             SSE response parsing
    health.go          Health monitoring + auto-recovery
  store/               SQLite persistence
    db.go              Connection, migrations, backups
    users.go           Users, passwords (bcrypt), API keys (SHA-256)
    sessions.go        Web sessions
    crypto.go          AES-256-GCM config encryption
    middleware.go      Middleware config + events
    archive_queue.go   Durable delivery queue
    access.go          Endpoint access tiers
    request_logs.go    Audit logging
  web/                 HTTP handlers + templates
    handlers.go        All route handlers
    templates/         Server-rendered HTML (13 templates)
    oauth_provider.go  OAuth 2.1 authorization server
    device_auth.go     Device code flow for CLI auth
  cli/                 CLI shared packages
    config/            arc-sync config (~/.config/arc-sync/)
    sync/              .mcp.json sync logic
    relay/             HTTP client for Arc Relay API
    project/           Project detection (Claude Code, Cursor)
    safety/            Git safety checks
  optimizer/           Background runner for LLM tool-optimization jobs
  oauth/               OAuth 2.1 client (PKCE, auto-discovery)
  auth/                Auth utilities
  catalog/             MCP server registry
migrations/            Embedded SQL migrations (001-012)
skills/arc-sync/       Claude Code skill definition
```

## Building and Testing

```bash
# Server (requires gcc, libsqlite3-dev)
CGO_ENABLED=1 go build ./cmd/arc-relay

# CLI (pure Go, cross-platform)
CGO_ENABLED=0 go build ./cmd/arc-sync

# Tests
go test ./...          # Full suite
go test -race ./...    # With race detector
go vet ./...           # Static analysis

# Quick dev cycle
make build-all         # Both binaries
make run               # Build + run with example config
```

## Key Abstractions

### Middleware Pipeline

The core value proposition. Middleware processes MCP traffic bidirectionally:

```go
type Middleware interface {
    Name() string
    ProcessRequest(ctx context.Context, req *mcp.Request, meta *RequestMeta) (*mcp.Request, error)
    ProcessResponse(ctx context.Context, req *mcp.Request, resp *mcp.Response, meta *RequestMeta) (*mcp.Response, error)
}
```

Request middleware runs in priority order. Response middleware runs in reverse. Middleware can modify, block, or observe traffic.

**To add a new middleware:**
1. Create `internal/middleware/your_middleware.go`
2. Implement the `Middleware` interface
3. Add a factory function: `NewYourMiddlewareFromConfig(config json.RawMessage, logger EventLogger, ...) (Middleware, error)`
4. Register the factory in `middleware.go` `NewRegistry()` function
5. Add tests in `your_middleware_test.go`

### Proxy Backends

Three transport types for MCP servers:

- **Stdio** - Docker containers with stdin/stdout bridge (StdioBridge)
- **HTTP** - Direct HTTP POST to MCP endpoint (HTTPProxy)
- **Remote** - External servers with optional OAuth (RemoteProxy)

### Store Layer

SQLite with WAL mode, foreign keys, embedded migrations. The `ConfigEncryptor` optionally encrypts sensitive fields at rest using AES-256-GCM.

### Auth

- **Web UI:** Session cookies (bcrypt passwords, session table in SQLite)
- **API/Proxy:** Bearer API keys (SHA-256 hashed, never stored plaintext)
- **OAuth 2.1:** PKCE flows for remote MCP servers, device code flow for CLI

## Configuration

TOML config file with environment variable overrides:

| Env Var | Config Key | Default |
|---------|-----------|---------|
| `ARC_RELAY_ENCRYPTION_KEY` | `encryption.key` | (required) |
| `ARC_RELAY_SESSION_SECRET` | `auth.session_secret` | (required) |
| `ARC_RELAY_ADMIN_PASSWORD` | `auth.admin_password` | (random) |
| `ARC_RELAY_DB_PATH` | `database.path` | `arc-relay.db` |
| `ARC_RELAY_BASE_URL` | `server.base_url` | `http://localhost:PORT` |
| `ARC_RELAY_PORT` | `server.port` | `8080` |
| `ARC_RELAY_LLM_TIMEOUT` | `llm.timeout` | `5m` |
| `ARC_RELAY_SENTRY_DSN` | `sentry_dsn` | (disabled) |

## Code Style

- Standard Go conventions (gofmt, go vet)
- Table-driven tests
- No external test frameworks - stdlib `testing` only
- Errors wrap with `fmt.Errorf("context: %w", err)`
- Middleware never blocks MCP traffic unless explicitly configured to (archive is observe-only)
