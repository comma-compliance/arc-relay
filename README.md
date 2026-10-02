# Arc Relay

An open-source MCP (Model Context Protocol) control plane. Arc Relay sits between your AI tools and MCP servers, providing auth, policy controls, traffic interception, and archiving - not just proxying.

```
AI Clients                Arc Relay                   MCP Servers
 (Claude, Codex,   +-----------------------+      +----------------+
  Cursor, etc.)    |  Auth & API Keys      |      | Docker stdio   |
       |           |  Middleware Pipeline  |----->| Docker HTTP    |
       +---------->|    Sanitizer (PII)    |      | Remote (OAuth) |
       |  POST     |    Sizer (limits)     |<-----+----------------+
       |  /mcp/    |    Alerter (rules)    |
       |  {name}   |    Archive (webhook)  |
       |           |  Health Monitor       |
       +---------->|  Web UI + REST API    |
                   +-----------------------+
```

## Features

- **Unified proxy** - all MCP servers behind one endpoint (`/mcp/{server-name}`)
- **Middleware pipeline** - bidirectional request/response processing (sanitizer, sizer, alerter, archive)
- **Archive with encryption** - stream tool calls to any webhook, optionally encrypted with NaCl Box
- **Docker lifecycle** - auto-start, stop, health check, and recover containers
- **Multi-transport** - stdio (Docker), HTTP (Docker/external), remote (SSE/OAuth)
- **Auth** - session cookies (web UI) + Bearer API keys (proxy) + OAuth 2.1 (remote servers)
- **Access tiers** - per-endpoint risk-based access control with auto-classification
- **Web UI** - manage servers, users, API keys, middleware, and logs
- **CLI tool** (`arc-sync`) - sync MCP servers to Claude Code projects via `.mcp.json`
- **Health monitoring** - periodic pings with auto-recovery for failed servers

## Quick Start

### Docker Compose

```bash
git clone https://github.com/comma-compliance/arc-relay.git
cd arc-relay
cp .env.example .env
# Edit .env - change encryption key, session secret, and admin password

docker compose up -d
open http://localhost:8080
```

### From Source

Requires Go 1.24+, GCC, and SQLite dev headers.

```bash
make build
./arc-relay --config config.example.toml
```

### One-click Deploy (Render, Heroku, Railway)

The repo ships deploy manifests for common PaaS platforms:

| Platform | File | Notes |
|---|---|---|
| Render | [`render.yaml`](render.yaml) | Persistent 1GB disk for SQLite, secrets auto-generated. |
| Heroku | [`app.json`](app.json) + [`heroku.yml`](heroku.yml) | Container stack. Dyno filesystem is ephemeral - data does not persist across restarts. |
| Railway | [`railway.json`](railway.json) | Uses the repo Dockerfile. Railway config-as-code only covers build/deploy, so you must set env vars and attach a Volume at `/data` in the Railway UI before the first boot. |

All three platforms inject a `PORT` env var that Arc Relay binds to automatically. `ARC_RELAY_ENCRYPTION_KEY`, `ARC_RELAY_SESSION_SECRET`, and `ARC_RELAY_ADMIN_PASSWORD` are auto-generated on Render and Heroku. On Railway you must set all three yourself; otherwise the app starts with a random admin password that is never printed, and you will be locked out.

Arc Relay auto-detects its public base URL from `RENDER_EXTERNAL_URL` (Render) and `RAILWAY_PUBLIC_DOMAIN` (Railway). On Heroku, set `ARC_RELAY_BASE_URL` manually to the app's public URL after the first deploy so OAuth callbacks and `Secure` session cookies work correctly.

**Docker-in-Docker limitation.** These platforms do not expose the host Docker socket to services, so deploys can only proxy to **remote** MCP backends (SSE/OAuth servers, external HTTP URLs). The built-in Docker lifecycle (stdio servers, managed HTTP servers) requires a deploy target with Docker socket access - Unraid, a VM, or a self-hosted Docker host.

Log in with username `admin` and the value of `ARC_RELAY_ADMIN_PASSWORD` (from `.env`, the config file, or the platform's env var UI on PaaS deploys).

## Configuration

Arc Relay reads a TOML config file with environment variable overrides. See [`config.example.toml`](config.example.toml).

| Variable | Purpose |
|---|---|
| `ARC_RELAY_ENCRYPTION_KEY` | Encrypts stored credentials (generate: `openssl rand -hex 32`) |
| `ARC_RELAY_SESSION_SECRET` | Signs web UI session cookies |
| `ARC_RELAY_ADMIN_PASSWORD` | Initial admin password (first run only) |
| `ARC_RELAY_DB_PATH` | SQLite database path (default: `arc-relay.db`) |
| `ARC_RELAY_BASE_URL` | Public URL for OAuth callbacks |
| `ARC_RELAY_LLM_API_KEY` | Anthropic API key for tool context optimization (optional) |
| `ARC_RELAY_LLM_MODEL` | LLM model for optimization (default: `claude-haiku-4-5-20251001`) |
| `ARC_RELAY_LLM_TIMEOUT` | Per-request timeout for optimization calls, as a duration (`10m`) or seconds (`600`) (default: `5m`) |
| `ARC_RELAY_SENTRY_DSN` | Sentry DSN for error reporting (optional; leave unset to disable Sentry) |

## User Onboarding

Arc Relay supports invite-based onboarding. Admins create invite links from the Users page; recipients click the link, choose a username and password, and immediately receive an API key for CLI access.

**Web UI invites:**
1. Go to the Users page and click "Create Invite"
2. Set the role (admin, user) and access level
3. Share the invite link - it's a one-time use URL that expires

**CLI invites:**
```bash
# Recipient runs this with the invite token from their admin:
arc-sync init https://your-relay:8080 --token INVITE_TOKEN
# They'll be prompted to choose a username and password
```

## CLI Tools

### arc-sync

`arc-sync` manages the connection between Arc Relay and your AI coding tools. It syncs MCP server definitions into `.mcp.json` files for Claude Code, Cursor, and VS Code projects.

**Install:**
```bash
# Download from your relay instance:
curl -fsSL https://your-relay:8080/install.sh | bash

# Or build from source:
CGO_ENABLED=0 go build ./cmd/arc-sync
```

**Commands:**
```bash
arc-sync init <url>       # Configure relay URL and authenticate (device code flow)
arc-sync                  # Interactive sync - add relay servers to current project
arc-sync list             # Show all servers and which are configured locally
arc-sync add <name>       # Add a specific server to the current project
arc-sync remove <name>    # Remove a server from the current project
arc-sync status           # Show configuration and project details
arc-sync server add       # Add a new MCP server to the relay (admin)
arc-sync server remove    # Remove a server from the relay (admin)
arc-sync server start     # Start a stopped server
arc-sync server stop      # Stop a running server
arc-sync setup-claude     # Install Claude Code skill and instructions
arc-sync setup-project    # Add MCP instructions to project .claude/CLAUDE.md
```

**Authentication:** `arc-sync init` uses the device code flow by default. It opens a browser where you log in and approve the CLI. For CI environments, set `ARC_SYNC_URL` and `ARC_SYNC_API_KEY` environment variables.

## Device Code Flow (CLI Authentication)

The device code flow lets CLI tools authenticate without handling passwords directly:

1. CLI calls `POST /api/auth/device` and receives a `device_code` and `user_code`
2. User opens the `verification_url` in a browser and logs in
3. User sees the code and clicks "Approve" (or "Deny")
4. CLI polls `POST /api/auth/device/token` with the `device_code`
5. On approval, the CLI receives an API key scoped to that user

This flow is used by `arc-sync init` and can be integrated into any CLI tool.

## Adding Servers to Claude Code

Install the CLI and sync your project:

```bash
arc-sync init https://your-relay:8080
arc-sync add my-server
```

Or add manually:

```bash
claude mcp add --transport http my-server \
  https://your-relay:8080/mcp/my-server \
  --header "Authorization: Bearer YOUR_API_KEY"
```

## Middleware Pipeline

Arc Relay's middleware processes MCP traffic bidirectionally:

| Middleware | Purpose | Actions |
|---|---|---|
| **Sanitizer** | Redact PII and secrets from responses | redact, block |
| **Sizer** | Enforce response size limits | truncate, warn, block |
| **Alerter** | Pattern and size-based alerting | log, webhook |
| **Archive** | Stream requests/responses to a webhook | POST with optional NaCl encryption |

Configure middleware per-server via the web UI or API. The archive middleware supports NaCl Box encryption (X25519 + XSalsa20-Poly1305) for defense-in-depth on top of TLS.

### Middleware Configuration Examples

Middleware is configured per-server as JSON. Below are examples for each type.

**Sanitizer** - redact or block sensitive patterns in responses:
```json
{
  "patterns": [
    {"name": "api_key", "regex": "(?i)(api[_-]?key|secret[_-]?key)\\s*[=:]\\s*\\S+", "action": "redact"},
    {"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "action": "redact"},
    {"name": "credit_card", "regex": "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b", "action": "block"}
  ]
}
```

**Sizer** - enforce response size limits:
```json
{
  "max_response_bytes": 500000,
  "action": "truncate"
}
```
Actions: `truncate` (trim to limit), `warn` (log but pass through), `block` (reject).

**Alerter** - pattern or size-based alerts:
```json
{
  "rules": [
    {"name": "prod_access", "match": "(?i)(production|prod[_-]db)", "direction": "request", "action": "log"},
    {"name": "large_response", "match_size": 100000, "direction": "response", "action": "webhook", "webhook_url": "https://hooks.example.com/alerts"}
  ]
}
```

**Archive** - stream tool calls to a webhook for compliance:
```json
{
  "url": "https://compliance.example.com/webhooks/incoming/arc_webhooks",
  "auth_type": "bearer",
  "auth_value": "your-webhook-token",
  "include": "both",
  "nacl_recipient_key": "base64-encoded-curve25519-public-key"
}
```
`include`: `request`, `response`, or `both`. `nacl_recipient_key` is optional - when set, payloads are encrypted with NaCl Box before delivery.

### Archive Payload Format

The archive middleware sends JSON payloads to the configured webhook URL via HTTP POST. Each payload is an envelope containing the MCP request and/or response:

```json
{
  "version": "v1",
  "source": "arc_relay",
  "phase": "exchange",
  "timestamp": "2026-04-07T12:00:00Z",
  "meta": {
    "server_id": "abc123",
    "server_name": "my-server",
    "user_id": "user-456",
    "client_ip": "10.0.0.1",
    "method": "tools/call",
    "tool_name": "search",
    "request_id": "1"
  },
  "request": {"jsonrpc": "2.0", "method": "tools/call", "params": {}},
  "response": {"jsonrpc": "2.0", "result": {}}
}
```

The `phase` field is `request`, `response`, or `exchange` (both). The `meta` block identifies who made the call, which server handled it, and the MCP method.

### NaCl Encryption for Archive Payloads

When `nacl_recipient_key` is configured, the archive payload is encrypted before delivery using NaCl Box (X25519 + XSalsa20-Poly1305) with an ephemeral sender keypair. The webhook receives a JSON envelope instead of the plaintext payload:

```json
{
  "version": "nacl-box-v1",
  "kid": "base64-8-byte-recipient-key-fingerprint",
  "nonce": "base64-24-byte-nonce",
  "ciphertext": "base64-sealed-payload",
  "sourcePublicKey": "base64-32-byte-ephemeral-sender-pubkey"
}
```

Receivers dispatch on the `version` field. The `kid` is a stable
fingerprint of the recipient pubkey (first 8 bytes of `blake2b-256`
of the 32-byte public key, base64-encoded) used to select the right
private key during rotation.

The recipient decrypts using:
1. Their Curve25519 private key (the one whose public half was configured as `nacl_recipient_key`)
2. The `sourcePublicKey` from the envelope (ephemeral, unique per payload)
3. The `nonce` from the envelope

This is defense-in-depth on top of TLS. The webhook endpoint cannot read payloads without the private key, even if the transport is compromised or a reverse proxy is sitting in front of the receiver.

**Public key only on the relay.** The Arc Relay binary stores only the
recipient's public key, and even that is optional. The matching
private key lives on the receiver and is never transmitted to the
relay. The relay also never stores a sender key: every envelope
generates a fresh ephemeral sender keypair, uses its private half once
to seal the box, and discards it.

**Provisioning.** In the common path an admin clicks "Set up the
Comma Compliance Archive" on the server detail page; the compliance
app bounces back through a stateful handoff that auto-provisions the
URL, bearer token, and recipient public key. Standalone deployments
can also configure `nacl_recipient_key` directly in the archive
middleware config.

**Interfaces for custom receivers.** See
[docs/archive-envelope.md](docs/archive-envelope.md) for the wire
format specification and [docs/archive-handoff.md](docs/archive-handoff.md)
for the handoff protocol.

### Writing Custom Middleware

Arc Relay's middleware pipeline is extensible. The four built-in middlewares (sanitizer, sizer, alerter, archive) are registered via the same `Registry.Register()` mechanism you use for your own. A custom middleware is any type that implements the `Middleware` interface:

```go
package mymiddleware

import (
    "context"
    "encoding/json"

    "github.com/comma-compliance/arc-relay/internal/mcp"
    "github.com/comma-compliance/arc-relay/internal/middleware"
    "github.com/comma-compliance/arc-relay/internal/store"
)

// TenantTagger adds a tenant ID header to every request and logs the tool name.
type TenantTagger struct {
    tenantID    string
    eventLogger middleware.EventLogger
}

func (t *TenantTagger) Name() string { return "tenant_tagger" }

func (t *TenantTagger) ProcessRequest(ctx context.Context, req *mcp.Request, meta *middleware.RequestMeta) (*mcp.Request, error) {
    // Modify the request, block it, or annotate it
    t.eventLogger(&store.MiddlewareEvent{
        Middleware: t.Name(),
        Action:     "tag",
        Detail:     "tenant=" + t.tenantID + " tool=" + meta.ToolName,
    })
    return req, nil
}

func (t *TenantTagger) ProcessResponse(ctx context.Context, req *mcp.Request, resp *mcp.Response, meta *middleware.RequestMeta) (*mcp.Response, error) {
    // Inspect or transform the response
    return resp, nil
}

// Factory parses the per-server JSON config and builds the middleware instance.
func Factory(config json.RawMessage, logger middleware.EventLogger) (middleware.Middleware, error) {
    var cfg struct {
        TenantID string `json:"tenant_id"`
    }
    if err := json.Unmarshal(config, &cfg); err != nil {
        return nil, err
    }
    return &TenantTagger{tenantID: cfg.TenantID, eventLogger: logger}, nil
}
```

Register your factory before the server starts handling traffic. The cleanest place is in `cmd/arc-relay/main.go` right after `middleware.NewRegistry(...)`:

```go
mwRegistry := middleware.NewRegistry(middlewareStore, archiveDispatcher)

// Register custom middleware
mwRegistry.Register("tenant_tagger", mymiddleware.Factory)
```

Once registered, enable your middleware on any server by creating a `middleware_configs` row with `middleware = "tenant_tagger"` and your JSON config. The web UI and API work identically to built-in middleware.

**How the pipeline runs:** `ProcessRequest` runs in registration order before the request reaches the backend; `ProcessResponse` runs in reverse order before the response reaches the client. Returning a non-nil error stops the pipeline and fails the request.

Examples of what custom middleware is good for:
- Per-tenant request tagging and routing
- Custom PII patterns beyond the built-in sanitizer
- Enrichment (looking up user context, adding headers)
- Cost tracking (token counting, billing hooks)
- Business-specific compliance rules

See `internal/middleware/sanitizer.go` for a production example of a middleware that reads a JSON config and transforms responses.

## Tool Context Optimizer

MCP servers often ship verbose tool definitions that consume excessive LLM context tokens. The Tool Context Optimizer analyzes and compresses these definitions while preserving semantic meaning.

**Without an LLM key:** Each server detail page shows a tool audit card with per-tool size breakdown and estimated token counts. No configuration needed.

**With an LLM key:** Set `ARC_RELAY_LLM_API_KEY` to an [Anthropic API key](https://console.anthropic.com/) to enable LLM-powered optimization. Click "Run Optimization" on any server's detail page to compress tool descriptions. Review the savings, then toggle "Serve optimized tools" to start serving the compressed versions to clients.

**Managing all servers:** The **Optimizer** page (`/optimize`, admin only) lists every server with its token counts, savings, status, model, and serving toggle. Select servers (or "Select needing a run" for ones whose tools changed, whose last run failed, or that were optimized with a different model) and optimize them in one go. Bulk runs process two servers at a time; each server's tool batches run up to four at a time. A re-run keeps serving the previous optimized tools until the new result is ready.

## Connect to Comma Compliance Arc

Arc Relay works standalone as a self-hosted MCP control plane. Optionally connect to [Comma Compliance Arc](https://commacompliance.ai/arc-relay/) for managed compliance policies, audit trails, and enterprise reporting.

Configure the archive middleware to point at your Comma Compliance webhook endpoint. See the web UI's "Compliance Archive" section for setup.

## Documentation

- [AGENTS.md](AGENTS.md) - AI contributor guide (project structure, key abstractions)
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup, PR process
- [SECURITY.md](SECURITY.md) - Vulnerability reporting
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture, MCP server types, and proxy design
- [docs/archive-envelope.md](docs/archive-envelope.md) - Wire format for archive payload encryption
- [docs/archive-handoff.md](docs/archive-handoff.md) - Archive recipient public-key handoff protocol

## License

Arc Relay is licensed under the [MIT License](LICENSE).

Built by [Comma Compliance](https://commacompliance.ai).
