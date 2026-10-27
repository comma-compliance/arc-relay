package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ServerEndpoints holds the cached enumeration results for an MCP server.
type ServerEndpoints struct {
	ServerInfo  ServerInfo `json:"server_info"`
	Tools       []Tool     `json:"tools"`
	Resources   []Resource `json:"resources"`
	Prompts     []Prompt   `json:"prompts"`
	Initialized bool       `json:"initialized"`
	Error       string     `json:"error,omitempty"`
}

// Sender is the interface for sending MCP requests (matches proxy.Backend).
type Sender interface {
	Send(ctx context.Context, req *Request) (*Response, error)
}

// ErrNilResponse is returned when a Sender reports success but hands back no
// response. That is a Sender bug; callers treat it as a failed request rather
// than dereferencing nil.
var ErrNilResponse = errors.New("sender returned no response and no error")

// send wraps sender.Send and turns a (nil, nil) result into ErrNilResponse.
func send(ctx context.Context, sender Sender, req *Request) (*Response, error) {
	resp, err := sender.Send(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("%s: %w", req.Method, ErrNilResponse)
	}
	return resp, nil
}

// EndpointCache stores enumerated endpoints for all servers.
type EndpointCache struct {
	mu    sync.RWMutex
	cache map[string]*ServerEndpoints // server ID -> endpoints
}

func NewEndpointCache() *EndpointCache {
	return &EndpointCache{
		cache: make(map[string]*ServerEndpoints),
	}
}

// Get returns cached endpoints for a server, or nil if not cached.
func (c *EndpointCache) Get(serverID string) *ServerEndpoints {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[serverID]
}

// Set stores endpoints for a server.
func (c *EndpointCache) Set(serverID string, endpoints *ServerEndpoints) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[serverID] = endpoints
}

// Remove clears cached endpoints for a server.
func (c *EndpointCache) Remove(serverID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, serverID)
}

// Enumerate performs the full MCP initialization and endpoint discovery sequence.
// It calls initialize, sends initialized notification, then lists tools/resources/prompts.
func Enumerate(ctx context.Context, sender Sender) (*ServerEndpoints, error) {
	endpoints := &ServerEndpoints{}

	// 1. Initialize
	initResult, err := doInitialize(ctx, sender)
	if err != nil {
		endpoints.Error = fmt.Sprintf("initialize failed: %v", err)
		return endpoints, err
	}
	endpoints.ServerInfo = initResult.ServerInfo
	endpoints.Initialized = true

	// 2. Send initialized notification
	sendInitializedNotification(sender)

	// 3. List tools (if supported)
	if _, ok := initResult.Capabilities["tools"]; ok {
		tools, err := doListTools(ctx, sender)
		if err != nil {
			endpoints.Error = fmt.Sprintf("tools/list failed: %v", err)
		} else {
			endpoints.Tools = tools
		}
	}

	// 4. List resources (if supported)
	if _, ok := initResult.Capabilities["resources"]; ok {
		resources, err := doListResources(ctx, sender)
		if err != nil {
			// Non-fatal: some servers advertise resources but don't implement list
			endpoints.Error = fmt.Sprintf("resources/list failed: %v", err)
		} else {
			endpoints.Resources = resources
		}
	}

	// 5. List prompts (if supported)
	if _, ok := initResult.Capabilities["prompts"]; ok {
		prompts, err := doListPrompts(ctx, sender)
		if err != nil {
			// Non-fatal
		} else {
			endpoints.Prompts = prompts
		}
	}

	return endpoints, nil
}

func doInitialize(ctx context.Context, sender Sender) (*InitializeResult, error) {
	id, _ := json.Marshal(1)
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    map[string]any{},
		ClientInfo:      ServerInfo{Name: "arc-relay", Version: "0.1.0"},
	}

	req, err := NewRequest(id, "initialize", params)
	if err != nil {
		return nil, err
	}

	resp, err := send(ctx, sender, req)
	if err != nil {
		return nil, fmt.Errorf("sending initialize: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("initialize error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing initialize result: %w", err)
	}
	return &result, nil
}

func sendInitializedNotification(sender Sender) {
	// Best-effort; some backends may not support notifications via HTTP
	// For HTTP backends this is typically a no-op since there's no persistent connection
}

func doListTools(ctx context.Context, sender Sender) ([]Tool, error) {
	id, _ := json.Marshal(2)
	req, err := NewRequest(id, "tools/list", nil)
	if err != nil {
		return nil, err
	}

	resp, err := send(ctx, sender, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing tools list: %w", err)
	}
	return result.Tools, nil
}

func doListResources(ctx context.Context, sender Sender) ([]Resource, error) {
	id, _ := json.Marshal(3)
	req, err := NewRequest(id, "resources/list", nil)
	if err != nil {
		return nil, err
	}

	resp, err := send(ctx, sender, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var result ResourcesListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing resources list: %w", err)
	}
	return result.Resources, nil
}

func doListPrompts(ctx context.Context, sender Sender) ([]Prompt, error) {
	id, _ := json.Marshal(4)
	req, err := NewRequest(id, "prompts/list", nil)
	if err != nil {
		return nil, err
	}

	resp, err := send(ctx, sender, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	var result PromptsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing prompts list: %w", err)
	}
	return result.Prompts, nil
}
