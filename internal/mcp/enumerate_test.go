package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// senderFunc adapts a function to the Sender interface.
type senderFunc func(ctx context.Context, req *Request) (*Response, error)

func (f senderFunc) Send(ctx context.Context, req *Request) (*Response, error) { return f(ctx, req) }

func okResponse(t *testing.T, req *Request, result any) *Response {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: raw}
}

// Regression for the 2026-10-27 crash: a sender returning (nil, nil) for
// initialize made doInitialize dereference nil and kill the process.
func TestEnumerateNilResponse(t *testing.T) {
	tests := []struct {
		name      string
		nilMethod string
		wantErr   bool
		wantInit  bool
	}{
		{name: "initialize", nilMethod: "initialize", wantErr: true},
		{name: "tools/list", nilMethod: "tools/list", wantInit: true},
		{name: "resources/list", nilMethod: "resources/list", wantInit: true},
		{name: "prompts/list", nilMethod: "prompts/list", wantInit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := senderFunc(func(_ context.Context, req *Request) (*Response, error) {
				if req.Method == tt.nilMethod {
					return nil, nil
				}
				switch req.Method {
				case "initialize":
					return okResponse(t, req, InitializeResult{
						ProtocolVersion: "2024-11-05",
						Capabilities: map[string]any{
							"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{},
						},
						ServerInfo: ServerInfo{Name: "fake", Version: "1"},
					}), nil
				case "tools/list":
					return okResponse(t, req, ToolsListResult{Tools: []Tool{{Name: "t"}}}), nil
				case "resources/list":
					return okResponse(t, req, ResourcesListResult{}), nil
				case "prompts/list":
					return okResponse(t, req, PromptsListResult{}), nil
				}
				t.Fatalf("unexpected method %s", req.Method)
				return nil, nil
			})

			endpoints, err := Enumerate(context.Background(), sender)
			if tt.wantErr {
				if !errors.Is(err, ErrNilResponse) {
					t.Fatalf("err = %v, want ErrNilResponse", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if endpoints == nil {
				t.Fatal("endpoints = nil")
			}
			if endpoints.Initialized != tt.wantInit {
				t.Errorf("Initialized = %v, want %v", endpoints.Initialized, tt.wantInit)
			}
		})
	}
}
