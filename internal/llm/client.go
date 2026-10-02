// Package llm provides a minimal Anthropic Messages API client for tool optimization.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultBaseURL = "https://api.anthropic.com/v1/messages"
	defaultModel   = "claude-haiku-4-5-20251001"
	apiVersion     = "2023-06-01"
	maxTokens      = 16384

	// DefaultTimeout bounds a single Messages API call. Thinking models
	// (Sonnet/Opus) can take several minutes on a large tool batch.
	DefaultTimeout = 5 * time.Minute
)

// Client is a minimal Anthropic Messages API client.
type Client struct {
	apiKey  string
	model   string
	baseURL string
	http    *http.Client
}

// NewClient creates a new Anthropic API client.
// If model is empty, defaults to claude-haiku-4-5. If timeout is zero,
// defaults to DefaultTimeout.
func NewClient(apiKey, model string, timeout time.Duration) *Client {
	if model == "" {
		model = defaultModel
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		apiKey:  apiKey,
		model:   model,
		baseURL: defaultBaseURL,
		http: &http.Client{
			Timeout: timeout,
		},
	}
}

// WithBaseURL overrides the Messages API endpoint (used by tests).
func (c *Client) WithBaseURL(url string) *Client {
	c.baseURL = url
	return c
}

// Timeout returns the per-request timeout.
func (c *Client) Timeout() time.Duration {
	return c.http.Timeout
}

// Model returns the configured model name.
func (c *Client) Model() string {
	return c.model
}

// Available returns true if the client has an API key configured.
func (c *Client) Available() bool {
	return c.apiKey != ""
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type messagesResponse struct {
	Content []contentBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Result holds the API response text and token usage.
type Result struct {
	Text         string
	InputTokens  int
	OutputTokens int
}

// Complete sends a message to the Anthropic API and returns the response.
func (c *Client) Complete(ctx context.Context, system, userPrompt string) (*Result, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("LLM API key not configured (set ARC_RELAY_LLM_API_KEY)")
	}

	reqBody := messagesRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    system,
		Messages: []Message{
			{Role: "user", Content: userPrompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to extract a clean error message from the API response
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Message != "" {
			return nil, fmt.Errorf("%s", apiErr.Error.Message)
		}
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result messagesResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("API error: %s: %s", result.Error.Type, result.Error.Message)
	}

	var text string
	for _, block := range result.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}

	return &Result{
		Text:         text,
		InputTokens:  result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens,
	}, nil
}
