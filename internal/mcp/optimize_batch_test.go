package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/comma-compliance/arc-relay/internal/llm"
)

// fakeLLM returns an Anthropic-shaped server that echoes each batch with
// every description shortened to "short". failOn makes batches containing
// that tool name return a 500.
func fakeLLM(t *testing.T, failOn string, active, maxActive *int64) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if active != nil {
			n := atomic.AddInt64(active, 1)
			mu.Lock()
			if n > *maxActive {
				*maxActive = n
			}
			mu.Unlock()
			defer atomic.AddInt64(active, -1)
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &req); err != nil || len(req.Messages) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		prompt := req.Messages[0].Content
		var tools []Tool
		if err := json.Unmarshal([]byte(prompt[strings.Index(prompt, "\n\n")+2:]), &tools); err != nil {
			http.Error(w, "bad tools", http.StatusBadRequest)
			return
		}
		for i := range tools {
			if failOn != "" && tools[i].Name == failOn {
				http.Error(w, `{"error":{"type":"api_error","message":"boom"}}`, http.StatusInternalServerError)
				return
			}
			tools[i].Description = "short"
		}
		out, _ := json.Marshal(tools)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]string{{"type": "text", "text": string(out)}},
		})
	}))
}

// bigTools builds n tools large enough that each pair fills one batch.
func bigTools(n int) []Tool {
	tools := make([]Tool, n)
	for i := range tools {
		tools[i] = Tool{
			Name:        fmt.Sprintf("tool_%02d", i),
			Description: strings.Repeat("x", 12000),
			InputSchema: json.RawMessage(`{"type":"object"}`),
		}
	}
	return tools
}

func TestOptimizeTools_ConcurrentBatchesKeepOrder(t *testing.T) {
	var active, maxActive int64
	srv := fakeLLM(t, "", &active, &maxActive)
	defer srv.Close()
	client := llm.NewClient("test-key", "test-model", 0).WithBaseURL(srv.URL)

	tools := bigTools(16)
	got, err := OptimizeTools(t.Context(), client, tools)
	if err != nil {
		t.Fatalf("OptimizeTools: %v", err)
	}
	if len(got) != len(tools) {
		t.Fatalf("got %d tools, want %d", len(got), len(tools))
	}
	for i := range tools {
		if got[i].Name != tools[i].Name {
			t.Errorf("position %d: got %q, want %q", i, got[i].Name, tools[i].Name)
		}
		if got[i].Description != "short" {
			t.Errorf("tool %s not optimized", got[i].Name)
		}
	}
	if maxActive > batchConcurrency {
		t.Errorf("max concurrent requests %d exceeds limit %d", maxActive, batchConcurrency)
	}
}

func TestOptimizeTools_BatchErrorFailsWholeRun(t *testing.T) {
	srv := fakeLLM(t, "tool_05", nil, nil)
	defer srv.Close()
	client := llm.NewClient("test-key", "test-model", 0).WithBaseURL(srv.URL)

	_, err := OptimizeTools(t.Context(), client, bigTools(8))
	if err == nil {
		t.Fatal("expected error when one batch fails")
	}
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "of 4") {
		t.Errorf("error should name the batch and cause, got: %v", err)
	}
}

func TestOptimizeTools_OutOfOrderCompletion(t *testing.T) {
	// Earlier batches finish last, and all batches are held until several
	// requests overlap, proving both concurrency and in-order reassembly.
	inner := fakeLLM(t, "", nil, nil)
	defer inner.Close()
	var started int64
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if atomic.AddInt64(&started, 1) >= batchConcurrency {
			once.Do(func() { close(release) })
		}
		<-release
		// Delay inversely to batch position: batch 0 contains tool_00.
		if strings.Contains(string(body), `tool_00`) {
			time.Sleep(50 * time.Millisecond)
		}
		resp, err := http.Post(inner.URL, "application/json", strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()
	client := llm.NewClient("test-key", "test-model", 0).WithBaseURL(srv.URL)

	tools := bigTools(8)
	got, err := OptimizeTools(t.Context(), client, tools)
	if err != nil {
		t.Fatalf("OptimizeTools: %v", err)
	}
	for i := range tools {
		if got[i].Name != tools[i].Name {
			t.Fatalf("position %d: got %q, want %q", i, got[i].Name, tools[i].Name)
		}
	}
}

func TestOptimizeTools_FailureCancelsQueuedBatches(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		// Whichever batch arrives first fails; goroutine start order is not fixed.
		if atomic.AddInt64(&requests, 1) == 1 {
			http.Error(w, `{"error":{"type":"api_error","message":"boom"}}`, http.StatusInternalServerError)
			return
		}
		// Other batches stay busy until the client cancels them.
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	client := llm.NewClient("test-key", "test-model", 0).WithBaseURL(srv.URL)

	start := time.Now()
	_, err := OptimizeTools(t.Context(), client, bigTools(16)) // 8 batches
	if err == nil || !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "of 8") {
		t.Fatalf("expected the failing batch's error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("in-flight batches were not cancelled (took %v)", elapsed)
	}
	if n := atomic.LoadInt64(&requests); n > batchConcurrency {
		t.Errorf("%d requests sent, want at most %d (queued batches should not start)", n, batchConcurrency)
	}
}
