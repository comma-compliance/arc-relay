package optimizer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/comma-compliance/arc-relay/internal/llm"
	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/comma-compliance/arc-relay/internal/testutil"
)

// llmServer echoes tools with shortened descriptions. If gate is non-nil
// each request waits on it; if fail is true every request returns a 500.
func llmServer(t *testing.T, gate chan struct{}, fail bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate != nil {
			<-gate
		}
		if fail {
			http.Error(w, `{"error":{"type":"api_error","message":"upstream down"}}`, http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		prompt := req.Messages[0].Content
		var tools []mcp.Tool
		_ = json.Unmarshal([]byte(prompt[strings.Index(prompt, "\n\n")+2:]), &tools)
		for i := range tools {
			tools[i].Description = "short"
		}
		out, _ := json.Marshal(tools)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]string{{"type": "text", "text": string(out)}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T, srvURL string) (*Runner, *store.OptimizeStore, string) {
	t.Helper()
	db := testutil.OpenTestFileDB(t)
	optStore := store.NewOptimizeStore(db)
	servers := store.NewServerStore(db, store.NewConfigEncryptor(""))
	srv := &store.Server{Name: "demo", ServerType: store.ServerTypeStdio, Config: json.RawMessage(`{}`)}
	if err := servers.Create(srv); err != nil {
		t.Fatalf("Create server: %v", err)
	}
	client := llm.NewClient("test-key", "test-model", 0).WithBaseURL(srvURL)
	return NewRunner(optStore, client, 1), optStore, srv.ID
}

var testTools = []mcp.Tool{
	{Name: "a", Description: "a fairly long description that will be shortened", InputSchema: json.RawMessage(`{"type":"object"}`)},
	{Name: "b", Description: "another fairly long description to shorten", InputSchema: json.RawMessage(`{"type":"object"}`)},
}

func TestRunner_StartCompletes(t *testing.T) {
	llmSrv := llmServer(t, nil, false)
	r, st, id := setup(t, llmSrv.URL)

	if err := r.Start(id, "demo", testTools); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Wait()

	opt, err := st.Get(id)
	if err != nil || opt == nil {
		t.Fatalf("Get: %v", err)
	}
	if opt.Status != "ready" {
		t.Fatalf("status %q, want ready (err=%q)", opt.Status, opt.ErrorMsg)
	}
	if opt.Model != "test-model" || opt.ToolsHash != mcp.HashTools(testTools) {
		t.Errorf("unexpected record: model=%q hash=%q", opt.Model, opt.ToolsHash)
	}
	if r.InFlight(id) {
		t.Error("job still marked in flight after completion")
	}
}

func TestRunner_RejectsDuplicateAndEmpty(t *testing.T) {
	gate := make(chan struct{})
	llmSrv := llmServer(t, gate, false)
	r, st, id := setup(t, llmSrv.URL)

	if err := r.Start(id, "demo", nil); !errors.Is(err, ErrNoTools) {
		t.Errorf("empty tools: got %v, want ErrNoTools", err)
	}
	if err := r.Start(id, "demo", testTools); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Start(id, "demo", testTools); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second start: got %v, want ErrAlreadyRunning", err)
	}
	if opt, _ := st.Get(id); opt == nil || (opt.Status != "pending" && opt.Status != "running") {
		t.Errorf("expected pending/running while in flight, got %+v", opt)
	}
	close(gate)
	r.Wait()
}

func TestRunner_NoLLM(t *testing.T) {
	db := testutil.OpenTestDB(t)
	r := NewRunner(store.NewOptimizeStore(db), llm.NewClient("", "", 0), 0)
	if err := r.Start("x", "x", testTools); !errors.Is(err, ErrNoLLM) {
		t.Errorf("got %v, want ErrNoLLM", err)
	}
}

func TestRunner_FailedRerunKeepsPreviousResult(t *testing.T) {
	llmSrv := llmServer(t, nil, true)
	r, st, id := setup(t, llmSrv.URL)

	previous := json.RawMessage(`[{"name":"a","description":"prev"}]`)
	if err := st.Upsert(&store.ToolOptimization{
		ServerID: id, ToolsHash: "oldhash", OptimizedChars: 10,
		OptimizedTools: previous, Model: "old-model", Status: "ready",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := r.Start(id, "demo", testTools); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Wait()

	opt, err := st.Get(id)
	if err != nil || opt == nil {
		t.Fatalf("Get: %v", err)
	}
	if opt.Status != "error" || !strings.Contains(opt.ErrorMsg, "upstream down") {
		t.Errorf("status=%q err=%q, want error with cause", opt.Status, opt.ErrorMsg)
	}
	if string(opt.OptimizedTools) != string(previous) || opt.ToolsHash != "oldhash" {
		t.Errorf("previous result was overwritten: hash=%q tools=%s", opt.ToolsHash, opt.OptimizedTools)
	}
}

func TestRunner_CapsConcurrentServers(t *testing.T) {
	gate := make(chan struct{})
	var mu sync.Mutex
	active, maxActive := 0, 0
	inner := llmServer(t, nil, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		<-gate
		body, _ := io.ReadAll(r.Body)
		resp, err := http.Post(inner.URL, "application/json", strings.NewReader(string(body)))
		mu.Lock()
		active--
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)

	db := testutil.OpenTestFileDB(t)
	optStore := store.NewOptimizeStore(db)
	servers := store.NewServerStore(db, store.NewConfigEncryptor(""))
	r := NewRunner(optStore, llm.NewClient("k", "m", 0).WithBaseURL(srv.URL), 2)

	var ids []string
	for i := 0; i < 4; i++ {
		s := &store.Server{Name: "srv" + string(rune('a'+i)), ServerType: store.ServerTypeStdio, Config: json.RawMessage(`{}`)}
		if err := servers.Create(s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		ids = append(ids, s.ID)
		if err := r.Start(s.ID, s.Name, testTools); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}

	// Wait until two jobs are blocked in the LLM call, then confirm the others are queued.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := active
		mu.Unlock()
		if n == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	pending := 0
	for _, id := range ids {
		if opt, _ := optStore.Get(id); opt != nil && opt.Status == "pending" {
			pending++
		}
	}
	if pending != 2 {
		t.Errorf("queued jobs = %d, want 2", pending)
	}
	close(gate)
	r.Wait()

	if maxActive > 2 {
		t.Errorf("max concurrent servers = %d, want <= 2", maxActive)
	}
	for _, id := range ids {
		if opt, _ := optStore.Get(id); opt == nil || opt.Status != "ready" {
			t.Errorf("server %s not ready: %+v", id, opt)
		}
	}
}

func TestRunner_ConcurrentStartSameServer(t *testing.T) {
	gate := make(chan struct{})
	llmSrv := llmServer(t, gate, false)
	r, _, id := setup(t, llmSrv.URL)

	var wg sync.WaitGroup
	var ok int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.Start(id, "demo", testTools) == nil {
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	wg.Wait()
	close(gate)
	r.Wait()
	if ok != 1 {
		t.Errorf("%d concurrent starts succeeded, want 1", ok)
	}
}
