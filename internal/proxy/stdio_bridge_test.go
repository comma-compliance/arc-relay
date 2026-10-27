package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/comma-compliance/arc-relay/internal/mcp"
)

// fakeContainer wires a StdioBridge to in-memory pipes. Requests written by
// the bridge show up on requests; tests write responses to stdoutW.
type fakeContainer struct {
	bridge   *StdioBridge
	stdoutW  *io.PipeWriter
	requests chan *mcp.Request
}

func newFakeContainer(t *testing.T) *fakeContainer {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	fc := &fakeContainer{
		bridge:   NewStdioBridge(stdinW, stdoutR),
		stdoutW:  stdoutW,
		requests: make(chan *mcp.Request, 4),
	}
	go func() {
		sc := bufio.NewScanner(stdinR)
		for sc.Scan() {
			var req mcp.Request
			if err := json.Unmarshal(sc.Bytes(), &req); err == nil {
				fc.requests <- &req
			}
		}
	}()
	t.Cleanup(func() {
		_ = fc.bridge.Close()
		_ = stdoutW.Close()
	})
	return fc
}

func pingRequest(t *testing.T, id int) *mcp.Request {
	t.Helper()
	rawID, _ := json.Marshal(id)
	req, err := mcp.NewRequest(rawID, "ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

type sendResult struct {
	resp *mcp.Response
	err  error
}

// sendAsync starts Send and waits until the request reaches the container,
// so the test can act while the request is pending.
func (fc *fakeContainer) sendAsync(t *testing.T, ctx context.Context, req *mcp.Request) <-chan sendResult {
	t.Helper()
	out := make(chan sendResult, 1)
	go func() {
		resp, err := fc.bridge.Send(ctx, req)
		out <- sendResult{resp, err}
	}()
	select {
	case <-fc.requests:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached container stdin")
	}
	return out
}

func waitResult(t *testing.T, ch <-chan sendResult) sendResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return after the stream ended")
		return sendResult{}
	}
}

func TestStdioBridgeRoundTrip(t *testing.T) {
	fc := newFakeContainer(t)
	out := make(chan sendResult, 1)
	go func() {
		resp, err := fc.bridge.Send(context.Background(), pingRequest(t, 42))
		out <- sendResult{resp, err}
	}()
	req := <-fc.requests
	if _, err := fmt.Fprintf(fc.stdoutW, `{"jsonrpc":"2.0","id":%s,"result":{}}`+"\n", req.ID); err != nil {
		t.Fatal(err)
	}
	r := waitResult(t, out)
	if r.err != nil || r.resp == nil {
		t.Fatalf("got resp=%v err=%v, want a response", r.resp, r.err)
	}
	if string(r.resp.ID) != "42" {
		t.Errorf("response id = %s, want the caller's id 42", r.resp.ID)
	}
}

// Two clients sharing one stdio server both use id 1 (most clients start
// there). Each must get its own response; before the fix one client got the
// other's result and the second hung until its deadline.
func TestStdioBridgeSameClientIDsDoNotCollide(t *testing.T) {
	fc := newFakeContainer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callAs := func(who string) *mcp.Request {
		id, _ := json.Marshal(1)
		req, err := mcp.NewRequest(id, "tools/call", map[string]string{"who": who})
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	type result struct {
		who  string
		resp *mcp.Response
		err  error
	}
	out := make(chan result, 2)
	for _, who := range []string{"alice", "bob"} {
		go func(who string) {
			resp, err := fc.bridge.Send(ctx, callAs(who))
			out <- result{who, resp, err}
		}(who)
	}

	// The server sees both requests, then answers each under the id it was
	// given, echoing who asked.
	reqs := []*mcp.Request{<-fc.requests, <-fc.requests}
	if string(reqs[0].ID) == string(reqs[1].ID) {
		t.Fatalf("both requests reached the server with id %s", reqs[0].ID)
	}
	for _, req := range reqs {
		var p map[string]string
		_ = json.Unmarshal(req.Params, &p)
		fmt.Fprintf(fc.stdoutW, `{"jsonrpc":"2.0","id":%s,"result":{"who":%q}}`+"\n", req.ID, p["who"])
	}

	for i := 0; i < 2; i++ {
		r := <-out
		if r.err != nil {
			t.Fatalf("%s: %v", r.who, r.err)
		}
		var got map[string]string
		_ = json.Unmarshal(r.resp.Result, &got)
		if got["who"] != r.who {
			t.Errorf("%s received %s's response", r.who, got["who"])
		}
		if string(r.resp.ID) != "1" {
			t.Errorf("%s: response id = %s, want the caller's id 1", r.who, r.resp.ID)
		}
	}
}

// Regression for the 2026-10-27 crash: the container died while initialize
// was pending, and Send returned (nil, nil).
func TestStdioBridgeSendNeverReturnsNilNil(t *testing.T) {
	tests := []struct {
		name    string
		end     func(fc *fakeContainer)
		wantMsg string
	}{
		{
			name: "bridge closed",
			end:  func(fc *fakeContainer) { _ = fc.bridge.Close() },
		},
		{
			name:    "stdout EOF",
			end:     func(fc *fakeContainer) { _ = fc.stdoutW.Close() },
			wantMsg: "EOF",
		},
		{
			name: "stdout read error",
			end: func(fc *fakeContainer) {
				fc.stdoutW.CloseWithError(errors.New("use of closed network connection"))
			},
			wantMsg: "use of closed network connection",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := newFakeContainer(t)
			// Long deadline: Send must return because the stream ended, not
			// because the context expired.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			ch := fc.sendAsync(t, ctx, pingRequest(t, 1))
			tt.end(fc)
			r := waitResult(t, ch)

			if r.resp != nil {
				t.Fatalf("resp = %+v, want nil", r.resp)
			}
			if !errors.Is(r.err, ErrBridgeClosed) {
				t.Fatalf("err = %v, want ErrBridgeClosed", r.err)
			}
			if tt.wantMsg != "" && !strings.Contains(r.err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want it to mention %q", r.err, tt.wantMsg)
			}
		})
	}
}

func TestStdioBridgeSendAfterClose(t *testing.T) {
	fc := newFakeContainer(t)
	_ = fc.bridge.Close()
	resp, err := fc.bridge.Send(context.Background(), pingRequest(t, 1))
	if resp != nil || !errors.Is(err, ErrBridgeClosed) {
		t.Fatalf("got resp=%v err=%v, want nil and ErrBridgeClosed", resp, err)
	}
}

func TestStdioBridgeSendAfterStreamEnded(t *testing.T) {
	fc := newFakeContainer(t)
	_ = fc.stdoutW.Close()
	select {
	case <-fc.bridge.done:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not notice stdout EOF")
	}
	resp, err := fc.bridge.Send(context.Background(), pingRequest(t, 1))
	if resp != nil || !errors.Is(err, ErrBridgeClosed) {
		t.Fatalf("got resp=%v err=%v, want nil and ErrBridgeClosed", resp, err)
	}
}

// A container that stops reading stdin leaves Send blocked in Write. When its
// stdout then ends, the bridge must close stdin so Send returns.
func TestStdioBridgeStdoutEOFUnblocksWrite(t *testing.T) {
	_, pipeW := io.Pipe() // nobody reads stdin, so Write blocks
	stdin := &signalingWriter{PipeWriter: pipeW, started: make(chan struct{})}
	stdoutR, stdoutW := io.Pipe()
	bridge := NewStdioBridge(stdin, stdoutR)
	t.Cleanup(func() { _ = bridge.Close() })

	out := make(chan sendResult, 1)
	go func() {
		resp, err := bridge.Send(context.Background(), pingRequest(t, 1))
		out <- sendResult{resp, err}
	}()
	// End stdout only once Send is inside Write, so the test exercises the
	// blocked write rather than a Send that sees an already-closed bridge.
	select {
	case <-stdin.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Send never wrote to stdin")
	}
	_ = stdoutW.Close()

	r := waitResult(t, out)
	if r.resp != nil || !errors.Is(r.err, ErrBridgeClosed) {
		t.Fatalf("got resp=%v err=%v, want nil and ErrBridgeClosed", r.resp, r.err)
	}
}

// signalingWriter closes started when the first Write begins.
type signalingWriter struct {
	*io.PipeWriter
	started chan struct{}
	once    sync.Once
}

func (w *signalingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	return w.PipeWriter.Write(p)
}

// A server-initiated request (here roots/list) can reuse an id that a pending
// call is using on the wire. It must not be delivered as that call's response.
func TestStdioBridgeIgnoresServerRequests(t *testing.T) {
	fc := newFakeContainer(t)
	out := make(chan sendResult, 1)
	go func() {
		resp, err := fc.bridge.Send(context.Background(), pingRequest(t, 1))
		out <- sendResult{resp, err}
	}()
	req := <-fc.requests
	fmt.Fprintf(fc.stdoutW, `{"jsonrpc":"2.0","id":%s,"method":"roots/list"}`+"\n", req.ID)
	fmt.Fprintf(fc.stdoutW, `{"jsonrpc":"2.0","id":%s,"method":null}`+"\n", req.ID)
	fmt.Fprintf(fc.stdoutW, `{"jsonrpc":"2.0","id":%s,"result":{"real":true}}`+"\n", req.ID)

	r := waitResult(t, out)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.resp.Result) != `{"real":true}` {
		t.Fatalf("got result %s, want the real response", r.resp.Result)
	}
}
