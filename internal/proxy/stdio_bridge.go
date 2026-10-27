package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/comma-compliance/arc-relay/internal/mcp"
	"github.com/comma-compliance/arc-relay/internal/safego"
)

// ErrBridgeClosed is returned by Send when the bridge was closed or the
// container's stdout stream ended before a response arrived.
var ErrBridgeClosed = errors.New("stdio bridge closed")

// StdioBridge translates between HTTP requests and a stdio MCP server process.
// It serializes requests (one at a time) and matches responses by JSON-RPC ID.
type StdioBridge struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser

	// nextID numbers requests on the wire. Clients pick their own JSON-RPC
	// ids (most start at 1), so two clients sharing this bridge would
	// otherwise collide in pending and receive each other's responses.
	nextID atomic.Uint64

	mu      sync.Mutex
	pending map[string]chan *mcp.Response // keyed by wire id
	scanner *bufio.Scanner
	closed  bool  // guarded by mu
	readErr error // guarded by mu; why the stdout stream ended, if known

	// done is closed once no further responses can arrive, either because
	// Close was called or because readLoop hit EOF/an error on stdout.
	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
}

// NewStdioBridge creates a bridge from an attached container's stdin/stdout.
func NewStdioBridge(stdin io.WriteCloser, stdout io.ReadCloser) *StdioBridge {
	b := &StdioBridge{
		stdin:   stdin,
		stdout:  stdout,
		pending: make(map[string]chan *mcp.Response),
		scanner: bufio.NewScanner(stdout),
		done:    make(chan struct{}),
	}
	// Increase scanner buffer for large responses
	b.scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	go b.readLoop()
	return b
}

// readLoop continuously reads newline-delimited JSON-RPC responses from stdout.
func (b *StdioBridge) readLoop() {
	defer safego.Recover("stdio bridge read loop")
	// Whatever ends the loop, fail every waiting Send instead of leaving
	// it to hang until its context expires. Close also closes stdin, which
	// unblocks a Send stuck writing to a container that stopped reading.
	defer func() { _ = b.Close() }()
	for b.scanner.Scan() {
		line := b.scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var resp mcp.Response
		if err := json.Unmarshal(line, &resp); err != nil {
			slog.Warn("stdio bridge: failed to parse response", "err", err)
			continue
		}
		// Requests and notifications from the server carry a method. They
		// are not answers to our calls, and a server request's id must not
		// be matched against a pending call that happens to share it.
		var kind struct {
			Method json.RawMessage `json:"method"` // nil only when absent
		}
		_ = json.Unmarshal(line, &kind)
		if kind.Method != nil {
			slog.Debug("stdio bridge: ignoring server-initiated message", "method", string(kind.Method))
			continue
		}

		// Match response to pending request by ID
		if resp.ID != nil {
			idKey := string(resp.ID)
			// Deliver under the lock (ch is buffered, so this never blocks).
			// Send relies on this: once it holds the lock, a response is
			// either already in ch or will never arrive.
			b.mu.Lock()
			ch, ok := b.pending[idKey]
			if ok {
				delete(b.pending, idKey)
				ch <- &resp
			}
			b.mu.Unlock()

			if !ok {
				slog.Warn("stdio bridge: no pending request for response", "id", idKey)
			}
		}
	}
	err := b.scanner.Err()
	if err != nil {
		slog.Warn("stdio bridge: read error", "err", err)
	} else {
		err = io.EOF
	}
	b.markDone(err)
}

// markDone records why the bridge stopped and wakes every pending Send.
// The first call wins; later calls are no-ops.
func (b *StdioBridge) markDone(readErr error) {
	b.doneOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		if b.readErr == nil {
			b.readErr = readErr
		}
		b.mu.Unlock()
		close(b.done)
	})
}

// closedErr builds the error returned to callers once the bridge is done.
func (b *StdioBridge) closedErr() error {
	b.mu.Lock()
	readErr := b.readErr
	b.mu.Unlock()
	if readErr != nil {
		return fmt.Errorf("%w: stdout stream ended: %v", ErrBridgeClosed, readErr)
	}
	return ErrBridgeClosed
}

// Send sends an MCP request over stdio and waits for the response.
func (b *StdioBridge) Send(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	// Send under a bridge-unique id and restore the caller's id on the reply.
	clientID := req.ID
	wireReq := *req
	wireReq.ID = json.RawMessage(strconv.FormatUint(b.nextID.Add(1), 10))
	idKey := string(wireReq.ID)
	ch := make(chan *mcp.Response, 1)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, b.closedErr()
	}
	b.pending[idKey] = ch
	b.mu.Unlock()

	// Serialize to JSON + newline
	data, err := json.Marshal(&wireReq)
	if err != nil {
		b.mu.Lock()
		delete(b.pending, idKey)
		b.mu.Unlock()
		return nil, fmt.Errorf("marshaling request: %w", err)
	}
	data = append(data, '\n')

	// Write to stdin (serialized — one request at a time for stdio)
	if _, err := b.stdin.Write(data); err != nil {
		b.mu.Lock()
		delete(b.pending, idKey)
		b.mu.Unlock()
		select {
		case <-b.done:
			return nil, b.closedErr()
		default:
		}
		return nil, fmt.Errorf("writing to stdin: %w", err)
	}

	// Wait for response or context cancellation
	// The response channel is never closed, so a receive always yields a
	// real response. Closing it used to hand callers a (nil, nil) result,
	// which crashed enumeration with a nil pointer dereference.
	select {
	case resp := <-ch:
		resp.ID = clientID
		return resp, nil
	case <-b.done:
		b.mu.Lock()
		delete(b.pending, idKey)
		b.mu.Unlock()
		// readLoop delivers under the lock, so a response that raced the
		// close is already in ch by now.
		select {
		case resp := <-ch:
			resp.ID = clientID
			return resp, nil
		default:
		}
		return nil, b.closedErr()
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, idKey)
		b.mu.Unlock()
		return nil, ctx.Err()
	}
}

// SendNotification sends a notification (no response expected).
func (b *StdioBridge) SendNotification(notification *mcp.Notification) error {
	data, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("marshaling notification: %w", err)
	}
	data = append(data, '\n')
	_, err = b.stdin.Write(data)
	return err
}

// Close shuts down the bridge.
func (b *StdioBridge) Close() error {
	b.closeOnce.Do(func() {
		// Wake pending Sends with ErrBridgeClosed before tearing down
		// the pipes, so they report the close rather than a read error.
		b.markDone(nil)
		_ = b.stdin.Close()
		_ = b.stdout.Close()
	})
	return nil
}
