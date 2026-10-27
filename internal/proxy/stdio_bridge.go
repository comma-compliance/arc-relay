package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

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

	mu      sync.Mutex
	pending map[string]chan *mcp.Response
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
	// it to hang until its context expires.
	defer b.markDone(nil)
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

		// Match response to pending request by ID
		if resp.ID != nil {
			idKey := string(resp.ID)
			b.mu.Lock()
			ch, ok := b.pending[idKey]
			if ok {
				delete(b.pending, idKey)
			}
			b.mu.Unlock()

			if ok {
				ch <- &resp
			} else {
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
	idKey := string(req.ID)
	ch := make(chan *mcp.Response, 1)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, b.closedErr()
	}
	b.pending[idKey] = ch
	b.mu.Unlock()

	// Serialize to JSON + newline
	data, err := json.Marshal(req)
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
		return nil, fmt.Errorf("writing to stdin: %w", err)
	}

	// Wait for response or context cancellation
	// The response channel is never closed, so a receive always yields a
	// real response. Closing it used to hand callers a (nil, nil) result,
	// which crashed enumeration with a nil pointer dereference.
	select {
	case resp := <-ch:
		return resp, nil
	case <-b.done:
		b.mu.Lock()
		delete(b.pending, idKey)
		b.mu.Unlock()
		// A response may have landed just before the stream ended.
		select {
		case resp := <-ch:
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
