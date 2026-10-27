package middleware

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/comma-compliance/arc-relay/internal/safego"
	"github.com/comma-compliance/arc-relay/internal/store"
)

// BackoffSchedule defines retry intervals by attempt number.
var BackoffSchedule = []time.Duration{
	0,                // attempt 0: immediate (already tried once at enqueue)
	15 * time.Second, // attempt 1
	1 * time.Minute,  // attempt 2
	5 * time.Minute,  // attempt 3
	15 * time.Minute, // attempt 4
	1 * time.Hour,    // attempt 5
	6 * time.Hour,    // attempt 6+ (cap)
}

var cbPauseDurations = []time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
}

const (
	cbClosed   = "closed"
	cbOpen     = "open"
	cbHalfOpen = "half-open"

	cbFailThreshold = 5
	drainBatchSize  = 50
)

// ArchiveDispatcher is a process-level singleton that manages durable
// delivery of archive payloads with retry and circuit breaking.
type ArchiveDispatcher struct {
	store       *store.ArchiveQueueStore
	eventLogger EventLogger
	httpClient  *http.Client

	// Circuit breaker (in-memory, resets on restart)
	mu               sync.Mutex
	consecutiveFails int
	cbState          string
	cbOpenedAt       time.Time
	cbPauseLevel     int

	// Control channels
	pollCh   chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	// Injectables for testing
	NowFunc   func() time.Time
	NewTicker func(d time.Duration) (<-chan time.Time, func())
}

// NewArchiveDispatcher creates a new dispatcher.
func NewArchiveDispatcher(queueStore *store.ArchiveQueueStore, eventLogger EventLogger) *ArchiveDispatcher {
	return &ArchiveDispatcher{
		store:       queueStore,
		eventLogger: eventLogger,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		cbState:     cbClosed,
		pollCh:      make(chan struct{}, 1),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		NowFunc:     time.Now,
		NewTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
}

// Start launches the background delivery loop.
func (d *ArchiveDispatcher) Start() {
	go d.loop()
}

// Stop signals the loop to exit and waits for it to finish.
func (d *ArchiveDispatcher) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
	<-d.doneCh
}

// Enqueue persists a payload to the queue and signals the delivery loop.
func (d *ArchiveDispatcher) Enqueue(payload []byte, cfg ArchiveConfig) error {
	item := &store.ArchiveQueueItem{
		Payload:      string(payload),
		URL:          cfg.URL,
		AuthType:     cfg.AuthType,
		AuthValue:    cfg.AuthValue,
		APIKeyHeader: cfg.APIKeyHeader,
	}
	if item.APIKeyHeader == "" {
		item.APIKeyHeader = "X-API-Key"
	}
	if err := d.store.Enqueue(item); err != nil {
		return fmt.Errorf("archive dispatcher: enqueue failed: %w", err)
	}
	// Non-blocking signal to wake the loop
	select {
	case d.pollCh <- struct{}{}:
	default:
	}
	return nil
}

// EnqueueWithServer is like Enqueue but includes server_id for per-server status tracking.
func (d *ArchiveDispatcher) EnqueueWithServer(payload []byte, cfg ArchiveConfig, serverID string) error {
	item := &store.ArchiveQueueItem{
		ServerID:     serverID,
		Payload:      string(payload),
		URL:          cfg.URL,
		AuthType:     cfg.AuthType,
		AuthValue:    cfg.AuthValue,
		APIKeyHeader: cfg.APIKeyHeader,
	}
	if item.APIKeyHeader == "" {
		item.APIKeyHeader = "X-API-Key"
	}
	if err := d.store.Enqueue(item); err != nil {
		return fmt.Errorf("archive dispatcher: enqueue failed: %w", err)
	}
	select {
	case d.pollCh <- struct{}{}:
	default:
	}
	return nil
}

func (d *ArchiveDispatcher) loop() {
	defer close(d.doneCh)
	defer safego.Recover("archive dispatcher")

	// Startup replay
	d.drainDue()

	tickCh, tickStop := d.NewTicker(30 * time.Second)
	defer tickStop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-tickCh:
			d.drainDue()
		case <-d.pollCh:
			d.drainDue()
		}
	}
}

func (d *ArchiveDispatcher) drainDue() {
	// Check circuit breaker
	d.mu.Lock()
	state := d.cbState
	if state == cbOpen {
		pauseIdx := d.cbPauseLevel
		if pauseIdx >= len(cbPauseDurations) {
			pauseIdx = len(cbPauseDurations) - 1
		}
		elapsed := d.NowFunc().Sub(d.cbOpenedAt)
		if elapsed >= cbPauseDurations[pauseIdx] {
			d.cbState = cbHalfOpen
			state = cbHalfOpen
			slog.Debug("archive dispatcher: circuit breaker half-open, probing")
		}
	}
	d.mu.Unlock()

	if state == cbOpen {
		return // Still paused
	}

	items, err := d.store.DequeueDue(drainBatchSize)
	if err != nil {
		slog.Error("archive dispatcher: dequeue error", "error", err)
		return
	}

	for _, item := range items {
		select {
		case <-d.stopCh:
			return
		default:
		}

		ok := d.sendOne(item)

		d.mu.Lock()
		if ok {
			d.consecutiveFails = 0
			if d.cbState == cbHalfOpen {
				d.cbState = cbClosed
				d.cbPauseLevel = 0
				slog.Debug("archive dispatcher: circuit breaker closed")
				if d.eventLogger != nil {
					d.eventLogger(&store.MiddlewareEvent{
						Middleware: "archive",
						EventType:  "circuit_closed",
						Summary:    "archive delivery recovered, circuit breaker closed",
					})
				}
			}
		} else {
			d.consecutiveFails++
			if d.cbState == cbHalfOpen {
				// Probe failed, reopen with escalated pause
				d.cbState = cbOpen
				d.cbOpenedAt = d.NowFunc()
				if d.cbPauseLevel < len(cbPauseDurations)-1 {
					d.cbPauseLevel++
				}
				slog.Debug("archive dispatcher: half-open probe failed, circuit reopened", "pause_level", d.cbPauseLevel)
				d.mu.Unlock()
				return
			}
			if d.consecutiveFails >= cbFailThreshold {
				d.cbState = cbOpen
				d.cbOpenedAt = d.NowFunc()
				slog.Debug("archive dispatcher: circuit breaker opened", "consecutive_failures", d.consecutiveFails)
				if d.eventLogger != nil {
					d.eventLogger(&store.MiddlewareEvent{
						Middleware: "archive",
						EventType:  "circuit_open",
						Summary:    fmt.Sprintf("archive delivery failing, circuit breaker opened after %d failures", d.consecutiveFails),
					})
				}
				d.mu.Unlock()
				return
			}
		}
		d.mu.Unlock()
	}
}

func (d *ArchiveDispatcher) sendOne(item *store.ArchiveQueueItem) bool {
	req, err := http.NewRequest("POST", item.URL, bytes.NewReader([]byte(item.Payload)))
	if err != nil {
		slog.Error("archive dispatcher: failed to create request", "error", err)
		if err2 := d.store.MarkHold(item.ID, "invalid request: "+err.Error()); err2 != nil {
			slog.Warn("archive dispatcher: mark hold failed", "item_id", item.ID, "error", err2)
		}
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	switch item.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+item.AuthValue)
	case "api_key":
		header := item.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, item.AuthValue)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Network/timeout errors are transient
		errMsg := fmt.Sprintf("network error: %v", err)
		nextAttempt := d.nextAttemptTime(item.Attempts)
		if err2 := d.store.Reschedule(item.ID, nextAttempt, errMsg); err2 != nil {
			slog.Warn("archive dispatcher: reschedule failed", "item_id", item.ID, "error", err2)
		}
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 300 {
		// Success
		if err := d.store.MarkDelivered(item.ID); err != nil {
			slog.Warn("archive dispatcher: mark delivered failed", "item_id", item.ID, "error", err)
		}
		return true
	}

	errMsg := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if isTransient(resp.StatusCode) {
		nextAttempt := d.nextAttemptTime(item.Attempts)
		if err := d.store.Reschedule(item.ID, nextAttempt, errMsg); err != nil {
			slog.Warn("archive dispatcher: reschedule failed", "item_id", item.ID, "error", err)
		}
		return false
	}

	// Permanent failure
	if err := d.store.MarkHold(item.ID, errMsg); err != nil {
		slog.Warn("archive dispatcher: mark hold failed", "item_id", item.ID, "error", err)
	}
	return false
}

func (d *ArchiveDispatcher) nextAttemptTime(currentAttempts int) time.Time {
	idx := currentAttempts + 1 // next attempt index
	if idx >= len(BackoffSchedule) {
		idx = len(BackoffSchedule) - 1
	}
	return d.NowFunc().Add(BackoffSchedule[idx])
}

func isTransient(statusCode int) bool {
	return statusCode >= 500 || statusCode == 408 || statusCode == 429
}

// SendTest performs a synchronous test delivery without using the queue.
// It shares request-building and error classification with production sends.
// When cfg.NaClRecipientKey is set the test payload is sealed with the same
// envelope path real traffic uses so a misconfigured key surfaces at handoff
// time instead of silently during the first real request. Returns the HTTP
// status code (0 on network error) and any error.
func (d *ArchiveDispatcher) SendTest(cfg ArchiveConfig) (int, error) {
	testPayload := []byte(`{"version":"v1","source":"arc_relay","phase":"test","meta":{"server_name":"connectivity_test"}}`)

	var recipientKey *[32]byte
	if cfg.NaClRecipientKey != "" {
		decoded, err := DecodeRecipientKey(cfg.NaClRecipientKey)
		if err != nil {
			return 0, fmt.Errorf("invalid nacl_recipient_key: %w", err)
		}
		recipientKey = &decoded
	}
	sealed, err := sealArchivePayload(testPayload, recipientKey)
	if err != nil {
		return 0, fmt.Errorf("seal test payload: %w", err)
	}
	testPayload = sealed

	req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(testPayload))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	switch cfg.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+cfg.AuthValue)
	case "api_key":
		header := cfg.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, cfg.AuthValue)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	// Successful test can help close the circuit breaker
	d.mu.Lock()
	if d.cbState == cbHalfOpen || d.cbState == cbOpen {
		d.cbState = cbClosed
		d.cbPauseLevel = 0
		d.consecutiveFails = 0
		slog.Debug("archive dispatcher: test success, circuit breaker closed")
	}
	d.mu.Unlock()

	return resp.StatusCode, nil
}

// Status returns a snapshot of the dispatcher and queue state.
type ArchiveDispatcherStatus struct {
	CircuitState string                    `json:"circuit_state"`
	Enabled      bool                      `json:"enabled"`
	QueueStatus  *store.ArchiveQueueStatus `json:"queue"`
}

func (d *ArchiveDispatcher) Status() *ArchiveDispatcherStatus {
	d.mu.Lock()
	circuitState := d.cbState
	d.mu.Unlock()

	qs, err := d.store.Status()
	if err != nil {
		slog.Error("archive dispatcher: status query error", "error", err)
		qs = &store.ArchiveQueueStatus{}
	}

	return &ArchiveDispatcherStatus{
		CircuitState: circuitState,
		Enabled:      true,
		QueueStatus:  qs,
	}
}

// SetHTTPClient replaces the HTTP client (for testing).
func (d *ArchiveDispatcher) SetHTTPClient(c *http.Client) {
	d.httpClient = c
}

// Wake signals the delivery loop to drain due items.
func (d *ArchiveDispatcher) Wake() {
	select {
	case d.pollCh <- struct{}{}:
	default:
	}
}

// NextAttemptTime returns when the next attempt should occur given current attempts.
// Exported for testing the backoff schedule.
func (d *ArchiveDispatcher) NextAttemptTime(currentAttempts int) time.Time {
	return d.nextAttemptTime(currentAttempts)
}

// RetryHeld resets held items and wakes the delivery loop. Also forces the
// circuit breaker back to closed so a paused dispatcher immediately resumes
// delivery instead of waiting for the circuit timer - the admin explicitly
// asked us to retry, so we trust them over the automated backoff.
func (d *ArchiveDispatcher) RetryHeld() (int64, error) {
	count, err := d.store.RetryHeld()
	if err != nil {
		return 0, err
	}
	d.ResetCircuit()
	return count, nil
}

// RewriteHeldDelivery updates the URL and auth fields on all held rows.
// Used by the retry-with-current-config flow to fix stale destinations
// before retrying.
func (d *ArchiveDispatcher) RewriteHeldDelivery(cfg ArchiveConfig) (int64, error) {
	return d.store.RewriteHeldDelivery(cfg.URL, cfg.AuthType, cfg.AuthValue, cfg.APIKeyHeader)
}

// ClearHeld deletes all held rows from the archive queue. Used when queued
// messages are unrecoverable and the admin wants a clean slate.
func (d *ArchiveDispatcher) ClearHeld() (int64, error) {
	return d.store.ClearHeld()
}

// ResetCircuit forces the circuit breaker back to closed and wakes the
// delivery loop. Called when the admin explicitly updates the archive
// config or manually retries the queue - either action represents a
// trust signal from the operator that they want delivery to resume.
func (d *ArchiveDispatcher) ResetCircuit() {
	d.mu.Lock()
	d.cbState = cbClosed
	d.cbPauseLevel = 0
	d.consecutiveFails = 0
	d.mu.Unlock()
	select {
	case d.pollCh <- struct{}{}:
	default:
	}
}
