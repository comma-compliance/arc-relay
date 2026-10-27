// Package safego keeps a panic in a background goroutine from killing the
// whole process. Only the HTTP handler recovers panics on its own; a panic in
// a bare goroutine (enumeration, health recovery, cleanup loops) would
// otherwise crash arc-relay without ever reaching Sentry.
package safego

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/getsentry/sentry-go"
)

// Recover must be deferred directly at the top of a goroutine:
//
//	go func() {
//		defer safego.Recover("enumerate")
//		...
//	}()
//
// It logs the panic with its stack, reports it to Sentry, and lets the
// goroutine exit instead of crashing the process.
func Recover(name string) {
	rv := recover()
	if rv == nil {
		return
	}
	report(name, rv)
}

// Run calls fn and recovers any panic it raises. Use it for one iteration of a
// long-lived loop so a single bad tick does not stop the loop.
func Run(name string, fn func()) {
	defer Recover(name)
	fn()
}

func report(name string, rv any) {
	slog.Error("panic recovered in background goroutine",
		"goroutine", name, "panic", fmt.Sprint(rv), "stack", string(debug.Stack()))
	hub := sentry.CurrentHub().Clone()
	hub.Scope().SetTag("goroutine", name)
	hub.Recover(rv)
	hub.Flush(2 * time.Second)
}
