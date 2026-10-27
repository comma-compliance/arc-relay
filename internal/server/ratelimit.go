package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/comma-compliance/arc-relay/internal/safego"
)

type rateBucket struct {
	tokens   float64
	lastFill time.Time
}

// RateLimiter implements per-user token bucket rate limiting.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	rate    float64 // tokens per second
	burst   int     // max bucket size
}

// NewRateLimiter creates a rate limiter with the given rate (req/sec) and burst size.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*rateBucket),
		rate:    rate,
		burst:   burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &rateBucket{tokens: float64(rl.burst), lastFill: now}
		rl.buckets[key] = b
	}

	// Refill tokens
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanup removes stale buckets every 5 minutes.
func (rl *RateLimiter) cleanup() {
	defer safego.Recover("rate limiter cleanup")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, b := range rl.buckets {
			if b.lastFill.Before(cutoff) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns an HTTP middleware that rate limits by authenticated user ID.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !rl.allow(user.ID) {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
