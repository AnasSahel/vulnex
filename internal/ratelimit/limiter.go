package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Default rate limits per host (requests per second).
var defaultLimits = map[string]rate.Limit{
	"services.nvd.nist.gov":          rate.Every(600 * time.Millisecond),  // ~1.6/sec with key
	"api.first.org":                  rate.Every(1 * time.Second),          // 1/sec conservative
	"api.github.com":                 rate.Every(720 * time.Millisecond),   // ~1.4/sec
	"api.osv.dev":                    rate.Every(500 * time.Millisecond),   // 2/sec conservative
	"raw.githubusercontent.com":      rate.Every(500 * time.Millisecond),   // 2/sec
	"gitlab.com":                     rate.Every(1 * time.Second),          // 1/sec conservative
}

// Limiter manages per-host token bucket rate limiters.
type Limiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	burst    int
}

// New creates a new Limiter with default per-host limits.
func New() *Limiter {
	l := &Limiter{
		limiters: make(map[string]*rate.Limiter),
		burst:    1,
	}
	for host, limit := range defaultLimits {
		l.limiters[host] = rate.NewLimiter(limit, l.burst)
	}
	return l
}

// SetLimit configures the rate limit for a specific host.
func (l *Limiter) SetLimit(host string, rps float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limiters[host] = rate.NewLimiter(rate.Limit(rps), l.burst)
}

// Wait blocks until the rate limiter for the given host allows an event.
// If no limiter is configured for the host, it returns immediately.
func (l *Limiter) Wait(ctx context.Context, host string) error {
	l.mu.RLock()
	limiter, ok := l.limiters[host]
	l.mu.RUnlock()

	if !ok {
		return nil
	}
	return limiter.Wait(ctx)
}

// Allow reports whether an event for the given host may happen now.
func (l *Limiter) Allow(host string) bool {
	l.mu.RLock()
	limiter, ok := l.limiters[host]
	l.mu.RUnlock()

	if !ok {
		return true
	}
	return limiter.Allow()
}
