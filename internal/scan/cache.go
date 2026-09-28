// Package scan orchestrates concurrent multi-target scans, caching and
// resource/timeout limits.
package scan

import (
	"sync"

	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// Envelope is the content-derived, cacheable part of a scan outcome; it is
// independent of the target name so identical contents share one entry.
type Envelope struct {
	ContentSHA string          `json:"content_sha256"`
	Size       int64           `json:"size"`
	Status     Status          `json:"status"`
	Error      *ErrorInfo      `json:"error,omitempty"`
	Findings   []rules.Finding `json:"findings"`
}

// Cache stores scan envelopes keyed by <rule-set-hash>:<content-sha256>.
type Cache interface {
	Get(key string) (Envelope, bool)
	Set(key string, env Envelope)
	Len() int
}

// MemoryCache is a concurrency-safe in-process Cache.
type MemoryCache struct {
	mu    sync.Mutex
	store map[string]Envelope
	hits  int
	miss  int
}

// NewMemoryCache builds an empty in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{store: make(map[string]Envelope)}
}

// Get returns a cached envelope, if present.
func (c *MemoryCache) Get(key string) (Envelope, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	env, ok := c.store[key]
	if ok {
		c.hits++
	} else {
		c.miss++
	}
	return env, ok
}

// Set stores an envelope.
func (c *MemoryCache) Set(key string, env Envelope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = env
}

// Len returns the number of cached entries.
func (c *MemoryCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.store)
}

// Stats reports cache utilization for tests/diagnostics.
func (c *MemoryCache) Stats() (entries, hits, misses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.store), c.hits, c.miss
}
