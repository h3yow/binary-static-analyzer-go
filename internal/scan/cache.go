package scan

import "sync"

// cacheKey identifies a reusable verdict. The rule version is part of the
// key on purpose: upgrading rules never silently reuses a verdict produced
// under an older version, and downgrading cannot resurrect one either.
type cacheKey struct {
	contentHash string
	ruleVersion string
}

type cacheEntry struct {
	result Result
}

// cache is a concurrency-safe content-addressed verdict cache.
type cache struct {
	mu    sync.RWMutex
	store map[cacheKey]cacheEntry
}

func newCache() *cache {
	return &cache{store: make(map[cacheKey]cacheEntry)}
}

func (c *cache) get(k cacheKey) (Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.store[k]
	if !ok {
		return Result{}, false
	}
	// Return a defensive copy so callers can never mutate cached findings.
	r := e.result
	if e.result.Findings != nil {
		r.Findings = append([]Finding(nil), e.result.Findings...)
	}
	return r, true
}

func (c *cache) put(k cacheKey, r Result) {
	if r.Findings != nil {
		// Store an independent backing array.
		cp := append([]Finding(nil), r.Findings...)
		r.Findings = cp
	}
	c.mu.Lock()
	c.store[k] = cacheEntry{result: r}
	c.mu.Unlock()
}

// Len reports the number of cached entries (for tests/diagnostics).
func (c *cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// inFlight deduplicates simultaneous scans of identical content: the first
// goroutine computes and publishes; the rest wait and receive the same value.
type inFlight struct {
	mu    sync.Mutex
	doing map[cacheKey]*flightCall
}

type flightCall struct {
	done   chan struct{}
	result Result
}

func newInFlight() *inFlight {
	return &inFlight{doing: make(map[cacheKey]*flightCall)}
}

// start either creates a call (leader=true) or joins an existing one
// (leader=false, call non-nil to wait on).
func (f *inFlight) start(k cacheKey) (*flightCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.doing[k]; ok {
		return c, false
	}
	c := &flightCall{done: make(chan struct{})}
	f.doing[k] = c
	return c, true
}

func (f *inFlight) finish(k cacheKey, c *flightCall, r Result) {
	f.mu.Lock()
	c.result = r
	delete(f.doing, k)
	f.mu.Unlock()
	close(c.done)
}
