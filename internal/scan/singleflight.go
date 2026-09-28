package scan

import "sync"

// call represents an in-flight evaluation shared by duplicate targets.
type call struct {
	done chan struct{}
	env  Envelope
}

// singleflight coalesces concurrent evaluations of the same cache key so
// identical contents submitted in one batch are parsed exactly once.
type singleflight struct {
	mu sync.Mutex
	m  map[string]*call
}

func newSingleflight() *singleflight {
	return &singleflight{m: make(map[string]*call)}
}

// do runs fn at most once for a given key among concurrent callers; every
// caller receives the same Envelope.
func (sf *singleflight) do(key string, fn func() Envelope) Envelope {
	sf.mu.Lock()
	if c, ok := sf.m[key]; ok {
		sf.mu.Unlock()
		<-c.done
		return c.env
	}
	c := &call{done: make(chan struct{})}
	sf.m[key] = c
	sf.mu.Unlock()

	c.env = fn()
	close(c.done)

	sf.mu.Lock()
	delete(sf.m, key)
	sf.mu.Unlock()
	return c.env
}
