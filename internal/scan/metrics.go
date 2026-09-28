package scan

// CacheLen reports the number of verdicts currently cached. Returns 0 when
// caching is disabled. Intended for tests and diagnostics.
func (s *Scanner) CacheLen() int {
	if s.cache == nil {
		return 0
	}
	return s.cache.Len()
}
