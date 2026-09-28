// Package scan runs concurrent multi-target scans with deterministic
// ordering, result caching and explicit resource/timeout semantics.
package scan

import (
	"errors"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// Sentinel errors describing explicit refusal/termination semantics.
var (
	// ErrTooLarge means a target exceeds the configured maximum input size.
	ErrTooLarge = errors.New("scan: target exceeds configured size limit")
	// ErrTimeout means the configured deadline elapsed before the scan finished.
	ErrTimeout = errors.New("scan: timed out")
	// ErrQueueRejected means too many targets were submitted while at capacity.
	ErrQueueRejected = errors.New("scan: concurrency queue full, target rejected")
)

// Config controls concurrency, resources and timeouts. Zero-value fields
// fall back to defaults documented on DefaultConfig.
type Config struct {
	// MaxConcurrency bounds simultaneous parse/evaluate jobs (default 4).
	MaxConcurrency int
	// MaxTargetSize rejects targets larger than this many bytes (default 256 MiB).
	MaxTargetSize int64
	// PerTargetTimeout bounds one target; 0 means no per-target deadline.
	PerTargetTimeout Duration
	// OverallTimeout bounds a whole Scan call; 0 means no overall deadline.
	OverallTimeout Duration
	// CacheEnabled reuses findings for identical (content, rule version) pairs.
	CacheEnabled bool
}

// Duration is a JSON-friendly alias kept simple on purpose.
type Duration int64 // nanoseconds

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		MaxConcurrency: 4,
		MaxTargetSize:  256 << 20,
		CacheEnabled:   true,
	}
}

// Target is one scan input. Name is a stable label (usually file path).
// Content provides the exact bytes; when nil, Read is used.
type Target struct {
	Name    string
	Content []byte
}

// Status is the final category for one target.
type Status string

const (
	StatusOK        Status = "ok"
	StatusParseFail Status = "parse_failed"
	StatusRejected  Status = "rejected" // size/queue limits
	StatusTimeout   Status = "timeout"
	StatusRuleError Status = "rule_error"
)

// Finding re-exports the rules finding for caller convenience.
type Finding = rules.Finding

// Result is the deterministic verdict for one target.
type Result struct {
	Target      string
	Status      Status
	Hash        string // sha256 of input content, when available
	Format      model.Format
	Findings    []Finding
	RuleVersion string
	// Error is the classified error, nil on success.
	Err error
}

// Report is the full output of a scan in input order.
type Report struct {
	RuleVersion string
	Results     []Result
}

// Scanner scans targets with a fixed engine and configuration. It is safe
// for concurrent Scan calls.
type Scanner struct {
	engine *rules.Engine
	cfg    Config
	cache  *cache
	flight *inFlight
}
