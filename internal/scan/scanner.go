// Package scan orchestrates concurrent multi-target scans, caching and
// resource/timeout limits.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/h3yow/binary-static-analyzer-go/internal/binary"
	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// Status is the terminal status of one target.
type Status string

// Target outcome statuses.
const (
	StatusOK          Status = "ok"
	StatusParseFailed Status = "parse_failed"
	StatusRejected    Status = "rejected"
	StatusTerminated  Status = "terminated"
	StatusRuleError   Status = "rule_error"
	StatusInternal    Status = "internal_error"
)

// ErrorInfo is the serializable form of a structured error.
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Format  string `json:"format,omitempty"`
	Offset  int64  `json:"offset,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

// Target is one scan input.
type Target struct {
	Name string
	Data []byte
}

// Result is the full, reproducible verdict for one target.
type Result struct {
	Target         string          `json:"target"`
	ContentSHA256  string          `json:"content_sha256"`
	Size           int64           `json:"size"`
	Status         Status          `json:"status"`
	Error          *ErrorInfo      `json:"error,omitempty"`
	RuleSetID      string          `json:"rule_set_id,omitempty"`
	RuleSetVersion string          `json:"rule_set_version,omitempty"`
	RuleSetHash    string          `json:"rule_set_hash,omitempty"`
	Findings       []rules.Finding `json:"findings"`
	Cached         bool            `json:"cached"`
	DurationMS     int64           `json:"duration_ms"`
}

// Default configuration values (applied when a field is zero-valued).
const (
	defaultConcurrency = 4
	defaultMaxFileSize = 256 << 20 // 256 MiB
	defaultMaxTargets  = 10000
)

// Config holds the configurable concurrency/resource/timeout limits.
type Config struct {
	// Concurrency bounds how many targets are evaluated at the same time.
	Concurrency int
	// MaxFileSize rejects inputs larger than this many bytes, synchronously.
	MaxFileSize int64
	// MaxTargets rejects batches with more than this many inputs, synchronously.
	MaxTargets int
	// Timeout bounds the wall-clock evaluation of one target. Zero disables it.
	Timeout time.Duration
	// Cache stores reusable outcomes. nil disables caching.
	Cache Cache
}

// Scanner runs scans with bounded concurrency and a shared cache.
type Scanner struct {
	cfg    Config
	ev     rules.Evaluator
	set    *rules.Set
	flight *singleflight
}

// New builds a Scanner. A nil/empty rule set means structure-only scanning
// (only parse outcomes are produced). Invalid rule sets fail construction.
func New(cfg Config, ruleSetJSON []byte) (*Scanner, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = defaultMaxFileSize
	}
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = defaultMaxTargets
	}

	s := &Scanner{cfg: cfg, flight: newSingleflight()}
	if len(ruleSetJSON) > 0 {
		set, err := rules.LoadSet(ruleSetJSON)
		if err != nil {
			return nil, fmt.Errorf("scan: load rule set: %w", err)
		}
		eng, err := rules.NewEngine(set)
		if err != nil {
			return nil, fmt.Errorf("scan: compile rule set: %w", err)
		}
		s.set = set
		s.ev = eng
	}
	return s, nil
}

// RuleSetHash returns the content hash of the active rule set, or "" when the
// scanner runs in structure-only mode.
func (s *Scanner) RuleSetHash() string {
	if s.set == nil {
		return ""
	}
	return s.set.Hash()
}

// Scan scans one target, honoring the cache and per-target timeout.
func (s *Scanner) Scan(ctx context.Context, t Target) Result {
	start := time.Now()
	size := int64(len(t.Data))
	sum := sha256.Sum256(t.Data)
	sha := hex.EncodeToString(sum[:])

	res := Result{
		Target:        t.Name,
		ContentSHA256: sha,
		Size:          size,
	}
	if s.set != nil {
		res.RuleSetID = s.set.ID
		res.RuleSetVersion = s.set.Version
		res.RuleSetHash = s.set.Hash()
	}

	if size > s.cfg.MaxFileSize {
		res.Status = StatusRejected
		res.Error = &ErrorInfo{
			Kind:    "file_too_large",
			Message: fmt.Sprintf("input size %d exceeds configured MaxFileSize %d", size, s.cfg.MaxFileSize),
		}
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	key := s.cacheKey(sha)
	if s.cfg.Cache != nil {
		if env, ok := s.cfg.Cache.Get(key); ok {
			fromEnvelope(&res, env)
			res.Cached = true
			res.DurationMS = time.Since(start).Milliseconds()
			return res
		}
	}

	// Coalesce concurrent evaluations of identical content. Only a hit in a
	// pre-existing cache marks Cached; callers that join an in-flight
	// evaluation share its work but are not reported as cache hits.
	env := s.flight.do(key, func() Envelope {
		e := s.evaluate(ctx, t.Data)
		e.ContentSHA = sha
		e.Size = size
		// Only outcomes that are purely a function of content + rule set are
		// reusable; timeouts/cancellations/panics are never cached.
		if e.Status == StatusOK || e.Status == StatusParseFailed {
			s.putCached(key, e)
		}
		return e
	})
	fromEnvelope(&res, env)
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func (s *Scanner) putCached(key string, env Envelope) {
	if s.cfg.Cache != nil {
		s.cfg.Cache.Set(key, env)
	}
}

func (s *Scanner) cacheKey(contentSHA string) string {
	if s.set == nil {
		return "no-rules:" + contentSHA
	}
	return s.set.Hash() + ":" + contentSHA
}

// evaluate performs parsing and rule evaluation under the per-target timeout.
// A panic in any parser/rule is recovered so one target never kills a worker.
func (s *Scanner) evaluate(parent context.Context, data []byte) (env Envelope) {
	ctx := parent
	var cancel context.CancelFunc
	if s.cfg.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, s.cfg.Timeout)
		defer cancel()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				env = Envelope{
					Status: StatusInternal,
					Error:  &ErrorInfo{Kind: "panic", Message: fmt.Sprintf("recovered: %v", r)},
				}
			}
		}()
		env = s.runOnce(ctx, data)
	}()
	select {
	case <-done:
		return env
	case <-ctx.Done():
		// Timeout (or parent cancellation): the evaluation goroutine may keep
		// running to a checkpoint, but we return immediately with a definite
		// terminal status; no result is cached.
		<-done // avoid leaking the goroutine; Evaluate checks ctx between rules
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Envelope{
				Status: StatusTerminated,
				Error: &ErrorInfo{
					Kind:    "timeout",
					Message: fmt.Sprintf("scan exceeded per-target timeout %s", s.cfg.Timeout),
				},
			}
		}
		return Envelope{
			Status: StatusTerminated,
			Error: &ErrorInfo{
				Kind:    "canceled",
				Message: "scan context canceled before completion",
			},
		}
	}
}

func (s *Scanner) runOnce(ctx context.Context, data []byte) Envelope {
	b, err := binary.Parse(data)
	if err != nil {
		return Envelope{Status: StatusParseFailed, Error: convertBinaryError(err)}
	}
	if s.ev == nil {
		return Envelope{Status: StatusOK, Findings: []rules.Finding{}}
	}
	findings, err := s.ev.Evaluate(ctx, b, data)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Envelope{
				Status: StatusTerminated,
				Error:  &ErrorInfo{Kind: "timeout", Message: err.Error()},
			}
		}
		if errors.Is(err, context.Canceled) {
			return Envelope{
				Status: StatusTerminated,
				Error:  &ErrorInfo{Kind: "canceled", Message: "evaluation canceled: " + err.Error()},
			}
		}
		return Envelope{
			Status: StatusRuleError,
			Error:  &ErrorInfo{Kind: "rule_engine_error", Message: err.Error()},
		}
	}
	if findings == nil {
		findings = []rules.Finding{}
	}
	return Envelope{Status: StatusOK, Findings: findings}
}

func convertBinaryError(err error) *ErrorInfo {
	var pe *binary.Error
	if errors.As(err, &pe) {
		return &ErrorInfo{
			Kind:    string(pe.Kind),
			Format:  string(pe.Format),
			Offset:  pe.Offset,
			Field:   pe.Field,
			Message: pe.Msg,
		}
	}
	return &ErrorInfo{Kind: "parse_error", Message: err.Error()}
}

func fromEnvelope(res *Result, env Envelope) {
	res.Status = env.Status
	res.Error = env.Error
	res.Findings = env.Findings
}
