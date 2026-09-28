package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/h3yow/binary-static-analyzer-go/internal/parser"
	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// New constructs a Scanner bound to an immutable rule engine.
func New(engine *rules.Engine, cfg Config) *Scanner {
	cfg = normalizeConfig(cfg)
	s := &Scanner{engine: engine, cfg: cfg}
	if cfg.CacheEnabled {
		s.cache = newCache()
		s.flight = newInFlight()
	}
	return s
}

func normalizeConfig(cfg Config) Config {
	d := DefaultConfig()
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = d.MaxConcurrency
	}
	if cfg.MaxTargetSize == 0 {
		cfg.MaxTargetSize = d.MaxTargetSize
	}
	return cfg
}

// unit is one fully-resolved scan input at a given report position.
type unit struct {
	name    string
	content []byte
	hash    string
	readErr error
}

// uniqueJob is one evaluation shared by all positions with identical content.
type uniqueJob struct {
	positions []int
	result    Result
	done      chan struct{}
}

// Scan scans all targets and returns results in the exact input order.
//
// Semantics:
//   - Duplicate content in one call is evaluated once; across calls, the
//     same content under the same rule version is served from cache. A rule
//     version change never reuses an old verdict.
//   - Results always appear in target input order.
//   - Targets over MaxTargetSize get StatusRejected / ErrTooLarge without
//     being scheduled.
//   - A per-target deadline yields StatusTimeout for that target. Overall
//     timeout (or ctx cancel) terminates the run: finished targets keep
//     their verdicts, unfinished ones are StatusTimeout, and the call
//     returns ErrTimeout rather than blocking or swallowing the condition.
func (s *Scanner) Scan(ctx context.Context, targets []Target) (*Report, error) {
	if s.cfg.OverallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.cfg.OverallTimeout))
		defer cancel()
	}

	units := make([]unit, len(targets))
	for i, t := range targets {
		content, err := s.readTarget(ctx, t)
		u := unit{name: t.Name, content: content}
		if len(content) > 0 {
			u.hash = hashContent(content)
		}
		if err != nil {
			u.readErr = err
		}
		units[i] = u
	}

	results := make([]Result, len(targets))
	subs := make([]*uniqueJob, len(targets))
	jobByKey := make(map[cacheKey]*uniqueJob)

	// Pre-fill rejections/read errors; everything else becomes a unique job.
	for i := range units {
		rv := s.engine.Version()
		switch {
		case units[i].readErr != nil:
			results[i] = s.rejectResult(units[i].name, units[i].hash, units[i].readErr)
			continue
		case s.cfg.MaxTargetSize > 0 && int64(len(units[i].content)) > s.cfg.MaxTargetSize:
			results[i] = s.rejectResult(units[i].name, units[i].hash,
				fmt.Errorf("%w: %d bytes > limit %d",
					ErrTooLarge, len(units[i].content), s.cfg.MaxTargetSize))
			continue
		}
		k := cacheKey{contentHash: units[i].hash, ruleVersion: rv}
		j, ok := jobByKey[k]
		if !ok {
			j = &uniqueJob{done: make(chan struct{})}
			jobByKey[k] = j
		}
		j.positions = append(j.positions, i)
		subs[i] = j
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.cfg.MaxConcurrency)

	for k, j := range jobByKey {
		// Persistent cache: no worker slot consumed.
		if s.cache != nil {
			if cached, ok := s.cache.get(k); ok {
				j.result = cached
				close(j.done)
				continue
			}
		}
		wg.Add(1)
		go func(k cacheKey, j *uniqueJob) {
			defer wg.Done()
			first := units[j.positions[0]]

			// Cross-call in-flight coalescing: join an identical running job.
			var call *flightCall
			leader := true
			if s.flight != nil {
				call, leader = s.flight.start(k)
			}
			if !leader {
				select {
				case <-call.done:
					j.result = call.result
				case <-ctx.Done():
				}
				if j.result.Status == "" {
					j.result = s.timeoutResult(first.name, first.hash)
				}
				close(j.done)
				return
			}

			// Bound concurrent evaluation; bail to timeout if canceled while
			// waiting for a slot instead of blocking forever.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				res := s.timeoutResult(first.name, first.hash)
				j.result = res
				if s.flight != nil {
					s.flight.finish(k, call, res)
				}
				close(j.done)
				return
			}
			res := s.evaluateOne(ctx, first.name, first.content, first.hash)
			<-sem

			j.result = res
			if s.flight != nil {
				s.flight.finish(k, call, res)
			}
			if s.cache != nil && isCacheable(res) {
				s.cache.put(k, res)
			}
			close(j.done)
		}(k, j)
	}

	// Wait for every job goroutine to finish before touching j.result, so
	// cancellation cannot race with a worker still writing it. Workers are
	// context-aware (parser/engine honor ctx), so a canceled run unwinds
	// rather than hanging.
	wg.Wait()

	for i := range units {
		j := subs[i]
		if j == nil {
			continue
		}
		// j.done is closed by every worker path.
		<-j.done
		r := j.result
		if r.Status == "" {
			r = s.timeoutResult(units[i].name, units[i].hash)
		}
		r.Target = units[i].name // shared job carried the first position name
		results[i] = r
	}

	report := &Report{RuleVersion: s.engine.Version(), Results: results}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return report, ErrTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return report, ctx.Err()
	}
	return report, nil
}

func isCacheable(r Result) bool {
	switch r.Status {
	case StatusOK, StatusParseFail, StatusRuleError:
		return true
	default:
		return false
	}
}

// evaluateOne parses and matches a single target, honoring the per-target
// timeout. The returned Result always has a populated Status.
func (s *Scanner) evaluateOne(parent context.Context, name string, content []byte, hash string) Result {
	ctx := parent
	if s.cfg.PerTargetTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, time.Duration(s.cfg.PerTargetTimeout))
		defer cancel()
	}

	opts := parser.Options{
		MaxBinarySize:   s.cfg.MaxTargetSize,
		MaxSectionBytes: 16 << 20,
		MaxSections:     1 << 16,
	}
	bin, err := parser.Parse(ctx, content, opts)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return s.timeoutResult(name, hash)
		}
		status := StatusParseFail
		if errors.Is(err, parser.ErrOversized) {
			status = StatusRejected
		}
		return Result{
			Target:      name,
			Status:      status,
			Hash:        hash,
			RuleVersion: s.engine.Version(),
			Err:         err,
		}
	}

	findings, ferr := s.engine.Evaluate(ctx, bin)
	if ferr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return s.timeoutResult(name, hash)
		}
		return Result{
			Target:      name,
			Status:      StatusRuleError,
			Hash:        hash,
			Format:      bin.Format,
			RuleVersion: s.engine.Version(),
			Err:         ferr,
		}
	}
	return Result{
		Target:      name,
		Status:      StatusOK,
		Hash:        hash,
		Format:      bin.Format,
		Findings:    findings,
		RuleVersion: s.engine.Version(),
	}
}

func (s *Scanner) rejectResult(name, hash string, err error) Result {
	return Result{
		Target:      name,
		Status:      StatusRejected,
		Hash:        hash,
		RuleVersion: s.engine.Version(),
		Err:         err,
	}
}

func (s *Scanner) timeoutResult(name, hash string) Result {
	return Result{
		Target:      name,
		Status:      StatusTimeout,
		Hash:        hash,
		RuleVersion: s.engine.Version(),
		Err:         ErrTimeout,
	}
}

// readTarget returns the exact bytes for a target. Inline Content is used
// verbatim; otherwise the named file is read. Reading is bounded so an
// oversized input is refused rather than exhausting memory.
func (s *Scanner) readTarget(ctx context.Context, t Target) ([]byte, error) {
	if t.Content != nil {
		if s.cfg.MaxTargetSize > 0 && int64(len(t.Content)) > s.cfg.MaxTargetSize {
			return t.Content, fmt.Errorf("%w: %d bytes > limit %d",
				ErrTooLarge, len(t.Content), s.cfg.MaxTargetSize)
		}
		return t.Content, nil
	}
	if t.Name == "" {
		return nil, fmt.Errorf("scan: target has neither content nor a name")
	}
	f, err := os.Open(t.Name)
	if err != nil {
		return nil, fmt.Errorf("scan: open target: %w", err)
	}
	defer f.Close()

	limit := s.cfg.MaxTargetSize
	if limit <= 0 {
		limit = 1 << 62
	}
	// One guard byte detects input strictly larger than the limit.
	data, rerr := io.ReadAll(io.LimitReader(f, limit+1))
	if rerr != nil {
		return data, fmt.Errorf("scan: read target: %w", rerr)
	}
	if int64(len(data)) > limit {
		return data, fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, t.Name, limit)
	}
	if err := ctx.Err(); err != nil {
		return data, err
	}
	return data, nil
}

func hashContent(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
