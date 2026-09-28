package scan

import (
	"context"
	"sort"
	"sync"
)

// ScanBatch scans many targets with bounded concurrency. The returned slice
// always matches the input order exactly, and the outcome for every position
// is identical to scanning that target on its own (deterministic content
// evaluation), even when targets share identical contents.
//
// If len(targets) exceeds Config.MaxTargets the batch is rejected
// synchronously: every position receives StatusRejected and no parsing work
// starts.
func (s *Scanner) ScanBatch(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	if len(targets) > s.cfg.MaxTargets {
		for i, t := range targets {
			results[i] = Result{
				Target: t.Name,
				Size:   int64(len(t.Data)),
				Status: StatusRejected,
				Error: &ErrorInfo{
					Kind:    "too_many_targets",
					Message: batchRejectMsg(len(targets), s.cfg.MaxTargets),
				},
			}
		}
		return results
	}

	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for i := range targets {
		i := i
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Stop dispatching new work once the parent context is done;
			// already-running targets finish and observe the same context.
			wg.Done()
			results[i] = canceledResult(targets[i], ctx)
			continue
		}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = s.Scan(ctx, targets[i])
		}()
	}
	wg.Wait()
	return results
}

func canceledResult(t Target, ctx context.Context) Result {
	kind := "canceled"
	msg := "scan context canceled before target could start"
	if ctx.Err() == context.DeadlineExceeded {
		kind = "timeout"
		msg = "batch context deadline exceeded before target could start"
	}
	return Result{
		Target: t.Name,
		Size:   int64(len(t.Data)),
		Status: StatusTerminated,
		Error:  &ErrorInfo{Kind: kind, Message: msg},
	}
}

// ScanMany is kept as a stable alias in case callers prefer the plural name.
func (s *Scanner) ScanMany(ctx context.Context, targets []Target) []Result {
	return s.ScanBatch(ctx, targets)
}

// SortedResults returns results ordered by target name; use only for display.
func SortedResults(rs []Result) []Result {
	out := make([]Result, len(rs))
	copy(out, rs)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

func batchRejectMsg(n, max int) string {
	return "batch of " + itoa(n) + " targets exceeds configured MaxTargets " + itoa(max)
}

// itoa avoids importing strconv solely for two integers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
