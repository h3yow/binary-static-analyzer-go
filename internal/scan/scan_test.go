package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
	"github.com/h3yow/binary-static-analyzer-go/internal/parser"
	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// --- test fixtures --------------------------------------------------------

var (
	// minimalELF: full magic, class64, LE, no sections (shoff=0,shnum=0)
	minimalELF = func() []byte {
		b := make([]byte, 64)
		b[0], b[1], b[2], b[3] = 0x7f, 'E', 'L', 'F'
		b[4], b[5], b[6] = 2, 1, 1
		b[16], b[17] = 2, 0    // e_type = ET_EXEC
		b[18], b[19] = 0x3e, 0 // e_machine = X86_64
		b[52], b[53] = 64, 0   // e_ehsize
		b[58], b[59] = 64, 0   // e_shentsize
		b[60], b[61] = 0, 0    // e_shnum = 0
		b[62], b[63] = 0, 0    // e_shstrndx
		return b
	}()
	garbage = []byte("definitely not an executable format")
)

func engineFor(t *testing.T, version string, rs ...rules.Rule) *rules.Engine {
	t.Helper()
	if len(rs) == 0 {
		rs = []rules.Rule{{ID: "IS_ELF", Scope: rules.ScopeFormat, Match: rules.MatchExact, Pattern: "elf", Severity: "info"}}
	}
	set, err := rules.SetFromRules(version, rs)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := rules.NewEngine(set)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func logTargets(t *testing.T, ts []Target) {
	t.Helper()
	for i, tg := range ts {
		n := len(tg.Content)
		head := tg.Content
		if n > 8 {
			head = head[:8]
		}
		t.Logf("target[%d] name=%q len=%d head=% x", i, tg.Name, n, head)
	}
}

// --- tests ----------------------------------------------------------------

func TestScan_OrderStableAndMatchesSequential(t *testing.T) {
	eng := engineFor(t, "v1")
	contents := [][]byte{minimalELF, garbage, minimalELF, minimalELF}
	mkTargets := func() []Target {
		out := make([]Target, len(contents))
		for i, c := range contents {
			out[i] = Target{Name: fmt.Sprintf("t%d", i), Content: c}
		}
		return out
	}

	// Concurrent scan with high concurrency and deliberate content order.
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 8
	s := New(eng, cfg)
	logTargets(t, mkTargets())
	concurrent, err := s.Scan(context.Background(), mkTargets())
	if err != nil {
		t.Fatal(err)
	}

	// Sequential, cache disabled so each is independently evaluated.
	seqCfg := DefaultConfig()
	seqCfg.MaxConcurrency = 1
	seqCfg.CacheEnabled = false
	seq := New(eng, seqCfg)
	sequential, err := seq.Scan(context.Background(), mkTargets())
	if err != nil {
		t.Fatal(err)
	}

	if len(concurrent.Results) != len(contents) {
		t.Fatalf("result count %d", len(concurrent.Results))
	}
	for i := range contents {
		c, q := concurrent.Results[i], sequential.Results[i]
		t.Logf("pos=%d concurrent=%s/%d seq=%s/%d target=%s",
			i, c.Status, len(c.Findings), q.Status, len(q.Findings), c.Target)
		if c.Target != fmt.Sprintf("t%d", i) {
			t.Fatalf("position %d carries wrong name %q", i, c.Target)
		}
		if c.Status != q.Status || len(c.Findings) != len(q.Findings) {
			t.Fatalf("concurrent vs sequential mismatch at %d", i)
		}
		if i == 0 && (len(c.Findings) != 1 || c.Findings[0].RuleID != "IS_ELF") {
			t.Fatalf("elf verdict wrong: %+v", c.Findings)
		}
		if i == 1 && !errors.Is(c.Err, parser.ErrUnknownFormat) {
			t.Fatalf("garbage must be parse_failed/unknown, got %v", c.Err)
		}
	}
}

func TestScan_DuplicateContentScannedOnce(t *testing.T) {
	eng := engineFor(t, "v1")
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 4
	s := New(eng, cfg)

	var parses int64
	parser.Register(&countingParser{&parses})
	defer parser.Register(noopResetParser{})

	targets := []Target{
		{Name: "a", Content: countingMagic()},
		{Name: "b", Content: countingMagic()},
		{Name: "c", Content: countingMagic()},
	}
	rep, err := s.Scan(context.Background(), targets)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.Status != StatusOK {
			t.Fatalf("unexpected status %s err=%v", r.Status, r.Err)
		}
	}
	t.Logf("parses observed=%d cache entries=%d", atomic.LoadInt64(&parses), s.CacheLen())
	if got := atomic.LoadInt64(&parses); got != 1 {
		t.Fatalf("identical content should parse once per Scan, got %d", got)
	}
}

func TestScan_CacheReusedAcrossScans(t *testing.T) {
	eng := engineFor(t, "v1")
	s := New(eng, DefaultConfig())
	r1, err := s.Scan(context.Background(), []Target{{Name: "a", Content: minimalELF}})
	if err != nil {
		t.Fatal(err)
	}
	if s.CacheLen() != 1 {
		t.Fatalf("want 1 cached, got %d", s.CacheLen())
	}
	r2, err := s.Scan(context.Background(), []Target{{Name: "a-again", Content: minimalELF}})
	if err != nil {
		t.Fatal(err)
	}
	if !equalResultsIgnoringName(r1.Results[0], r2.Results[0]) {
		t.Fatalf("cached verdict differs:\n%+v\n%+v", r1.Results[0], r2.Results[0])
	}
	t.Logf("reused verdict: status=%s findings=%d hash=%s",
		r2.Results[0].Status, len(r2.Results[0].Findings), r2.Results[0].Hash)
}

func TestScan_RuleVersionChangeBustsCache(t *testing.T) {
	eng1 := engineFor(t, "v1", rules.Rule{ID: "R1", Scope: rules.ScopeFormat, Match: rules.MatchExact, Pattern: "elf", Severity: "low"})
	eng2 := engineFor(t, "v2",
		rules.Rule{ID: "R1", Scope: rules.ScopeFormat, Match: rules.MatchExact, Pattern: "elf", Severity: "low"},
		rules.Rule{ID: "R2", Scope: rules.ScopeArch, Match: rules.MatchExact, Pattern: "x86_64", Severity: "high"},
	)
	s := New(eng1, DefaultConfig())
	r1, _ := s.Scan(context.Background(), []Target{{Name: "a", Content: minimalELF}})
	if r1.Results[0].RuleVersion != "v1" || len(r1.Results[0].Findings) != 1 {
		t.Fatalf("v1 verdict wrong: %+v", r1.Results[0])
	}

	// Same scanner cache, but engine upgraded: cache key includes version,
	// so the historical v1 verdict must not be silently reused.
	s.engine = eng2
	r2, _ := s.Scan(context.Background(), []Target{{Name: "a", Content: minimalELF}})
	if r2.Results[0].RuleVersion != "v2" || len(r2.Results[0].Findings) != 2 {
		t.Fatalf("v2 verdict must be recomputed, got %+v", r2.Results[0])
	}
	// Historical v1 verdict still reproducible from its own result.
	t.Logf("v1=%d findings (%s); v2=%d findings (%s) — versions isolated",
		1, r1.Results[0].RuleVersion, 2, r2.Results[0].RuleVersion)
}

func TestScan_TooLargeRejected(t *testing.T) {
	eng := engineFor(t, "v1")
	cfg := DefaultConfig()
	cfg.MaxTargetSize = 4
	s := New(eng, cfg)
	rep, err := s.Scan(context.Background(), []Target{{Name: "big", Content: minimalELF}})
	if err != nil {
		t.Fatalf("rejection must not fail the whole call: %v", err)
	}
	r := rep.Results[0]
	t.Logf("verdict for oversized: status=%s err=%v", r.Status, r.Err)
	if r.Status != StatusRejected || !errors.Is(r.Err, ErrTooLarge) {
		t.Fatalf("want rejected/ErrTooLarge, got %s/%v", r.Status, r.Err)
	}
}

func TestScan_PerTargetTimeout(t *testing.T) {
	// A parser that blocks until canceled must yield StatusTimeout, not hang.
	var entered int64
	parser.Register(&slowParser{&entered})
	defer parser.Register(noopResetParser{})

	eng := engineFor(t, "v1")
	cfg := DefaultConfig()
	cfg.PerTargetTimeout = Duration(20 * time.Millisecond)
	s := New(eng, cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, err := s.Scan(context.Background(), []Target{{Name: "slow", Content: slowMagic()}})
		if err != nil {
			t.Errorf("unexpected call error: %v", err)
		}
		r := rep.Results[0]
		if r.Status != StatusTimeout || !errors.Is(r.Err, ErrTimeout) {
			t.Errorf("want timeout, got %s/%v", r.Status, r.Err)
		}
		t.Logf("slow target verdict: status=%s err=%v", r.Status, r.Err)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan hung despite per-target timeout")
	}
}

func TestScan_OverallTimeout(t *testing.T) {
	var entered int64
	parser.Register(&slowParser{&entered})
	defer parser.Register(noopResetParser{})

	eng := engineFor(t, "v1")
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 1
	cfg.OverallTimeout = Duration(20 * time.Millisecond)
	s := New(eng, cfg)
	targets := []Target{
		{Name: "slow1", Content: slowMagic()},
		{Name: "slow2", Content: slowMagic()},
	}
	rep, err := s.Scan(context.Background(), targets)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout from call, got %v", err)
	}
	if rep == nil {
		t.Fatal("report should still be returned")
	}
	for i, r := range rep.Results {
		t.Logf("overall-timeout pos=%d status=%s", i, r.Status)
		if r.Status != StatusTimeout {
			t.Fatalf("unfinished target must be timeout, got %s", r.Status)
		}
	}
}

// --- counting parser (distinct magic) ------------------------------------

type countingParser struct{ n *int64 }

func countingMagic() []byte            { return []byte("CNT1....") }
func (c *countingParser) Name() string { return "counting" }
func (c *countingParser) Sniff(data []byte) bool {
	return bytes.HasPrefix(data, []byte("CNT1"))
}
func (c *countingParser) Parse(ctx context.Context, data []byte, opts parser.Options) (*model.Binary, error) {
	atomic.AddInt64(c.n, 1)
	// Emulate some work so concurrent duplicates actually race.
	time.Sleep(5 * time.Millisecond)
	return &model.Binary{Format: model.FormatELF}, nil
}

// slowParser blocks until its context is canceled.
type slowParser struct{ entered *int64 }

func slowMagic() []byte                      { return []byte("SLOW....") }
func (p *slowParser) Name() string           { return "slow" }
func (p *slowParser) Sniff(data []byte) bool { return bytes.HasPrefix(data, []byte("SLOW")) }
func (p *slowParser) Parse(ctx context.Context, data []byte, opts parser.Options) (*model.Binary, error) {
	atomic.AddInt64(p.entered, 1)
	<-ctx.Done()
	return nil, ctx.Err()
}

// noopResetParser re-registers a harmless parser then we rely on registry
// order; instead tests simply prepend and this type removes ambiguity by
// never sniffing.
type noopResetParser struct{}

func (noopResetParser) Name() string      { return "noop-reset" }
func (noopResetParser) Sniff([]byte) bool { return false }
func (noopResetParser) Parse(context.Context, []byte, parser.Options) (*model.Binary, error) {
	return nil, &parser.ParseError{Cause: parser.ErrUnsupported}
}

func equalResultsIgnoringName(a, b Result) bool {
	if a.Status != b.Status || a.Hash != b.Hash || a.RuleVersion != b.RuleVersion ||
		a.Format != b.Format || len(a.Findings) != len(b.Findings) {
		return false
	}
	for i := range a.Findings {
		if a.Findings[i] != b.Findings[i] {
			return false
		}
	}
	return true
}
