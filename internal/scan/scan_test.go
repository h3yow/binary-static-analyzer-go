package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	bin "github.com/h3yow/binary-static-analyzer-go/internal/binary"
)

const ruleJSON = `{
  "id": "default",
  "version": "2026.09",
  "rules": [
    {"id":"FMT","version":"1","name":"is ELF","severity":"info",
     "target":"format","op":"equals","value":"elf"},
    {"id":"SEC","version":"1","name":"secret","severity":"high",
     "target":"section_content","section":".data","op":"contains","value":"SECRET"}
  ]
}`

func elfFixture(t *testing.T) []byte {
	t.Helper()
	names := "\x00.text\x00.data\x00.shstrtab\x00"
	nameOff := func(s string) uint32 { return uint32(bytes.Index([]byte(names), []byte(s))) }
	textBody := []byte{0xcc, 0x90}
	dataBody := []byte("SECRET-DATA")
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x7f, 'E', 'L', 'F'
	hdr[4], hdr[5], hdr[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], 2)
	le.PutUint16(hdr[18:], 0x3e)
	le.PutUint32(hdr[20:], 1)
	le.PutUint64(hdr[24:], 0x400010)
	le.PutUint16(hdr[58:], 64)
	le.PutUint16(hdr[60:], 4)
	le.PutUint16(hdr[62:], 3)
	var buf bytes.Buffer
	buf.Write(hdr)
	textOff := uint64(buf.Len())
	buf.Write(textBody)
	dataOff := uint64(buf.Len())
	buf.Write(dataBody)
	strOff := uint64(buf.Len())
	buf.WriteString(names)
	shoff := uint64(buf.Len())
	buf.Write(make([]byte, 64))
	writeShdr := func(name uint32, typ uint32, flags uint64, addr, off, size uint64) {
		sh := make([]byte, 64)
		le.PutUint32(sh[0:], name)
		le.PutUint32(sh[4:], typ)
		le.PutUint64(sh[8:], flags)
		le.PutUint64(sh[16:], addr)
		le.PutUint64(sh[24:], off)
		le.PutUint64(sh[32:], size)
		buf.Write(sh)
	}
	writeShdr(nameOff(".text"), 1, 2|4, 0x401000, textOff, uint64(len(textBody)))
	writeShdr(nameOff(".data"), 1, 2, 0x402000, dataOff, uint64(len(dataBody)))
	writeShdr(nameOff(".shstrtab"), 3, 0, 0, strOff, uint64(len(names)))
	out := buf.Bytes()
	le.PutUint64(out[40:], shoff)
	return out
}

func TestConcurrentScanMatchesSequentialAndOrderStable(t *testing.T) {
	good := elfFixture(t)
	targets := []Target{
		{Name: "a", Data: good},
		{Name: "trunc", Data: []byte{0x7f, 'E', 'L', 'F'}},
		{Name: "b", Data: good},
		{Name: "garbage", Data: []byte("hello world this is not an executable")},
		{Name: "c", Data: good},
	}

	newS := func(t *testing.T) *Scanner {
		t.Helper()
		s, err := New(Config{Concurrency: 8, Cache: NewMemoryCache()}, []byte(ruleJSON))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	seq := newS(t)
	var seqResults []Result
	for _, tg := range targets {
		seqResults = append(seqResults, seq.Scan(context.Background(), tg))
	}

	// Run several concurrent rounds; ordering and content must be stable.
	for round := 0; round < 5; round++ {
		par := newS(t)
		got := par.ScanBatch(context.Background(), targets)
		if len(got) != len(targets) {
			t.Fatalf("round %d: got %d results, want %d", round, len(got), len(targets))
		}
		for i := range targets {
			if got[i].Target != targets[i].Name {
				t.Fatalf("round %d: order drifted at %d: %s", round, i, got[i].Target)
			}
			if got[i].Status != seqResults[i].Status {
				t.Fatalf("round %d target %s: concurrent status %s != sequential %s",
					round, got[i].Target, got[i].Status, seqResults[i].Status)
			}
			if len(got[i].Findings) != len(seqResults[i].Findings) {
				t.Fatalf("round %d target %s: findings differ (%d vs %d)",
					round, got[i].Target, len(got[i].Findings), len(seqResults[i].Findings))
			}
			for j := range got[i].Findings {
				if got[i].Findings[j].Basis != seqResults[i].Findings[j].Basis {
					t.Fatalf("round %d target %s finding %d basis drift", round, got[i].Target, j)
				}
			}
		}
	}

	// Inputs and decision bases are logged for the malformed cases.
	par := newS(t)
	res := par.ScanBatch(context.Background(), targets)
	for i, r := range res {
		if r.Error != nil {
			t.Logf("input %q (%d bytes): status=%s error.kind=%s offset=%d field=%q msg=%q",
				targets[i].Name, r.Size, r.Status, r.Error.Kind, r.Error.Offset, r.Error.Field, r.Error.Message)
		} else {
			for _, f := range r.Findings {
				t.Logf("input %q: rule=%s basis=%q", targets[i].Name, f.RuleID, f.Basis)
			}
		}
	}

	if res[1].Status != StatusParseFailed || res[1].Error.Kind != string(bin.KindTruncated) {
		t.Fatalf("truncated ELF: %+v", res[1].Error)
	}
	if res[3].Status != StatusParseFailed || res[3].Error.Kind != string(bin.KindUnsupportedFormat) {
		t.Fatalf("garbage: %+v", res[3].Error)
	}
	if res[0].Status != StatusOK || len(res[0].Findings) != 2 {
		t.Fatalf("good ELF: status=%s findings=%d", res[0].Status, len(res[0].Findings))
	}
}

func TestCacheReuseAndSingleflight(t *testing.T) {
	good := elfFixture(t)
	// First scan is cold; subsequent scans of identical content must report
	// Cached=true and carry the identical verdict envelope.
	cache := NewMemoryCache()
	s, err := New(Config{Concurrency: 4, Cache: cache}, []byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	r1 := s.Scan(context.Background(), Target{Name: "first", Data: good})
	r2 := s.Scan(context.Background(), Target{Name: "second", Data: good})
	if r1.Cached {
		t.Fatal("first scan must be cold")
	}
	if !r2.Cached {
		t.Fatal("identical content must be served from cache")
	}
	if cache.Len() != 1 {
		t.Fatalf("cache entries = %d, want 1", cache.Len())
	}
	if r1.ContentSHA256 != r2.ContentSHA256 || len(r1.Findings) != len(r2.Findings) {
		t.Fatal("cached verdict must equal cold verdict")
	}
	t.Logf("input sha256=%s cached basis count=%d cache stats=%s",
		r1.ContentSHA256, len(r1.Findings), cache.statsForTest())

	// Concurrent identical submissions coalesce and the second wave is cached.
	ts := []Target{
		{Name: "x1", Data: good}, {Name: "x2", Data: good},
		{Name: "x3", Data: good}, {Name: "x4", Data: good},
	}
	batch := s.ScanBatch(context.Background(), ts)
	for _, r := range batch {
		if !r.Cached {
			t.Fatalf("target %s should be cached after warm-up", r.Target)
		}
	}
}

func TestLimitsSynchronousRejection(t *testing.T) {
	s, err := New(Config{Concurrency: 2, MaxFileSize: 4, MaxTargets: 3, Cache: NewMemoryCache()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	big := Target{Name: "big", Data: make([]byte, 5)}
	r := s.Scan(context.Background(), big)
	if r.Status != StatusRejected || r.Error.Kind != "file_too_large" {
		t.Fatalf("size limit: %+v", r)
	}
	t.Logf("oversize input basis: %s", r.Error.Message)

	ts := []Target{
		{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"},
	}
	rs := s.ScanBatch(context.Background(), ts)
	for _, rr := range rs {
		if rr.Status != StatusRejected || rr.Error.Kind != "too_many_targets" {
			t.Fatalf("batch limit: %+v", rr)
		}
	}
	t.Logf("oversized batch (%d inputs) basis: %s", len(rs), rs[0].Error.Message)
}

func TestTimeoutTerminatesWithDefiniteStatus(t *testing.T) {
	// Go's RE2 regexp engine cannot backtrack, so deterministically exercise
	// the timeout path with a slow Evaluator (the engine slot is an interface
	// precisely to allow bounded, non-hanging rule backends).
	slow := &slowEvaluator{delay: 500 * time.Millisecond}
	s := &Scanner{
		cfg:    Config{Concurrency: 2, Timeout: 25 * time.Millisecond, MaxFileSize: 1 << 30, MaxTargets: 1000},
		flight: newSingleflight(),
		ev:     slow,
	}

	good := elfFixture(t)
	start := time.Now()
	r := s.Scan(context.Background(), Target{Name: "slow", Data: good})
	elapsed := time.Since(start)
	t.Logf("input: %d-byte ELF; slow engine delay=500ms; status=%s elapsed=%s basis=%v",
		len(good), r.Status, elapsed, r.Error)
	if r.Status != StatusTerminated || r.Error.Kind != "timeout" {
		t.Fatalf("want terminated/timeout, got %s %+v", r.Status, r.Error)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("scan hung past timeout: %s", elapsed)
	}

	// Timeout outcomes must not be cached and a generous timeout still
	// produces the definite OK result.
	s2 := &Scanner{
		cfg:    Config{Concurrency: 2, Timeout: 5 * time.Second, Cache: NewMemoryCache(), MaxFileSize: 1 << 30, MaxTargets: 1000},
		flight: newSingleflight(),
		ev:     slow,
	}
	ok := s2.Scan(context.Background(), Target{Name: "slow", Data: good})
	if ok.Status != StatusOK || ok.Cached {
		t.Fatalf("fresh scan should complete OK without a cached timeout: %+v", ok)
	}
}

func TestRuleSetVersionPinnedInResult(t *testing.T) {
	good := elfFixture(t)
	s, err := New(Config{Cache: NewMemoryCache()}, []byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	r := s.Scan(context.Background(), Target{Name: "x", Data: good})
	if r.RuleSetVersion != "2026.09" || r.RuleSetHash == "" {
		t.Fatalf("result not pinned to rule set: %+v", r)
	}
	t.Logf("decision basis pinned: rule_set=%s/%s hash=%s", r.RuleSetID, r.RuleSetVersion, r.RuleSetHash)

	// Same content under a *different* rule-set hash must NOT hit the cache.
	v2 := []byte(`{
	  "id":"default","version":"2026.10",
	  "rules":[
	    {"id":"FMT","version":"1","name":"is ELF","severity":"info",
	     "target":"format","op":"equals","value":"elf"}
	  ]
	}`)
	s2, err := New(Config{Cache: NewMemoryCache()}, v2)
	if err != nil {
		t.Fatal(err)
	}
	r2 := s2.Scan(context.Background(), Target{Name: "x", Data: good})
	if r2.Cached || r2.RuleSetHash == r.RuleSetHash || len(r2.Findings) != 1 {
		t.Fatalf("rule upgrade changed verdict and must not reuse old cache: %+v", r2)
	}
	t.Logf("upgraded basis: %s hash=%s findings=%d", r2.RuleSetVersion, r2.RuleSetHash, len(r2.Findings))
}

func TestMalformedSamplesDistinguished(t *testing.T) {
	s, _ := New(Config{}, []byte(ruleJSON))
	cases := []struct {
		name string
		data []byte
		kind string
	}{
		{"elf truncated", []byte{0x7f, 'E', 'L', 'F'}, string(bin.KindTruncated)},
		{"elf bad class", append([]byte{0x7f, 'E', 'L', 'F', 9}, make([]byte, 20)...), string(bin.KindInvalidField)},
		{"pe mz only", []byte{'M', 'Z'}, string(bin.KindTruncated)},
		{"unknown", []byte{0, 1, 2, 3, 4, 5, 6, 7}, string(bin.KindUnsupportedFormat)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := s.Scan(context.Background(), Target{Name: tc.name, Data: tc.data})
			t.Logf("input=%q (%d bytes) -> status=%s kind=%s basis=%s",
				tc.name, len(tc.data), r.Status, r.Error.Kind, r.Error.Message)
			if r.Status != StatusParseFailed {
				t.Fatalf("status=%s", r.Status)
			}
			if r.Error == nil || r.Error.Kind != tc.kind {
				t.Fatalf("kind=%v want %s (err=%v)", r.Error, tc.kind, r.Error)
			}
		})
	}
}

func TestBatchCancellationGivesDefiniteStatus(t *testing.T) {
	good := elfFixture(t)
	// One very slow target occupies the single slot; the queued target should
	// receive terminated/canceled once the batch context is canceled rather
	// than hanging.
	s := &Scanner{
		cfg:    Config{Concurrency: 1, MaxFileSize: 1 << 30, MaxTargets: 100},
		flight: newSingleflight(),
		ev:     &slowEvaluator{delay: 2 * time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	targets := []Target{
		{Name: "slow-1", Data: good},
		{Name: "slow-2", Data: append(good, 1)},
		{Name: "slow-3", Data: append(good, 2)},
	}
	start := time.Now()
	rs := s.ScanBatch(ctx, targets)
	elapsed := time.Since(start)
	for i, r := range rs {
		t.Logf("input %q: status=%s kind=%v elapsed=%s", r.Target, r.Status, r.Error, elapsed)
		if r.Status != StatusTerminated {
			t.Fatalf("target %d (%s): status=%s, want terminated", i, r.Target, r.Status)
		}
	}
	if elapsed > 3*time.Second {
		t.Fatalf("batch hung after cancellation: %s", elapsed)
	}
}
