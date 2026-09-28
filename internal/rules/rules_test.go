package rules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

func sampleBinary() *model.Binary {
	return &model.Binary{
		Format:       model.FormatELF,
		Arch:         model.ArchX86_64,
		Bits:         64,
		LittleEndian: true,
		Sections: []model.Section{
			{Name: ".text", Offset: 0x1000, Raw: []byte("AAAAevil-signatureBBBB")},
			{Name: ".data", Offset: 0x2000, Raw: []byte("clean data")},
		},
		Imports: []model.Import{
			{Library: "libc.so.6", Symbol: "system"},
			{Library: "libc.so.6", Symbol: "exit"},
		},
	}
}

func TestLoadSet_Valid(t *testing.T) {
	doc := `{
	  "version": "2026.09.1",
	  "rules": [
	    {"id":"EVIL","scope":"section_bytes","match":"contains","pattern":"evil","severity":"high","description":"evil marker"},
	    {"id":"TEXT","scope":"section_name","match":"exact","pattern":".text","severity":"info","description":"text section"}
	  ]
	}`
	t.Logf("input rules json:\n%s", doc)
	set, err := LoadSet(context.Background(), []byte(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Version != "2026.09.1" || len(set.Rules) != 2 {
		t.Fatalf("bad set: %+v", set)
	}
	eng, err := NewEngine(set)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := eng.Evaluate(context.Background(), sampleBinary())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Logf("finding rule=%s section=%q offset=%#x len=%d matched=%q",
			f.RuleID, f.Location.Section, f.Location.Offset, f.Location.Length, f.Matched)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
	if findings[0].Location.Offset != 0x1004 {
		t.Fatalf("evil marker offset wrong: %#x", findings[0].Location.Offset)
	}
}

func TestLoadSet_InvalidCases(t *testing.T) {
	cases := map[string]string{
		"empty version":      `{"version":"","rules":[{"id":"A","scope":"format","match":"exact","pattern":"elf"}]}`,
		"no rules":           `{"version":"v1","rules":[]}`,
		"dup id":             `{"version":"v1","rules":[{"id":"A","scope":"format","match":"exact","pattern":"elf"},{"id":"A","scope":"arch","match":"exact","pattern":"x86"}]}`,
		"unknown scope":      `{"version":"v1","rules":[{"id":"A","scope":"bogus","match":"exact","pattern":"x"}]}`,
		"unknown match":      `{"version":"v1","rules":[{"id":"A","scope":"format","match":"bogus","pattern":"x"}]}`,
		"bad regexp":         `{"version":"v1","rules":[{"id":"A","scope":"section_name","match":"regexp","pattern":"("}]}`,
		"bad hex":            `{"version":"v1","rules":[{"id":"A","scope":"section_bytes","match":"hex","pattern":"zz"}]}`,
		"hex wrong scope":    `{"version":"v1","rules":[{"id":"A","scope":"format","match":"hex","pattern":"aa bb"}]}`,
		"unknown json field": `{"version":"v1","rules":[],"extra":1}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Logf("input: %s", doc)
			_, err := LoadSet(context.Background(), []byte(doc))
			if !errors.Is(err, ErrInvalidRuleSet) {
				t.Fatalf("%s: want ErrInvalidRuleSet, got %v", name, err)
			}
			t.Logf("verdict basis: %v", err)
		})
	}
}

func TestHexMatch_LocationAndEvidence(t *testing.T) {
	set, err := SetFromRules("v1", []Rule{{
		ID: "H", Scope: ScopeSectionBytes, Match: MatchHex,
		Pattern: "65 76 69 6c", Severity: "high", Description: "hex evil",
	}})
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := NewEngine(set)
	findings, err := eng.Evaluate(context.Background(), sampleBinary())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 hit, got %d", len(findings))
	}
	f := findings[0]
	t.Logf("hex hit: section=%s absOffset=%#x length=%d evidence=%s",
		f.Location.Section, f.Location.Offset, f.Location.Length, f.Matched)
	if f.Location.Section != ".text" || f.Location.Offset != 0x1004 || f.Location.Length != 4 {
		t.Fatalf("bad location: %+v", f.Location)
	}
	if strings.ToLower(f.Matched) != "6576696c" {
		t.Fatalf("bad matched evidence: %q", f.Matched)
	}
}

// TestRuleVersionIsolation proves verdicts do not silently change when rules
// are upgraded: each engine is bound to one version and a fresh engine with
// different rules yields different findings, while the old engine still
// produces the historical verdict.
func TestRuleVersionIsolation(t *testing.T) {
	b := sampleBinary()

	v1, err := SetFromRules("v1", []Rule{
		{ID: "OLD", Scope: ScopeSectionName, Match: MatchExact, Pattern: ".data", Severity: "low"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := SetFromRules("v2", []Rule{
		{ID: "NEW", Scope: ScopeSectionBytes, Match: MatchContains, Pattern: "evil", Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng1, _ := NewEngine(v1)
	eng2, _ := NewEngine(v2)

	f1, _ := eng1.Evaluate(context.Background(), b)
	f2, _ := eng2.Evaluate(context.Background(), b)
	f1Again, _ := eng1.Evaluate(context.Background(), b)

	t.Logf("v1 findings=%v (version=%s)", ids(f1), eng1.Version())
	t.Logf("v2 findings=%v (version=%s)", ids(f2), eng2.Version())

	if len(f1) != 1 || f1[0].RuleID != "OLD" {
		t.Fatalf("v1 historical verdict changed: %+v", f1)
	}
	if len(f2) != 1 || f2[0].RuleID != "NEW" {
		t.Fatalf("v2 verdict wrong: %+v", f2)
	}
	if len(f1Again) != 1 || f1Again[0].RuleID != "OLD" {
		t.Fatalf("old engine verdict must remain reproducible: %+v", f1Again)
	}
	if eng1.Version() == eng2.Version() {
		t.Fatal("engines report same version")
	}
}

func TestDeterministicOrdering(t *testing.T) {
	set, _ := SetFromRules("v1", []Rule{
		{ID: "B", Scope: ScopeSectionName, Match: MatchPrefix, Pattern: "."},
		{ID: "A", Scope: ScopeSectionName, Match: MatchPrefix, Pattern: "."},
	})
	eng, _ := NewEngine(set)
	var prev []Finding
	for i := 0; i < 5; i++ {
		got, _ := eng.Evaluate(context.Background(), sampleBinary())
		if prev != nil && !sameFindings(prev, got) {
			t.Fatalf("non-deterministic findings on run %d:\n%+v\n%+v", i, prev, got)
		}
		prev = got
	}
	t.Logf("stable findings: %v", ids(prev))
}

func ids(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}

func sameFindings(a, b []Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
