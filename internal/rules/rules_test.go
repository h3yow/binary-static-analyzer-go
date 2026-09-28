package rules

import (
	"context"
	"errors"
	"testing"

	"github.com/h3yow/binary-static-analyzer-go/internal/binary"
)

const v1Rules = `{
  "id": "baseline",
  "version": "2026.01",
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [
    {"id":"R001","version":"1","name":"PE container","severity":"info",
     "target":"format","op":"equals","value":"pe"},
    {"id":"R002","version":"2","name":"secret marker","severity":"high",
     "target":"section_content","section":".data","op":"contains","value":"SECRET"},
    {"id":"R003","version":"1","name":"writable code","severity":"critical",
     "target":"section_perm","section":"*","op":"contains_all","value":"wx"}
  ]
}`

const v2Rules = `{
  "id": "baseline",
  "version": "2026.09",
  "rules": [
    {"id":"R001","version":"1","name":"PE container","severity":"info",
     "target":"format","op":"equals","value":"pe"},
    {"id":"R002","version":"3","name":"secret marker changed","severity":"medium",
     "target":"section_content","section":".data","op":"regex","value":"SECR.T"},
    {"id":"R004","version":"1","name":"new rule","severity":"low",
     "target":"file_content","op":"contains","value":"NOMATCH_HERE"}
  ]
}`

func TestRuleVersionReproducibility(t *testing.T) {
	// Build the same minimal ELF used by the binary-package tests: its .data
	// section contains "SECRET".
	b, err := binary.Parse(buildELF(t))
	if err != nil {
		t.Fatalf("parse input: %v", err)
	}
	raw := buildELF(t)
	t.Logf("input: %d bytes, sections=%d", len(raw), len(b.Sections))

	s1, err := LoadSet([]byte(v1Rules))
	if err != nil {
		t.Fatalf("load v1: %v", err)
	}
	s2, err := LoadSet([]byte(v2Rules))
	if err != nil {
		t.Fatalf("load v2: %v", err)
	}
	if s1.Hash() == s2.Hash() {
		t.Fatalf("different rule versions must hash differently: %s", s1.Hash())
	}
	h1Again, _ := LoadSet([]byte(v1Rules))
	if h1Again.Hash() != s1.Hash() {
		t.Fatalf("same rule set content must hash identically")
	}

	e1, _ := NewEngine(s1)
	f1, err := e1.Evaluate(context.Background(), b, raw)
	if err != nil {
		t.Fatalf("eval v1: %v", err)
	}
	e2, _ := NewEngine(s2)
	f2, err := e2.Evaluate(context.Background(), b, raw)
	if err != nil {
		t.Fatalf("eval v2: %v", err)
	}

	if len(f1) != 1 || f1[0].RuleID != "R002" {
		t.Fatalf("v1 findings = %+v, want only R002", f1)
	}
	t.Logf("v1 basis: %s -> matched %q at offset %d section %q",
		f1[0].Basis, f1[0].Matched, f1[0].Location.Offset, f1[0].Location.Section)

	// .data offset must be exactly where buildELF places "SECRET".
	if want := int64(binaryDataOffset(t, raw)); f1[0].Location.Offset != want {
		t.Fatalf("location = %d, want %d", f1[0].Location.Offset, want)
	}

	if len(f2) != 1 || f2[0].RuleID != "R002" || f2[0].Severity != SeverityMedium {
		t.Fatalf("v2 findings = %+v, want upgraded R002 at medium", f2)
	}
	t.Logf("v2 basis: %s -> matched %q (rule version %s)",
		f2[0].Basis, f2[0].Matched, f2[0].RuleVersion)

	// Re-running v1 must yield byte-for-byte the same historical verdict even
	// though v2 exists.
	f1Repeat, _ := e1.Evaluate(context.Background(), b, raw)
	if len(f1Repeat) != 1 || f1Repeat[0].Basis != f1[0].Basis ||
		f1Repeat[0].Location != f1[0].Location || f1Repeat[0].Severity != f1[0].Severity {
		t.Fatalf("historical v1 verdict drifted: %+v vs %+v", f1Repeat[0], f1[0])
	}
}

func TestLoadSetRejectsInvalidRules(t *testing.T) {
	cases := map[string]string{
		"bad json":             `{not json`,
		"unknown field":        `{"id":"x","version":"1","rules":[],"nope":1}`,
		"missing set id":       `{"version":"1","rules":[]}`,
		"missing rule id":      `{"id":"s","version":"1","rules":[{"version":"1","target":"format","op":"equals","value":"elf","severity":"info"}]}`,
		"duplicate rule id":    `{"id":"s","version":"1","rules":[{"id":"a","version":"1","target":"format","op":"equals","value":"elf","severity":"info"},{"id":"a","version":"1","target":"format","op":"equals","value":"pe","severity":"info"}]}`,
		"bad target":           `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"disk","op":"equals","value":"x"}]}`,
		"bad op":               `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"format","op":"glob","value":"elf"}]}`,
		"bad regex":            `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"file_content","op":"regex","value":"("}]}`,
		"bad severity":         `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"urgent","target":"format","op":"equals","value":"elf"}]}`,
		"bad entrypoint hex":   `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"entrypoint","op":"hex_equals","value":"4096"}]}`,
		"empty contains value": `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"file_content","op":"contains","value":""}]}`,
		"bad perm expression":  `{"id":"s","version":"1","rules":[{"id":"a","version":"1","severity":"info","target":"section_perm","op":"contains_all","value":"zz"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Logf("input rule set %s: %s", name, body)
			_, err := LoadSet([]byte(body))
			var re *RuleError
			if name == "bad json" || name == "unknown field" {
				if err == nil {
					t.Fatalf("want JSON error")
				}
			} else if !errors.As(err, &re) {
				t.Fatalf("want *RuleError, got %v", err)
			}
			if err != nil {
				t.Logf("decision basis: %v", err)
			}
		})
	}
}

func TestSectionPermAndEntrypointRules(t *testing.T) {
	raw := buildELF(t)
	b, err := binary.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"s","version":"1","rules":[
	  {"id":"P1","version":"1","name":"exec section","severity":"low",
	   "target":"section_perm","section":".text","op":"contains_all","value":"x"},
	  {"id":"E1","version":"1","name":"entry known","severity":"info",
	   "target":"entrypoint","op":"hex_equals","value":"0x400010"}
	]}`
	s, err := LoadSet([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := NewEngine(s)
	f, err := eng.Evaluate(context.Background(), b, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 {
		t.Fatalf("findings = %+v", f)
	}
	for _, x := range f {
		t.Logf("finding rule=%s basis=%q matched=%q", x.RuleID, x.Basis, x.Matched)
	}
}
