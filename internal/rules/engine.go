package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/h3yow/binary-static-analyzer-go/internal/binary"
)

// Evaluator evaluates a parsed binary against rules.
type Evaluator interface {
	Evaluate(ctx context.Context, b *binary.Binary, raw []byte) ([]Finding, error)
}

// compiledRule holds the precomputed artifacts for one rule.
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
	hex  *uint64
	perm uint8
}

// Engine evaluates binaries against an immutable validated rule set.
type Engine struct {
	set      *Set
	compiled []compiledRule
}

// NewEngine validates every rule and compiles regexps.
func NewEngine(set *Set) (*Engine, error) {
	if set == nil {
		return nil, fmt.Errorf("rules: rule set must not be nil")
	}
	compiled := make([]compiledRule, len(set.Rules))
	for i := range set.Rules {
		r := set.Rules[i]
		c := compiledRule{rule: r}
		switch r.Target {
		case TargetEntrypoint:
			c.hex = parseHex(r.Value)
		case TargetSectionContent, TargetFileContent:
			if r.Op == OpRegex {
				re, err := regexp.Compile(r.Value)
				if err != nil {
					return nil, &RuleError{Index: i, RuleID: r.ID, Message: err.Error()}
				}
				c.re = re
			}

		case TargetSectionPerm:
			c.perm = parsePerm(r.Value)
		}
		compiled[i] = c
	}
	return &Engine{set: set, compiled: compiled}, nil
}

// Set returns the immutable rule set backing the engine.
func (e *Engine) Set() *Set { return e.set }

// Evaluate runs all rules in rule-set order and returns every hit, ordered by
// rule index and then section index, so identical inputs always produce an
// identical result.
func (e *Engine) Evaluate(ctx context.Context, b *binary.Binary, raw []byte) ([]Finding, error) {
	var findings []Finding
	for i := range e.compiled {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := &e.compiled[i]
		findings = append(findings, e.evalOne(c, b, raw)...)
	}
	return findings, nil
}

func (e *Engine) evalOne(c *compiledRule, b *binary.Binary, raw []byte) []Finding {
	r := c.rule
	var out []Finding
	switch r.Target {
	case TargetEntrypoint:
		if c.hex != nil && b.EntryPoint == *c.hex {
			out = append(out, Finding{
				RuleID: r.ID, RuleVersion: r.Version, Name: r.Name,
				Severity: r.Severity, Target: r.Target,
				Location: Location{Offset: int64(b.EntryPoint), Length: 0},
				Matched:  "0x" + strconv.FormatUint(b.EntryPoint, 16),
				Basis:    fmt.Sprintf("entry point 0x%x %s 0x%x", b.EntryPoint, OpHexEquals, *c.hex),
			})
		}
	case TargetFormat:
		if string(b.Format) == r.Value {
			out = append(out, Finding{
				RuleID: r.ID, RuleVersion: r.Version, Name: r.Name,
				Severity: r.Severity, Target: r.Target,
				Location: Location{Offset: 0},
				Matched:  string(b.Format),
				Basis:    fmt.Sprintf("container format %q equals %q", b.Format, r.Value),
			})
		}
	case TargetSectionName:
		for si := range b.Sections {
			s := &b.Sections[si]
			hit := false
			switch r.Op {
			case OpEquals:
				hit = s.Name == r.Value
			case OpGlob:
				if m, _ := filepath.Match(r.Value, s.Name); m {
					hit = true
				}
			}
			if hit {
				out = append(out, Finding{
					RuleID: r.ID, RuleVersion: r.Version, Name: r.Name,
					Severity: r.Severity, Target: r.Target,
					Location: Location{Section: s.Name, Offset: int64(s.Offset)},
					Matched:  s.Name,
					Basis:    fmt.Sprintf("section name %q matches %s %q", s.Name, r.Op, r.Value),
				})
			}
		}
	case TargetSectionPerm:
		for si := range b.Sections {
			s := &b.Sections[si]
			if !sectionGlobMatch(r.Section, s.Name) {
				continue
			}
			have := uint8(s.Perm)
			if have&c.perm == c.perm && c.perm != 0 {
				out = append(out, Finding{
					RuleID: r.ID, RuleVersion: r.Version, Name: r.Name,
					Severity: r.Severity, Target: r.Target,
					Location: Location{Section: s.Name, Offset: int64(s.Offset)},
					Matched:  s.Perm.String(),
					Basis: fmt.Sprintf("section %q perms %s (0x%x) contain all of %q (0x%x)",
						s.Name, s.Perm, have, r.Value, c.perm),
				})
			}
		}
	case TargetSectionContent:
		for si := range b.Sections {
			s := &b.Sections[si]
			if !sectionGlobMatch(r.Section, s.Name) {
				continue
			}
			start := int64(s.Offset)
			end := start + int64(s.Size)
			if start < 0 || end < start || end > int64(len(raw)) {
				continue
			}
			if f, ok := matchBytes(c, s.Name, raw[start:end], start); ok {
				out = append(out, f)
			}
		}
	case TargetFileContent:
		if f, ok := matchBytes(c, "", raw, 0); ok {
			out = append(out, f)
		}
	}
	return out
}

// matchBytes returns the first hit for a contains/regex rule. fileBase is the
// blob offset at which buf starts, so reported offsets are file-relative.
func matchBytes(c *compiledRule, section string, buf []byte, fileBase int64) (Finding, bool) {
	r := c.rule
	var idx int
	var matched []byte
	switch r.Op {
	case OpContains:
		idx = indexOf(buf, []byte(r.Value))
		if idx < 0 {
			return Finding{}, false
		}
		matched = []byte(r.Value)
	case OpRegex:
		loc := c.re.FindIndex(buf)
		if loc == nil {
			return Finding{}, false
		}
		idx = loc[0]
		matched = buf[loc[0]:loc[1]]
	default:
		return Finding{}, false
	}
	basis := fmt.Sprintf("bytes %s %q at file offset %d",
		r.Op, truncateForLog(r.Value), fileBase+int64(idx))
	if section != "" {
		basis = fmt.Sprintf("section %q: %s", section, basis)
	}
	return Finding{
		RuleID: r.ID, RuleVersion: r.Version, Name: r.Name,
		Severity: r.Severity, Target: r.Target,
		Location: Location{Section: section, Offset: fileBase + int64(idx), Length: int64(len(matched))},
		Matched:  truncateForLog(string(matched)),
		Basis:    basis,
	}, true
}

func sectionGlobMatch(pattern, name string) bool {
	if pattern == "" {
		return true
	}
	m, err := filepath.Match(pattern, name)
	return err == nil && m
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	last := len(haystack) - len(needle)
	for i := 0; i <= last; i++ {
		if haystack[i] == needle[0] {
			j := 1
			for ; j < len(needle); j++ {
				if haystack[i+j] != needle[j] {
					break
				}
			}
			if j == len(needle) {
				return i
			}
		}
	}
	return -1
}

func truncateForLog(s string) string {
	const limit = 128
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	if len(s) > limit {
		return s[:limit] + "...(truncated)"
	}
	return s
}
