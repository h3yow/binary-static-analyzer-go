package rules

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/h3yow/binary-static-analyzer-go/internal/model"
)

// compiledRule is a validated Rule with its expensive representation ready.
type compiledRule struct {
	rule    Rule
	pattern []byte         // decoded hex pattern when Match == hex
	regex   *regexp.Regexp // compiled pattern when Match == regexp
}

// NewEngine compiles a validated rule set into an evaluation engine. The
// engine is safe for concurrent use and is permanently bound to the exact
// set version; upgrading rules requires a new engine.
func NewEngine(set *Set) (*Engine, error) {
	if set == nil {
		return nil, fmt.Errorf("rules: nil rule set")
	}
	crs := make([]compiledRule, 0, len(set.Rules))
	for _, r := range set.Rules {
		cr := compiledRule{rule: r}
		switch r.Match {
		case MatchRegex:
			re, err := compileRegex(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rules: rule %s: %w", r.ID, err)
			}
			cr.regex = re
		case MatchHex:
			raw, err := decodeHexPattern(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rules: rule %s: %w", r.ID, err)
			}
			cr.pattern = raw
		}
		crs = append(crs, cr)
	}
	return &Engine{set: set, compiled: crs}, nil
}

// Version returns the rule set version bound to this engine.
func (e *Engine) Version() string {
	return e.set.Version
}

// Evaluate runs every rule against b and returns findings sorted by
// (rule id, section name, offset, matched) so the output is deterministic and
// identical for sequential and concurrent scans.
func (e *Engine) Evaluate(ctx context.Context, b *model.Binary) ([]Finding, error) {
	if b == nil {
		return nil, fmt.Errorf("rules: nil binary")
	}
	var out []Finding
	for _, cr := range e.compiled {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out = append(out, e.evalOne(ctx, cr, b)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, c := out[i].Location, out[j].Location
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if a.Section != c.Section {
			return a.Section < c.Section
		}
		if a.Offset != c.Offset {
			return a.Offset < c.Offset
		}
		return out[i].Matched < out[j].Matched
	})
	return out, nil
}

func (e *Engine) evalOne(ctx context.Context, cr compiledRule, b *model.Binary) []Finding {
	r := cr.rule
	switch r.Scope {
	case ScopeFormat:
		if matchString(cr, string(b.Format)) {
			return []Finding{newFinding(cr, Location{Offset: -1, Detail: "format=" + string(b.Format)}, string(b.Format))}
		}
	case ScopeArch:
		if matchString(cr, string(b.Arch)) {
			return []Finding{newFinding(cr, Location{Offset: -1, Detail: "arch=" + string(b.Arch)}, string(b.Arch))}
		}
	case ScopeImport:
		var hits []Finding
		for _, imp := range b.Imports {
			label := imp.Library + "!" + imp.Symbol
			if matchString(cr, label) || matchString(cr, imp.Symbol) {
				hits = append(hits, newFinding(cr, Location{Offset: -1, Detail: "import=" + label}, label))
			}
		}
		return hits
	case ScopeSectionName:
		var hits []Finding
		for _, s := range b.Sections {
			if matchString(cr, s.Name) {
				hits = append(hits, newFinding(cr, Location{
					Section: s.Name, Offset: int64(s.Offset), Detail: "section name",
				}, s.Name))
			}
		}
		return hits
	case ScopeSectionBytes:
		return matchSectionBytes(cr, b)
	}
	return nil
}

// matchSectionBytes locates every hit inside section data and records the
// absolute file offset plus the exact matched bytes as evidence. Sections
// without retained Raw (over the capture limit) are skipped, not silently
// matched; this is recorded nowhere as a hit because none exists.
func matchSectionBytes(cr compiledRule, b *model.Binary) []Finding {
	var hits []Finding
	for _, s := range b.Sections {
		if s.Raw == nil {
			continue
		}
		base := int64(s.Offset)
		switch cr.rule.Match {
		case MatchHex, MatchContains:
			needle := cr.pattern
			if cr.rule.Match == MatchContains {
				needle = []byte(cr.rule.Pattern)
			}
			if len(needle) == 0 {
				continue
			}
			start := 0
			for {
				idx := bytes.Index(s.Raw[start:], needle)
				if idx < 0 {
					break
				}
				abs := start + idx
				hits = append(hits, newFinding(cr, Location{
					Section: s.Name,
					Offset:  base + int64(abs),
					Length:  len(needle),
					Detail:  "byte pattern in section data",
				}, hex.EncodeToString(needle)))
				// Advance by the full match: non-overlapping hits, so a long
				// run (e.g. NOP sleds) yields one finding per distinct hit.
				start = abs + len(needle)
				if start > len(s.Raw) {
					break
				}
			}
		case MatchRegex:
			for _, loc := range cr.regex.FindAllIndex(s.Raw, -1) {
				hits = append(hits, newFinding(cr, Location{
					Section: s.Name,
					Offset:  base + int64(loc[0]),
					Length:  loc[1] - loc[0],
					Detail:  "regexp in section data",
				}, string(s.Raw[loc[0]:loc[1]])))
			}
		default:
			// exact/prefix/suffix on bytes interpreted as the whole blob.
			var matched string
			var off, length int
			ok := false
			switch cr.rule.Match {
			case MatchExact:
				if bytes.Equal(s.Raw, []byte(cr.rule.Pattern)) {
					ok, matched, off, length = true, cr.rule.Pattern, 0, len(s.Raw)
				}
			case MatchPrefix:
				if bytes.HasPrefix(s.Raw, []byte(cr.rule.Pattern)) {
					ok, matched, off, length = true, cr.rule.Pattern, 0, len(cr.rule.Pattern)
				}
			case MatchSuffix:
				p := []byte(cr.rule.Pattern)
				if bytes.HasSuffix(s.Raw, p) {
					ok, matched, off, length = true, cr.rule.Pattern, len(s.Raw)-len(p), len(p)
				}
			}
			if ok {
				hits = append(hits, newFinding(cr, Location{
					Section: s.Name, Offset: base + int64(off), Length: length,
					Detail: "byte relation in section data",
				}, matched))
			}
		}
	}
	return hits
}

func newFinding(cr compiledRule, loc Location, matched string) Finding {
	return Finding{
		RuleID:      cr.rule.ID,
		Severity:    cr.rule.Severity,
		Description: cr.rule.Description,
		Scope:       cr.rule.Scope,
		Location:    loc,
		Matched:     matched,
	}
}

// matchString applies non-byte match types to a string-valued target.
func matchString(cr compiledRule, target string) bool {
	p := cr.rule.Pattern
	switch cr.rule.Match {
	case MatchExact:
		return target == p
	case MatchContains:
		return strings.Contains(target, p)
	case MatchPrefix:
		return strings.HasPrefix(target, p)
	case MatchSuffix:
		return strings.HasSuffix(target, p)
	case MatchRegex:
		return cr.regex.MatchString(target)
	default:
		return false
	}
}

func compileRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

// decodeHexPattern accepts an even-length hex string, tolerating embedded
// whitespace, and returns the raw bytes.
func decodeHexPattern(pattern string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, pattern)
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty hex pattern")
	}
	return raw, nil
}
