package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Loader errors.
var (
	ErrInvalidRuleSet = errors.New("rules: invalid rule set")
	ErrRuleNotFound   = errors.New("rules: rule id not found")
)

// ruleFile is the on-disk JSON representation.
type ruleFile struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// validScopes / validMatch enumerate accepted enum values.
var validScopes = map[Scope]bool{
	ScopeSectionName:  true,
	ScopeSectionBytes: true,
	ScopeFormat:       true,
	ScopeArch:         true,
	ScopeImport:       true,
}

var validMatch = map[MatchType]bool{
	MatchExact:    true,
	MatchContains: true,
	MatchPrefix:   true,
	MatchSuffix:   true,
	MatchRegex:    true,
	MatchHex:      true,
}

// LoadSet parses and validates a JSON rule set, returning an immutable Set.
//
// Validation is strict: unknown fields are rejected, version is required and
// non-empty, rule ids must be unique and non-empty, scope/match must be known
// enums, patterns must decode/compile, and regexp/hex scopes must be legal.
func LoadSet(ctx context.Context, raw []byte) (*Set, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rf ruleFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRuleSet, err)
	}
	if dec.Decode(&struct{}{}) == nil {
		return nil, fmt.Errorf("%w: multiple JSON values in document", ErrInvalidRuleSet)
	}
	return SetFromRules(rf.Version, rf.Rules)
}

// SetFromRules builds and validates a set directly (used in tests and by
// LoadSet). The returned slice is copied so callers cannot mutate it.
func SetFromRules(version string, rs []Rule) (*Set, error) {
	if version == "" {
		return nil, fmt.Errorf("%w: empty version", ErrInvalidRuleSet)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("%w: rule set %q contains no rules", ErrInvalidRuleSet, version)
	}
	seen := make(map[string]bool, len(rs))
	frozen := make([]Rule, len(rs))
	for i, r := range rs {
		if err := validateRule(r); err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("%w: duplicate rule id %q", ErrInvalidRuleSet, r.ID)
		}
		seen[r.ID] = true
		frozen[i] = r
	}
	// Sorting rule ids here would make iteration order version-independent of
	// file order; we deliberately preserve file order and sort findings in
	// Evaluate, so authored order stays visible.
	return &Set{Version: version, Rules: frozen}, nil
}

func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("%w: rule at %q has empty id", ErrInvalidRuleSet, r.Description)
	}
	if !validScopes[r.Scope] {
		return fmt.Errorf("%w: rule %q has unknown scope %q", ErrInvalidRuleSet, r.ID, r.Scope)
	}
	if !validMatch[r.Match] {
		return fmt.Errorf("%w: rule %q has unknown match type %q", ErrInvalidRuleSet, r.ID, r.Match)
	}
	if r.Pattern == "" && r.Match != MatchExact {
		return fmt.Errorf("%w: rule %q has empty pattern", ErrInvalidRuleSet, r.ID)
	}
	// Byte scanning scopes may use all match types; name-like scopes cannot
	// meaningfully use raw hex patterns.
	switch r.Scope {
	case ScopeSectionBytes:
		// hex and regexp both valid; check they decode below.
	default:
		if r.Match == MatchHex {
			return fmt.Errorf("%w: rule %q uses hex match outside section_bytes scope", ErrInvalidRuleSet, r.ID)
		}
	}
	if r.Match == MatchRegex {
		if _, err := compileRegex(r.Pattern); err != nil {
			return fmt.Errorf("%w: rule %q has invalid regexp: %v", ErrInvalidRuleSet, r.ID, err)
		}
	}
	if r.Match == MatchHex {
		if _, err := decodeHexPattern(r.Pattern); err != nil {
			return fmt.Errorf("%w: rule %q has invalid hex pattern: %v", ErrInvalidRuleSet, r.ID, err)
		}
	}
	return nil
}

// MustFreeze validates and returns an already-built set, panicking on error.
// Intended for package-level default sets only.
func MustFreeze(set *Set) *Set {
	s, err := SetFromRules(set.Version, set.Rules)
	if err != nil {
		panic(err)
	}
	return s
}

// Rule looks up a rule by id (used by tooling).
func (s *Set) Rule(id string) (Rule, error) {
	for _, r := range s.Rules {
		if r.ID == id {
			return r, nil
		}
	}
	return Rule{}, fmt.Errorf("%w: %s", ErrRuleNotFound, id)
}
