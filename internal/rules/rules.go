// Package rules defines the configurable detection-rule model and the
// matching engine.
package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Severity levels.
type Severity string

// Severity values accepted in rule-set JSON.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rule is one configurable detection rule.
type Rule struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	// Target selects what the rule inspects. See Target* constants.
	Target string `json:"target"`
	// Section restricts section-* targets to a section-name glob
	// (filepath.Match syntax); empty means every section.
	Section string `json:"section,omitempty"`
	Op      string `json:"op"`
	Value   string `json:"value"`
}

// Set is an immutable, versioned collection of rules.
type Set struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	CreatedAt string `json:"created_at,omitempty"`
	Rules     []Rule `json:"rules"`

	hash string
}

// Location pinpoints a rule hit inside the input.
type Location struct {
	Section string `json:"section,omitempty"`
	Offset  int64  `json:"offset"`
	Length  int64  `json:"length"`
}

// Finding is one rule hit with its location and decision basis.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleVersion string   `json:"rule_version"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Target      string   `json:"target"`
	Location    Location `json:"location"`
	Matched     string   `json:"matched"`
	Basis       string   `json:"basis"`
}

// RuleError describes an invalid rule inside a rule set.
type RuleError struct {
	RuleID  string
	Index   int
	Message string
}

func (e *RuleError) Error() string {
	id := e.RuleID
	if id == "" {
		id = fmt.Sprintf("#%d", e.Index)
	}
	return "invalid rule " + id + ": " + e.Message
}

// LoadSet parses and validates a JSON rule set. CreatedAt never influences
// evaluation or the content hash (see Hash).
func LoadSet(data []byte) (*Set, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Set
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("rule set JSON is invalid: %w", err)
	}
	if err := validateSet(&s); err != nil {
		return nil, err
	}
	s.hash = computeHash(&s)
	return &s, nil
}

func validateSet(s *Set) error {
	if s.ID == "" {
		return &RuleError{Index: -1, Message: "rule set id must not be empty"}
	}
	if s.Version == "" {
		return &RuleError{Index: -1, RuleID: s.ID, Message: "rule set version must not be empty"}
	}
	seen := make(map[string]int, len(s.Rules))
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.ID == "" {
			return &RuleError{Index: i, Message: "rule id must not be empty"}
		}
		if prev, dup := seen[r.ID]; dup {
			return &RuleError{Index: i, RuleID: r.ID,
				Message: fmt.Sprintf("duplicate rule id (first seen at index %d)", prev)}
		}
		seen[r.ID] = i
		if r.Version == "" {
			return &RuleError{Index: i, RuleID: r.ID, Message: "rule version must not be empty"}
		}
		if !validSeverity(r.Severity) {
			return &RuleError{Index: i, RuleID: r.ID,
				Message: fmt.Sprintf("unknown severity %q", r.Severity)}
		}
		if err := validateRule(r); err != nil {
			return err
		}
	}
	return nil
}

func validSeverity(s Severity) bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Hash returns a stable content hash identifying the exact semantic content
// of this rule set (id, version, and every rule field in order). The
// informational created_at field is excluded so relabeling a set never
// changes verdicts.
func (s *Set) Hash() string { return s.hash }

func computeHash(s *Set) string {
	type canonicalSet struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Rules   []Rule `json:"rules"`
	}
	b, err := json.Marshal(canonicalSet{ID: s.ID, Version: s.Version, Rules: s.Rules})
	if err != nil {
		// Our own types cannot fail to marshal.
		panic("rules: failed to marshal canonical set: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
