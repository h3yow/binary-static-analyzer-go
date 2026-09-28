// Package rules implements versioned, configurable detection rules.
package rules

// Scope selects what part of a parsed binary a rule examines.
type Scope string

const (
	// ScopeSectionName matches against section names.
	ScopeSectionName Scope = "section_name"
	// ScopeSectionBytes searches for a byte pattern inside section data.
	ScopeSectionBytes Scope = "section_bytes"
	// ScopeFormat matches against the format identifier (elf/pe/macho).
	ScopeFormat Scope = "format"
	// ScopeArch matches against the architecture identifier.
	ScopeArch Scope = "arch"
	// ScopeImport matches against "library!symbol" imported entries.
	ScopeImport Scope = "import"
)

// MatchType selects the comparison semantics.
type MatchType string

const (
	MatchExact    MatchType = "exact"
	MatchContains MatchType = "contains"
	MatchPrefix   MatchType = "prefix"
	MatchSuffix   MatchType = "suffix"
	MatchRegex    MatchType = "regexp"
	MatchHex      MatchType = "hex" // pattern decoded as hex bytes, byte-contains
)

// Rule is a single configurable detection rule.
type Rule struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Scope       Scope     `json:"scope"`
	Match       MatchType `json:"match"`
	Pattern     string    `json:"pattern"`
	Severity    string    `json:"severity"`
}

// Set is an immutable, versioned collection of rules.
type Set struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Finding records one rule hit with enough evidence to reproduce the verdict.
type Finding struct {
	RuleID      string
	Severity    string
	Description string
	Scope       Scope
	// Location identifies where the hit occurred.
	Location Location
	// Matched is the exact value/pattern that matched.
	Matched string
}

// Location points at a specific place in the parsed binary.
type Location struct {
	Section string
	Offset  int64 // absolute file offset, -1 when not byte-locatable
	Length  int
	Detail  string // extra human-readable basis, e.g. matched import
}

// Engine evaluates a rule set against a parsed binary. It is safe for
// concurrent use.
type Engine struct {
	set      *Set
	compiled []compiledRule
}
