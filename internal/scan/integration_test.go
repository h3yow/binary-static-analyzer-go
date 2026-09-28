package scan

import (
	"context"
	"testing"

	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

// TestIntegration_VersionSwitchReproducible is the end-to-end form of the
// reproducibility requirement: scan under v1, upgrade the rule file to v2,
// scan the same bytes again. Both verdicts must be obtainable and must match
// what each version produced originally — the cache must not bleed versions.
func TestIntegration_VersionSwitchReproducible(t *testing.T) {
	load := func(version string, extra bool) *rules.Engine {
		rs := []rules.Rule{
			{ID: "ELF", Scope: rules.ScopeFormat, Match: rules.MatchExact, Pattern: "elf", Severity: "info"},
		}
		if extra {
			rs = append(rs, rules.Rule{ID: "AMD64", Scope: rules.ScopeArch, Match: rules.MatchExact, Pattern: "x86_64", Severity: "high"})
		}
		return engineFor(t, version, rs...)
	}

	s := New(load("ruleset-v1", false), DefaultConfig())
	target := []Target{{Name: "sample", Content: minimalELF}}

	first, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	// Run v1 twice more to prove the cached historical verdict is stable.
	second, _ := s.Scan(context.Background(), target)
	if len(first.Results[0].Findings) != 1 || len(second.Results[0].Findings) != 1 {
		t.Fatalf("v1 verdict unstable: %d vs %d",
			len(first.Results[0].Findings), len(second.Results[0].Findings))
	}
	t.Logf("v1 reproducible: %d findings, rule_version=%s",
		len(second.Results[0].Findings), second.Results[0].RuleVersion)

	// "Upgrade the deployed rule file": bind a new engine/version.
	s.engine = load("ruleset-v2", true)
	upgraded, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Results[0].RuleVersion != "ruleset-v2" {
		t.Fatalf("version not updated: %s", upgraded.Results[0].RuleVersion)
	}
	if len(upgraded.Results[0].Findings) != 2 {
		t.Fatalf("v2 must be freshly evaluated, got %d findings", len(upgraded.Results[0].Findings))
	}
	t.Logf("v2 recomputed: %d findings, rule_version=%s",
		len(upgraded.Results[0].Findings), upgraded.Results[0].RuleVersion)

	// Downgrade back: old verdict still reproducible, not influenced by v2.
	s.engine = load("ruleset-v1", false)
	again, _ := s.Scan(context.Background(), target)
	if len(again.Results[0].Findings) != 1 || again.Results[0].Findings[0].RuleID != "ELF" {
		t.Fatalf("historical v1 verdict changed after upgrade/downgrade: %+v",
			again.Results[0].Findings)
	}
	t.Logf("v1 after downgrade still: %d findings (%s)",
		len(again.Results[0].Findings), again.Results[0].RuleVersion)
}
