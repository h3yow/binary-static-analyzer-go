package rules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

func validateRule(r *Rule) error {
	bad := func(msg string) error {
		return &RuleError{Index: -1, RuleID: r.ID, Message: msg}
	}
	switch r.Target {
	case TargetEntrypoint:
		if r.Op != OpHexEquals {
			return bad(fmt.Sprintf("target %q requires op %q, got %q", r.Target, OpHexEquals, r.Op))
		}
		if parseHex(r.Value) == nil {
			return bad(fmt.Sprintf("value %q is not a 0x-prefixed hexadecimal address", r.Value))
		}
	case TargetSectionName:
		switch r.Op {
		case OpEquals, OpGlob:
		default:
			return bad(fmt.Sprintf("target %q requires op %q or %q", r.Target, OpEquals, OpGlob))
		}
		if r.Value == "" {
			return bad("value must not be empty")
		}
		if r.Op == OpGlob {
			if _, err := filepath.Match(r.Value, "probe"); err != nil {
				return bad(fmt.Sprintf("invalid glob %q: %v", r.Value, err))
			}
		}
	case TargetSectionPerm:
		if r.Op != OpContainsAll {
			return bad(fmt.Sprintf("target %q requires op %q", r.Target, OpContainsAll))
		}
		if !isPermExpr(r.Value) {
			return bad(fmt.Sprintf("value %q must be a non-empty combination of r, w, x", r.Value))
		}
	case TargetSectionContent, TargetFileContent:
		switch r.Op {
		case OpContains, OpRegex:
		default:
			return bad(fmt.Sprintf("target %q requires op %q or %q", r.Target, OpContains, OpRegex))
		}
		if r.Value == "" {
			return bad("value must not be empty")
		}
		if r.Op == OpRegex {
			if _, err := regexp.Compile(r.Value); err != nil {
				return bad(fmt.Sprintf("invalid regexp %q: %v", r.Value, err))
			}
		}
	case TargetFormat:
		if r.Op != OpEquals {
			return bad(fmt.Sprintf("target %q requires op %q", r.Target, OpEquals))
		}
		switch r.Value {
		case "elf", "pe", "macho":
		default:
			return bad(fmt.Sprintf("value %q must be one of elf, pe, macho", r.Value))
		}
	default:
		return bad(fmt.Sprintf("unknown target %q", r.Target))
	}
	return nil
}

func parseHex(v string) *uint64 {
	if !strings.HasPrefix(v, "0x") && !strings.HasPrefix(v, "0X") {
		return nil
	}
	var x uint64
	for i := 2; i < len(v); i++ {
		c := v[i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return nil
		}
		if x > (^uint64(0))/16 {
			return nil
		}
		x = x*16 + uint64(d)
	}
	if len(v) == 2 {
		return nil
	}
	return &x
}

func isPermExpr(v string) bool {
	seen := map[rune]bool{}
	for _, c := range v {
		if c != 'r' && c != 'w' && c != 'x' {
			return false
		}
		if seen[c] {
			return false
		}
		seen[c] = true
	}
	return len(v) > 0
}

// parsePerm turns an "rwx"-style string into a permission mask.
func parsePerm(v string) (mask uint8) {
	for _, c := range v {
		switch c {
		case 'r':
			mask |= 4
		case 'w':
			mask |= 2
		case 'x':
			mask |= 1
		}
	}
	return mask
}
