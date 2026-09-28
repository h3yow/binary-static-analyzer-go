package scan

import (
	"encoding/json"
	"errors"

	"github.com/h3yow/binary-static-analyzer-go/internal/parser"
)

// errorInfo is the JSON form of a classified scan/parse error.
type errorInfo struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// classify maps sentinel errors to stable machine-readable kinds.
func classify(err error) string {
	switch {
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrTooLarge):
		return "too_large"
	case errors.Is(err, ErrQueueRejected):
		return "queue_rejected"
	case errors.Is(err, parser.ErrEmpty):
		return "empty_input"
	case errors.Is(err, parser.ErrTruncated):
		return "truncated"
	case errors.Is(err, parser.ErrCorrupt):
		return "corrupt"
	case errors.Is(err, parser.ErrUnsupported):
		return "unsupported"
	case errors.Is(err, parser.ErrOversized):
		return "oversized"
	case errors.Is(err, parser.ErrUnknownFormat):
		return "unknown_format"
	default:
		return "error"
	}
}

// MarshalJSON renders Result with the error classified into Kind/Message so
// downstream consumers can distinguish failure causes without parsing prose.
func (r Result) MarshalJSON() ([]byte, error) {
	type alias struct {
		Target      string     `json:"target"`
		Status      Status     `json:"status"`
		Hash        string     `json:"hash,omitempty"`
		Format      string     `json:"format,omitempty"`
		Findings    []Finding  `json:"findings"`
		RuleVersion string     `json:"rule_version"`
		Error       *errorInfo `json:"error,omitempty"`
	}
	out := alias{
		Target:      r.Target,
		Status:      r.Status,
		Hash:        r.Hash,
		Format:      string(r.Format),
		Findings:    r.Findings,
		RuleVersion: r.RuleVersion,
	}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	if r.Err != nil {
		out.Error = &errorInfo{Kind: classify(r.Err), Message: r.Err.Error()}
	}
	return json.Marshal(out)
}

// MarshalJSON renders the report with snake_case field names.
func (rep Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RuleVersion string   `json:"rule_version"`
		Results     []Result `json:"results"`
	}{RuleVersion: rep.RuleVersion, Results: rep.Results})
}
