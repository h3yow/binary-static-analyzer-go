package rules

import "encoding/json"

func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RuleID      string   `json:"rule_id"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Scope       Scope    `json:"scope"`
		Location    Location `json:"location"`
		Matched     string   `json:"matched"`
	}{
		RuleID:      f.RuleID,
		Severity:    f.Severity,
		Description: f.Description,
		Scope:       f.Scope,
		Location:    f.Location,
		Matched:     f.Matched,
	})
}

func (l Location) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Section string `json:"section,omitempty"`
		Offset  int64  `json:"offset"`
		Length  int    `json:"length,omitempty"`
		Detail  string `json:"detail,omitempty"`
	}{
		Section: l.Section,
		Offset:  l.Offset,
		Length:  l.Length,
		Detail:  l.Detail,
	})
}
