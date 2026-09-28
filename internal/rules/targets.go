package rules

// Rule targets.
const (
	// TargetEntrypoint matches against the parsed entry-point address.
	TargetEntrypoint = "entrypoint"
	// TargetSectionName matches section names.
	TargetSectionName = "section_name"
	// TargetSectionPerm matches section permission masks.
	TargetSectionPerm = "section_perm"
	// TargetSectionContent matches bytes inside sections.
	TargetSectionContent = "section_content"
	// TargetFileContent matches bytes anywhere in the input blob.
	TargetFileContent = "file_content"
	// TargetFormat matches the container format / arch metadata.
	TargetFormat = "format"
)

// Rule operators.
const (
	OpEquals       = "equals"
	OpNotEquals    = "not_equals"
	OpContains     = "contains"
	OpContainsAll  = "contains_all"
	OpContainsNone = "contains_none"
	OpRegex        = "regex"
	OpGlob         = "glob"
	OpHexEquals    = "hex_equals"
)
