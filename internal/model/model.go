// Package model defines the unified structural model for parsed executables.
package model

// Format identifies an executable container format.
type Format string

// Supported container formats.
const (
	FormatELF   Format = "elf"
	FormatPE    Format = "pe"
	FormatMachO Format = "macho"
)

// Architecture describes a machine architecture in a format-neutral way.
type Architecture string

const (
	ArchUnknown Architecture = "unknown"
	ArchX86     Architecture = "x86"
	ArchX86_64  Architecture = "x86_64"
	ArchARM     Architecture = "arm"
	ArchARM64   Architecture = "arm64"
)

// Section is a region of an executable (section or equivalent).
type Section struct {
	Name      string
	Offset    uint64 // absolute offset within the file
	Size      uint64
	Address   uint64 // virtual address, 0 if unavailable
	Entropy   float64
	Raw       []byte // may be nil for oversized sections
	Flags     uint32
	Truncated bool // declared size exceeds file bounds
}

// Import describes a single imported symbol.
type Import struct {
	Library string
	Symbol  string
}

// Binary is the unified, format-neutral view of a parsed executable.
type Binary struct {
	Format       Format
	FormatDetail string // format-specific detail, e.g. "elf64-little"
	Arch         Architecture
	Bits         int
	LittleEndian bool
	EntryPoint   uint64
	Size         int64
	Sections     []Section
	Imports      []Import
	SourceSHA256 string // hex sha256 of the exact input bytes
}
